//! On-disk spool of gzipped uploads (docs/operations.md, "The data directory").

use std::collections::VecDeque;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::log::{check_error, shutdown};
use crate::reported_ips::open_0640;
use crate::stats::{self, UploadStats};

/// Number of concurrent PCE senders, as in FlowLink.
pub const MAX_SENDERS: usize = 5;

/// A queued spool file. `time` is the creation time used for retention.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpoolFile {
    pub name: String,
    pub size: i64,
    pub time: SystemTime,
    /// Flow records in the file, for the upload stats; 0 for files found by the start-up scan.
    pub records: u64,
}

#[derive(Debug, Default)]
struct State {
    total: i64,
    /// Files counted in `total`: queued or being sent.
    files: usize,
    queue: VecDeque<SpoolFile>,
}

pub struct Spool {
    dir: PathBuf,
    retention_mins: f64,
    max_bytes: i64,
    state: Mutex<State>,
    work: Condvar,
    /// Files currently being sent.
    pub sending: AtomicI32,
    stats: &'static UploadStats,
}

impl Spool {
    /// Retention minutes are 16-bit and wrap above 546 h, as in FlowLink.
    pub fn new(dir: PathBuf, file_retention_hours: i16, data_directory_size_mb: i16) -> Self {
        Self {
            dir,
            retention_mins: file_retention_hours.wrapping_mul(60) as f64,
            max_bytes: (data_directory_size_mb as i64) << 20,
            state: Mutex::default(),
            work: Condvar::new(),
            sending: AtomicI32::new(0),
            stats: stats::uploads(),
        }
    }

    /// Counts removals into `stats` instead of the process-wide counters (tests).
    #[cfg(test)]
    pub(crate) fn with_stats(self, stats: &'static UploadStats) -> Self {
        Self { stats, ..self }
    }

    /// The upload counters this spool and its senders report to.
    pub fn stats(&self) -> &'static UploadStats {
        self.stats
    }

    /// Files and bytes waiting to be sent (queued or being sent).
    pub fn backlog(&self) -> (usize, i64) {
        let st = self.lock();
        (st.files, st.total)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn path(&self, fd: &SpoolFile) -> PathBuf {
        self.dir.join(&fd.name)
    }

    pub fn expired(&self, fd: &SpoolFile) -> bool {
        minutes_since(fd.time) >= self.retention_mins
    }

    pub fn queue_len(&self) -> usize {
        self.lock().queue.len()
    }

    /// Startup scan: queue `traffic_flows*` files sorted by name, deleting expired and
    /// empty ones. The size cap is not applied here.
    pub fn scan(&self) -> io::Result<()> {
        let mut st = self.lock();
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let Ok(meta) = entry.metadata() else { continue };
            if !meta.is_file() || !name.starts_with("traffic_flows") {
                continue;
            }
            let time = meta.modified().unwrap_or(SystemTime::now());
            let size = meta.len() as i64;
            if minutes_since(time) >= self.retention_mins || size == 0 {
                if size != 0 {
                    self.stats.on_removed_by_retention();
                }
                let _ = fs::remove_file(self.dir.join(&name));
                continue;
            }
            insert_sorted(&mut st.queue, SpoolFile { name, size, time, records: 0 });
            st.total += size;
            st.files += 1;
        }
        Ok(())
    }

    /// Evict the oldest queued files to honour the size cap,
    /// write `traffic_flows_<µs>.pb.gz` (0640) and queue it unless shutting down. `records`: flow records in `data`.
    pub fn add(&self, data: &[u8], records: u64, final_flush: bool) {
        let size = data.len() as i64;
        if size == 0 {
            return;
        }
        let mut st = self.lock();
        let mut avail = self.max_bytes - st.total;
        // Silent eviction, as in FlowLink. Divergence: FlowLink panics when the queue
        // runs empty; we stop evicting and still write the file.
        while size > avail {
            let Some(f) = st.queue.pop_front() else { break };
            avail += f.size;
            st.total -= f.size;
            st.files -= 1;
            self.stats.on_removed_by_cap();
            let _ = fs::remove_file(self.dir.join(&f.name));
        }
        let now = SystemTime::now();
        let micros = now.duration_since(UNIX_EPOCH).map(|d| d.as_micros()).unwrap_or(0);
        let name = format!("traffic_flows_{micros}.pb.gz");
        let written = open_0640(&self.dir.join(&name)).and_then(|mut f| f.write_all(data));
        if check_error(written.err()) {
            return;
        }
        if !shutdown() || final_flush {
            st.queue.push_back(SpoolFile { name, size, time: now, records });
            st.total += size;
            st.files += 1;
            self.work.notify_one();
        }
    }

    /// Put a file back in name order (no total change, no signal).
    pub fn insert(&self, fd: SpoolFile) {
        insert_sorted(&mut self.lock().queue, fd);
    }

    /// Forget an already popped file and remove it from disk.
    pub fn delete(&self, fd: &SpoolFile) {
        let mut st = self.lock();
        st.total -= fd.size;
        st.files = st.files.saturating_sub(1);
        let _ = fs::remove_file(self.path(fd));
    }

    /// Pop the oldest file, blocking until one is queued. During
    /// shutdown, files ahead of the last one are dropped from the queue (they stay on disk), so
    /// the final single-file flush is what gets sent. Senders keep waiting during shutdown, as in
    /// FlowLink, so they can pick up that flush.
    pub fn get(&self) -> SpoolFile {
        let mut st = self.lock();
        loop {
            if let Some(fd) = st.queue.pop_front() {
                if !shutdown() || st.queue.is_empty() {
                    return fd;
                }
                continue;
            }
            st = self.work.wait(st).unwrap_or_else(|e| e.into_inner());
        }
    }

    pub fn sending(&self) -> i32 {
        self.sending.load(Ordering::SeqCst)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn insert_sorted(q: &mut VecDeque<SpoolFile>, fd: SpoolFile) {
    let i = q.iter().position(|f| fd.name <= f.name).unwrap_or(q.len());
    q.insert(i, fd);
}

fn minutes_since(t: SystemTime) -> f64 {
    SystemTime::now().duration_since(t).unwrap_or_default().as_secs_f64() / 60.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn spool(dir: &Path, mb: i16) -> Spool {
        Spool::new(dir.to_path_buf(), 24, mb)
    }

    #[test]
    fn add_writes_named_file_and_queues_fifo() {
        let dir = tempfile::tempdir().unwrap();
        let s = spool(dir.path(), 100);
        s.add(b"one", 1, false);
        std::thread::sleep(Duration::from_millis(2));
        s.add(b"two", 1, false);
        s.add(b"", 0, false);
        assert_eq!(s.queue_len(), 2);
        let first = s.get();
        assert!(first.name.starts_with("traffic_flows_") && first.name.ends_with(".pb.gz"));
        assert_eq!(fs::read(s.path(&first)).unwrap(), b"one");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(s.path(&first)).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode & !0o640, 0);
        }
        s.delete(&first);
        assert!(!s.path(&first).exists());
        assert_eq!(fs::read(s.path(&s.get())).unwrap(), b"two");
    }

    #[test]
    fn size_cap_evicts_oldest_and_never_panics() {
        let dir = tempfile::tempdir().unwrap();
        let s = Spool { max_bytes: 10, ..spool(dir.path(), 0) };
        s.add(&[1; 6], 1, false);
        std::thread::sleep(Duration::from_millis(2));
        s.add(&[2; 6], 1, false); // evicts the first
        assert_eq!(s.queue_len(), 1);
        std::thread::sleep(Duration::from_millis(2));
        s.add(&[3; 50], 1, false); // larger than the cap with nothing left to evict
        assert_eq!(s.queue_len(), 1);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn scan_queues_sorted_and_drops_empty_and_foreign_files() {
        let dir = tempfile::tempdir().unwrap();
        for (n, d) in [("traffic_flows_3.pb.gz", "c"), ("traffic_flows_1.pb.gz", "a"), ("traffic_flows_2.pb.gz", "")] {
            fs::write(dir.path().join(n), d).unwrap();
        }
        fs::write(dir.path().join("restart_info.yml"), "x").unwrap();
        let s = spool(dir.path(), 100);
        s.scan().unwrap();
        assert_eq!(s.get().name, "traffic_flows_1.pb.gz");
        assert_eq!(s.get().name, "traffic_flows_3.pb.gz");
        assert!(!dir.path().join("traffic_flows_2.pb.gz").exists());
        assert!(dir.path().join("restart_info.yml").exists());
    }

    fn stats() -> &'static UploadStats {
        Box::leak(Box::new(UploadStats::new()))
    }

    #[test]
    fn backlog_and_removals_are_counted() {
        let dir = tempfile::tempdir().unwrap();
        let st = stats();
        let s = Spool { max_bytes: 10, ..spool(dir.path(), 0).with_stats(st) };
        assert_eq!(s.backlog(), (0, 0));
        s.add(&[1; 3], 3, false);
        std::thread::sleep(Duration::from_millis(2));
        s.add(&[2; 4], 4, false);
        assert_eq!(s.backlog(), (2, 7));
        std::thread::sleep(Duration::from_millis(2));
        s.add(&[3; 6], 5, false); // evicts the first file
        assert_eq!(s.backlog(), (2, 10));
        assert_eq!((st.snapshot().removed_by_cap, st.snapshot().removed_by_retention), (1, 0));
        let fd = s.get();
        assert_eq!((fd.size, fd.records), (4, 4));
        // A popped file still counts until it is sent or deleted.
        assert_eq!(s.backlog(), (2, 10));
        s.delete(&fd);
        assert_eq!(s.backlog(), (1, 6));
    }

    #[test]
    fn scan_counts_expired_files_and_has_no_record_counts() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("traffic_flows_1.pb.gz"), "old").unwrap();
        fs::write(dir.path().join("traffic_flows_2.pb.gz"), "").unwrap(); // empty: dropped, not counted
        let st = stats();
        let s = Spool::new(dir.path().to_path_buf(), 0, 100).with_stats(st); // 0 h: everything has expired
        s.scan().unwrap();
        assert_eq!(s.backlog(), (0, 0));
        assert_eq!((st.snapshot().removed_by_retention, st.snapshot().removed_by_cap), (1, 0));

        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("traffic_flows_1.pb.gz"), "abc").unwrap();
        let s = spool(dir.path(), 100);
        s.scan().unwrap();
        assert_eq!(s.backlog(), (1, 3));
        assert_eq!(s.get().records, 0);
    }

    #[test]
    fn retention_wraps_like_int16() {
        let s = Spool::new(PathBuf::from("."), 547, 100);
        assert_eq!(s.retention_mins, (547i16).wrapping_mul(60) as f64);
        assert!(s.retention_mins < 0.0);
    }
}
