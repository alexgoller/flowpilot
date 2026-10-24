//! Persisted state: IPs already known to the PCE (`uw_known`) and the sliding flow window (`uw_candidates`).

use super::window::FlowWindow;
use crate::reported_ips::open_0640;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::{self, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::{fs, mem};

const DAY_SECS: i64 = 86_400;

#[derive(Serialize, Deserialize, Default, Debug, PartialEq)]
pub struct KnownState {
    pub ips: BTreeSet<IpAddr>,
    pub last_full_refresh: Option<i64>,
    /// Unix seconds of each workload creation, for the daily cap.
    pub created_at: Vec<i64>,
}

impl KnownState {
    /// Creations after `now - 86400`; older entries are pruned. Future entries (the clock stepped back) are
    /// clamped to `now` and counted, so a clock step never frees the daily cap and locks it for at most 24 h.
    pub fn created_in_last_day(&mut self, now: i64) -> usize {
        for t in &mut self.created_at {
            *t = (*t).min(now);
        }
        self.created_at.retain(|&t| t > now - DAY_SECS);
        self.created_at.len()
    }
}

pub struct StateFiles {
    known: PathBuf,
    candidates: PathBuf,
}

impl StateFiles {
    pub fn new(dir: &Path, pce_addr: &str, org_id: i32) -> Self {
        let base = format!("{pce_addr}-org{org_id}-uw_");
        Self { known: dir.join(format!("{base}known.json")), candidates: dir.join(format!("{base}candidates.json")) }
    }

    pub fn load_known(&self) -> KnownState {
        load(&self.known)
    }

    pub fn save_known(&self, s: &KnownState) -> io::Result<()> {
        save(&self.known, s)
    }

    pub fn load_window(&self) -> FlowWindow {
        load(&self.candidates)
    }

    pub fn save_window(&self, w: &FlowWindow) -> io::Result<()> {
        save(&self.candidates, w)
    }
}

/// A missing file is a normal first start; an unreadable one is logged and treated as empty.
fn load<T: DeserializeOwned + Default>(path: &Path) -> T {
    match fs::read(path) {
        Ok(data) => serde_json::from_slice(&data).unwrap_or_else(|e| {
            crate::log_line!("Unmanaged workloads: ignoring unreadable", path.display().to_string() + ":", e);
            T::default()
        }),
        Err(e) if e.kind() == io::ErrorKind::NotFound => T::default(),
        Err(e) => {
            crate::log_line!("Unmanaged workloads: ignoring unreadable", path.display().to_string() + ":", e);
            T::default()
        }
    }
}

fn save<T: Serialize>(path: &Path, v: &T) -> io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let mut f = open_0640(&tmp)?;
    f.write_all(&serde_json::to_vec(v)?)?;
    f.sync_all()?;
    mem::drop(f);
    fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn created_in_last_day_prunes_old_and_keeps_future() {
        // A future entry (clock stepped back) still counts, so the step cannot free the cap.
        let mut k = KnownState { created_at: vec![10, 13_600, 13_601, 100_001], ..Default::default() };
        assert_eq!(k.created_in_last_day(100_000), 2);
        assert_eq!(k.created_at, [13_601, 100_000]);
    }

    #[test]
    fn future_entries_lock_the_cap_at_most_a_day() {
        // Created while the clock was a week ahead: clamped to now, so it frees 24 h after the correction.
        let mut k = KnownState { created_at: vec![100_000 + 7 * DAY_SECS], ..Default::default() };
        assert_eq!(k.created_in_last_day(100_000), 1);
        assert_eq!(k.created_in_last_day(100_000 + DAY_SECS), 0);
    }

    #[test]
    fn files_named_like_reported_ips() {
        let dir = tempfile::tempdir().unwrap();
        let sf = StateFiles::new(dir.path(), "pce.example:8443", 3);
        sf.save_known(&KnownState::default()).unwrap();
        let p = dir.path().join("pce.example:8443-org3-uw_known.json");
        assert!(p.exists());
        assert!(!dir.path().join("pce.example:8443-org3-uw_known.json.tmp").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o640);
        }
        sf.save_window(&FlowWindow::default()).unwrap();
        assert!(dir.path().join("pce.example:8443-org3-uw_candidates.json").exists());
    }

    #[test]
    fn roundtrip_known_and_window() {
        let dir = tempfile::tempdir().unwrap();
        let sf = StateFiles::new(dir.path(), "pce", 1);
        let k = KnownState {
            ips: BTreeSet::from([ip("10.0.0.1"), ip("10.0.0.2")]),
            last_full_refresh: Some(5),
            created_at: vec![1, 2],
        };
        sf.save_known(&k).unwrap();
        assert_eq!(sf.load_known(), k);
        let mut w = FlowWindow::default();
        w.add(7, BTreeMap::from([(ip("10.0.0.3"), 9)]));
        sf.save_window(&w).unwrap();
        assert_eq!(sf.load_window(), w);
    }

    #[test]
    fn load_accepts_old_file_with_last_check() {
        let dir = tempfile::tempdir().unwrap();
        let sf = StateFiles::new(dir.path(), "pce", 1);
        let old = r#"{"ips":["10.0.0.1"],"last_full_refresh":5,"last_check":6,"created_at":[1]}"#;
        fs::write(dir.path().join("pce-org1-uw_known.json"), old).unwrap();
        let k = sf.load_known();
        assert_eq!(k.ips, BTreeSet::from([ip("10.0.0.1")]));
        assert_eq!((k.last_full_refresh, k.created_at), (Some(5), vec![1]));
    }

    #[test]
    fn load_accepts_old_window_with_one_slice_per_batch() {
        let dir = tempfile::tempdir().unwrap();
        let sf = StateFiles::new(dir.path(), "pce", 1);
        let old = r#"{"slices":[{"end":7200,"counts":{"10.0.0.1":2}},{"end":7800,"counts":{"10.0.0.1":3}}]}"#;
        fs::write(dir.path().join("pce-org1-uw_candidates.json"), old).unwrap();
        let mut w = sf.load_window();
        w.add(8_400, BTreeMap::from([(ip("10.0.0.1"), 4)]));
        assert_eq!(w.totals()[&ip("10.0.0.1")], 9);
        w.expire(7_200 + 86_400, 86_400);
        assert_eq!(w.totals()[&ip("10.0.0.1")], 7);
    }

    #[test]
    fn load_ignores_truncated_file() {
        let dir = tempfile::tempdir().unwrap();
        let sf = StateFiles::new(dir.path(), "pce", 1);
        fs::write(dir.path().join("pce-org1-uw_known.json"), "{\"ips\":[").unwrap();
        assert_eq!(sf.load_known(), KnownState::default());
        assert_eq!(sf.load_window(), FlowWindow::default());
    }
}
