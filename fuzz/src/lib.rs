//! Shared harness for the FlowPilot decoder fuzz targets (see fuzz/README.md).
//!
//! Every target feeds datagrams to `flowpilot::parsers::decode_datagram`. The NetFlow v9 and IPFIX
//! template stores are process-wide statics that cannot be reset, so each fuzz input gets a fresh
//! device address: templates learned by one input are invisible to the next, and an input
//! reproduces the same way on its own as inside a long run (apart from the wall clock, which the
//! 120-second replay window and `export_time == 0` read).
//!
//! Oracles, besides "does not panic / hang / blow up memory" (libFuzzer's job):
//! * every emitted flow passed `check_flow` (non-empty addresses that parse, version set);
//! * a datagram never yields more than `2 * bytes + 2` flows (NAT duplicates are the only
//!   legitimate doubling) — catches runaway record loops such as one over an empty template;
//! * a v9 or v10 datagram decodes to the same flows on the NetFlow and on the IPFIX parser
//!   (both reinterpret the same 20 header bytes), see [`cross_parser`].

pub mod gen;
pub mod seeds;

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use crossbeam_channel::{unbounded, Receiver};
use flowpilot::flow::{FlowData, FlowSink};
use flowpilot::metrics::Meter;
use flowpilot::parsers::{decode_datagram, ParserContext, ReceivedDatagram};

/// The parsers log every template, unknown set and short read to stdout through `log_line!`, and
/// there is no quiet switch (`-debug` only adds output). So fd 1 is pointed at an unlinked
/// temporary file (unless `FLOWPILOT_FUZZ_VERBOSE` is set; libFuzzer reports on stderr), which
/// [`finish_input`] reads back after every input.
fn log_capture() -> Option<&'static Mutex<File>> {
    static LOG: OnceLock<Option<Mutex<File>>> = OnceLock::new();
    LOG.get_or_init(|| {
        let test = cfg!(test) && std::env::var_os("FLOWPILOT_FUZZ_CAPTURE").is_none();
        if test || std::env::var_os("FLOWPILOT_FUZZ_VERBOSE").is_some() {
            return None;
        }
        let path = std::env::temp_dir().join(format!("flowpilot-fuzz-log-{}", std::process::id()));
        let file = OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&path).ok()?;
        let _ = std::fs::remove_file(&path);
        // SAFETY: dup2 onto fd 1; `file` stays open for the life of the process.
        if unsafe { libc::dup2(file.as_raw_fd(), 1) } < 0 {
            return None;
        }
        Some(Mutex::new(file))
    })
    .as_ref()
}

/// Read and clear the captured log (fd 1 shares the file offset with `file`).
fn take_log() -> String {
    let Some(m) = log_capture() else { return String::new() };
    let mut f = m.lock().unwrap_or_else(|e| e.into_inner());
    let mut s = String::new();
    let _ = f.seek(SeekFrom::Start(0)).and_then(|_| f.read_to_string(&mut s));
    let _ = f.set_len(0).and_then(|_| f.seek(SeekFrom::Start(0)));
    s
}

/// Fuzz-side workaround for finding F2 (replay scan cost): PendingSet entries are only removed when
/// their exact (device, domain, template) key gets a template, and every template definition
/// partitions the whole list (up to 10 000 entries). With a fresh device per input nothing is
/// ever drained, the list sits at its cap and throughput drops to a few execs/s. So after each
/// input, read the `No template for {dev domain tid}` lines it logged and define an empty
/// template for each such key in both stores, which removes the entries (the replay of an
/// empty template stops at once). Only the finished input's own device is touched.
///
/// Also the log-amplification oracle: legitimate parsing logs at most a few lines per 4 bytes
/// of input (one per set, template, stashed set or record), so more than `4 * bytes + 64`
/// lines means a loop that spins without consuming input (see the report, finding F1).
/// `FLOWPILOT_FUZZ_LOG_ORACLE` = `panic` (default), `reject` (do not crash, but keep the input
/// out of the corpus, see [`verdict`]; lets a campaign look past F1) or `off`.
fn finish_input(bytes_decoded: usize) {
    let log = take_log();
    let lines = log.lines().count();
    if lines > 4 * bytes_decoded + 64 {
        match std::env::var("FLOWPILOT_FUZZ_LOG_ORACLE").as_deref() {
            Ok("off") => {}
            Ok("reject") => REJECT.store(true, Ordering::Relaxed),
            _ => panic!("log amplification: {lines} lines from {bytes_decoded} bytes"),
        }
    }
    let mut keys: Vec<(String, u32, u16)> = Vec::new();
    for line in log.lines() {
        let Some(rest) = line.split("No template for {").nth(1) else { continue };
        let Some(key) = rest.split('}').next() else { continue };
        let mut it = key.split(' ');
        if let (Some(dev), Some(Ok(dom)), Some(Ok(tid)), None) =
            (it.next(), it.next().map(str::parse), it.next().map(str::parse), it.next())
        {
            if !keys.iter().any(|k| k.0 == dev && k.1 == dom && k.2 == tid) {
                keys.push((dev.to_string(), dom, tid));
            }
        }
    }
    let now = gen::now_secs();
    for (dev, dom, tid) in keys {
        let t = gen::tmpl(tid, &[]);
        decode("ipfix", &dev, &gen::ipfix_msg(now, 0, dom, &[gen::set(2, &t), gen::set(4, &[0; 32])]));
        decode("netflow", &dev, &gen::v9_msg(1, 0, now, 0, dom, &[gen::set(0, &t)]));
    }
    take_log();
}

static REJECT: AtomicBool = AtomicBool::new(false);

/// What a target returns: `Reject` when the input tripped the log oracle in `reject` mode.
pub fn verdict() -> libfuzzer_sys::Corpus {
    if REJECT.swap(false, Ordering::Relaxed) {
        libfuzzer_sys::Corpus::Reject
    } else {
        libfuzzer_sys::Corpus::Keep
    }
}

/// A device address no earlier input has used (template store isolation).
pub fn fresh_device() -> String {
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    format!("fz{n}")
}

struct Harness {
    ctx: ParserContext,
    rx: Receiver<FlowData>,
}

fn harness() -> &'static Harness {
    static H: OnceLock<Harness> = OnceLock::new();
    H.get_or_init(|| {
        log_capture();
        let (tx, rx) = unbounded();
        Harness { ctx: ParserContext::new(Meter::new(), FlowSink::new(tx), Default::default()), rx }
    })
}

/// Decode one datagram from `dev` with parser `kind` and return the flows it emitted.
pub fn decode(kind: &str, dev: &str, buf: &[u8]) -> Vec<FlowData> {
    let h = harness();
    let pd = ReceivedDatagram { device_addr: dev.into(), seq_id: "fz".into(), transport: "udp".into(), buf: buf.to_vec() };
    decode_datagram(kind, &pd, &h.ctx);
    let flows: Vec<FlowData> = h.rx.try_iter().collect();
    for f in &flows {
        check_flow_invariants(f);
    }
    flows
}

/// Decode a sequence of datagrams from one fresh device (templates persist between them).
/// Returns the number of flows; asserts the amplification bound over the whole sequence, since
/// stored data from an earlier datagram may be replayed by a later template.
pub fn decode_sequence(kind: &str, datagrams: &[&[u8]]) -> usize {
    let dev = fresh_device();
    let (mut flows, mut bytes) = (0usize, 0usize);
    for d in datagrams {
        bytes += d.len();
        flows += decode(kind, &dev, d).len();
        assert!(flows <= 2 * bytes + 2, "{flows} flows from {bytes} bytes");
    }
    finish_input(bytes);
    flows
}

fn check_flow_invariants(f: &FlowData) {
    assert!(f.key.src_ip.parse::<IpAddr>().is_ok(), "unparsable src_ip {:?}", f.key.src_ip);
    assert!(f.key.dst_ip.parse::<IpAddr>().is_ok(), "unparsable dst_ip {:?}", f.key.dst_ip);
    assert!(f.key.ip_version != 0);
}

/// Split one fuzz input into datagrams: repeated `[len: u16 BE][len bytes]`, the last one
/// truncated to what is left. At most 16 datagrams.
pub fn split_sequence(data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut rest = data;
    while rest.len() >= 2 && out.len() < 16 {
        let n = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
        rest = &rest[2..];
        let n = n.min(rest.len());
        out.push(&rest[..n]);
        rest = &rest[n..];
    }
    out
}

/// Inverse of [`split_sequence`] (seeds, tests).
pub fn join_sequence(datagrams: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for d in datagrams {
        out.extend_from_slice(&(d.len() as u16).to_be_bytes());
        out.extend_from_slice(d);
    }
    out
}

/// Differential oracle: a version 9 or 10 datagram must decode identically on the NetFlow and
/// the IPFIX parser (each with its own fresh device, so the stores do not interact). When the
/// header time is 0 both use the local clock, so the flow time may differ by the second boundary.
pub fn cross_parser(buf: &[u8]) {
    let clock = match buf.get(..2) {
        Some([0, 10]) => buf.get(4..8) == Some(&[0; 4]), // ExportTime
        Some([0, 9]) => buf.get(8..12) == Some(&[0; 4]), // unix_secs
        _ => return,
    };
    let norm = |v: Vec<FlowData>| {
        v.into_iter()
            .map(|mut f| {
                f.key.device_addr.clear();
                f
            })
            .collect::<Vec<_>>()
    };
    let a = norm(decode("netflow", &fresh_device(), buf));
    let b = norm(decode("ipfix", &fresh_device(), buf));
    finish_input(2 * buf.len());
    assert_eq!(a.len(), b.len(), "netflow vs ipfix parser: flow count differs");
    for (x, y) in a.iter().zip(&b) {
        if clock {
            assert!((x.flow_time - y.flow_time).abs() <= 1, "flow_time {x} vs {y}");
            let (mut x, mut y) = (x.clone(), y.clone());
            (x.flow_time, y.flow_time) = (0, 0);
            assert_eq!(x, y, "netflow vs ipfix parser");
        } else {
            assert_eq!(x, y, "netflow vs ipfix parser");
        }
    }
}

