//! Measurements behind the fuzz report's template-store analysis (memory and CPU an
//! unauthenticated UDP sender can make the collector spend). `template_map_is_bounded` asserts the
//! template-map cap; the ignored tests are measurements: run them explicitly and read the numbers
//! on stderr.
//!
//!     cargo test --release --test template_store_growth -- --ignored --nocapture --test-threads=1
//!
//! Live heap bytes are counted by a wrapping global allocator, so the figures are exact for
//! this process (allocator slack and page overhead come on top in RSS).

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crossbeam_channel::unbounded;
use flowpilot::flow::FlowSink;
use flowpilot::metrics::Meter;
use flowpilot::parsers::{decode_datagram, ParserContext, ReceivedDatagram};

struct Counting;
static LIVE: AtomicIsize = AtomicIsize::new(0);

// SAFETY: forwards to System and only adds bookkeeping.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        LIVE.fetch_add(l.size() as isize, Ordering::Relaxed);
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size() as isize, Ordering::Relaxed);
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        LIVE.fetch_add(n as isize - l.size() as isize, Ordering::Relaxed);
        unsafe { System.realloc(p, l, n) }
    }
}

#[global_allocator]
static A: Counting = Counting;

fn live() -> isize {
    LIVE.load(Ordering::Relaxed)
}

/// fd 1 to /dev/null while decoding (every template logs "Created template for").
fn quiet<T>(f: impl FnOnce() -> T) -> T {
    // SAFETY: plain fd juggling on fd 1, restored before returning.
    let saved = unsafe {
        let saved = libc::dup(1);
        let null = libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY);
        libc::dup2(null, 1);
        libc::close(null);
        saved
    };
    let out = f();
    unsafe {
        libc::dup2(saved, 1);
        libc::close(saved);
    }
    out
}

/// The stores are process-wide and fd 1 is redirected while decoding: one test at a time.
fn serial() -> MutexGuard<'static, ()> {
    static SERIAL: Mutex<()> = Mutex::new(());
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

/// Largest IPv4 UDP payload.
const MAX_UDP: usize = 65_507;

fn set(id: u16, body: &[u8]) -> Vec<u8> {
    [&id.to_be_bytes()[..], &(body.len() as u16 + 4).to_be_bytes()[..], body].concat()
}

fn ipfix(export: u32, domain: u32, sets: &[Vec<u8>]) -> Vec<u8> {
    let body = sets.concat();
    [&10u16.to_be_bytes()[..], &((16 + body.len()) as u16).to_be_bytes(), &export.to_be_bytes(), &[0; 4], &domain.to_be_bytes(), &body]
        .concat()
}

fn now() -> u32 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as u32
}

fn ctx() -> ParserContext {
    let (tx, rx) = unbounded();
    std::mem::forget(rx); // flows are not of interest; keep the channel open
    ParserContext::new(Meter::new(), FlowSink::new(tx), Default::default())
}

fn decode(c: &ParserContext, kind: &str, dev: &str, buf: Vec<u8>) {
    let pd = ReceivedDatagram { device_addr: dev.into(), seq_id: String::new(), transport: "udp".into(), buf };
    decode_datagram(kind, &pd, c);
}

/// One max-size IPFIX datagram packed with empty (FieldCount 0) templates: 4 wire bytes each.
fn empty_templates_datagram(first_tid: u16) -> (Vec<u8>, usize) {
    let n = (MAX_UDP - 16 - 4) / 4;
    let body: Vec<u8> = (0..n).flat_map(|i| [(first_tid as usize + i) as u16, 0].into_iter().flat_map(u16::to_be_bytes)).collect();
    (ipfix(now(), 0, &[set(2, &body)]), n)
}

/// The template map has a memory budget per store (32 MiB, `MAX_TEMPLATE_BYTES`): spoofed exporters
/// flooding empty templates stop growing the heap once it is used up, the oldest templates go
/// first, and the ones learned last still decode.
#[test]
fn template_map_is_bounded() {
    const BUDGET: isize = 32 << 20;
    let _serial = serial();
    let c = ctx();
    let v4 = [1u8, 0, 0, 2, 0, 8, 0, 4, 0, 12, 0, 4]; // template 256: source and destination IPv4
    let data = set(256, &[[10, 7, 0, 1, 10, 7, 0, 2]; 4].concat()); // > 32 bytes
    let flows = |dev: &str| {
        let (tx, rx) = unbounded();
        let c = ParserContext::new(Meter::new(), FlowSink::new(tx), Default::default());
        quiet(|| decode(&c, "ipfix", dev, ipfix(now(), 0, std::slice::from_ref(&data))));
        rx.try_iter().count()
    };
    let flood = |from: usize, to: usize| {
        quiet(|| {
            for i in from..to {
                decode(&c, "ipfix", &format!("198.22.{}.{}", i / 256, i % 256), empty_templates_datagram(256).0);
            }
        })
    };
    quiet(|| decode(&c, "ipfix", "198.23.0.1", ipfix(now(), 0, &[set(2, &v4), set(2, &[0; 32])])));
    assert_eq!(flows("198.23.0.1"), 4);

    let before = live();
    flood(0, 20); // ~330 000 templates; the budget holds about 100 000 empty ones
    let full = live();
    flood(20, 40);
    let after = live();
    eprintln!("template map: +{} MiB after 20 datagrams, +{} MiB after 40", (full - before) >> 20, (after - before) >> 20);
    assert!(after - before < BUDGET, "heap grew {} MiB", (after - before) >> 20);
    assert!(after - full < 4 << 20, "heap still growing at the cap: +{} MiB", (after - full) >> 20);

    assert_eq!(flows("198.23.0.1"), 0, "the oldest template was evicted; its data waits for it");
    quiet(|| decode(&c, "ipfix", "198.23.0.2", ipfix(now(), 0, &[set(2, &v4), set(2, &[0; 32])])));
    assert_eq!(flows("198.23.0.2"), 4, "a template learned after the flood decodes");
}

/// Fuzz F2: a template with no data waiting for it must not scan the PendingSet list, so defining
/// templates costs about the same whether the list is empty or at its 10 000-entry cap.
#[test]
fn templates_without_waiting_data_skip_the_replay_scan() {
    let _serial = serial();
    let c = ctx();
    let small: Vec<u8> = (0..(MAX_UDP - 16) / 8).flat_map(|_| set(997, &[0; 4])).collect();
    let tmpl: Vec<u8> = (0..2000u16).flat_map(|i| [256 + i, 0]).flat_map(u16::to_be_bytes).collect();
    let tmpl = ipfix(now(), 0, &[set(2, &tmpl)]);
    let timed = |dev: &str| {
        let t = Instant::now();
        quiet(|| decode(&c, "ipfix", dev, tmpl.clone()));
        t.elapsed()
    };
    let empty = timed("198.24.0.2");
    quiet(|| {
        for _ in 0..2 {
            decode(&c, "ipfix", "198.24.0.1", ipfix(now(), 0, std::slice::from_ref(&small)));
        }
    });
    let full = timed("198.24.0.3");
    // Drain: the template the stashed sets wait for takes them all out.
    quiet(|| decode(&c, "ipfix", "198.24.0.1", ipfix(now(), 0, &[set(2, &[3, 0xe5, 0, 0]), set(4, &[0; 32])])));
    eprintln!("2000 templates: {empty:.2?} with PendingSet empty, {full:.2?} with it at its cap");
    assert!(full < empty * 3 + Duration::from_millis(50), "{full:?} at the cap vs {empty:?} empty");
}

#[test]
#[ignore = "measurement for the fuzz report; run explicitly"]
fn template_map_growth() {
    let _serial = serial();
    let c = ctx();
    // (a) Spoofed devices, each sending one datagram of empty templates.
    let before = live();
    let (dgrams, mut entries, mut wire) = (200, 0usize, 0usize);
    let t = Instant::now();
    quiet(|| {
        for i in 0..dgrams {
            let (d, n) = empty_templates_datagram(256);
            wire += d.len();
            entries += n;
            decode(&c, "ipfix", &format!("198.18.{}.{}", i / 256, i % 256), d);
        }
    });
    let grown = (live() - before) as f64;
    eprintln!(
        "(a) empty templates: {dgrams} datagrams, {wire} wire bytes, {entries} templates sent -> {:.1} MiB live heap, \
         {:.0} B/entry, {:.1}x wire bytes, {:.2?} ({:.1} µs/datagram)",
        grown / 1048576.0,
        grown / entries as f64,
        grown / wire as f64,
        t.elapsed(),
        t.elapsed().as_micros() as f64 / dgrams as f64
    );

    // (b) Wide templates: one template of 16 371 fields per datagram.
    let before = live();
    let n = (MAX_UDP - 16 - 4 - 4) / 4;
    let mut tb = vec![1u8, 0];
    tb.extend((n as u16).to_be_bytes());
    for _ in 0..n {
        tb.extend([0, 2, 0, 4]); // packetDeltaCount, 4 bytes
    }
    let d = ipfix(now(), 0, &[set(2, &tb)]);
    let wire = d.len() * 50;
    quiet(|| {
        for i in 0..50 {
            decode(&c, "ipfix", &format!("198.19.0.{i}"), d.clone());
        }
    });
    let grown = (live() - before) as f64;
    eprintln!(
        "(b) wide templates: 50 x {n}-field templates, {wire} wire bytes -> {:.1} MiB live heap, {:.2}x wire bytes",
        grown / 1048576.0,
        grown / wire as f64
    );
}

#[test]
#[ignore = "measurement for the fuzz report; run explicitly"]
fn stored_data_growth_and_replay_cost() {
    let _serial = serial();
    let c = ctx();
    // (c) Stored data: data sets without a template are buffered (MAX_STORED = 10 000 entries
    // per store, no byte limit). 1 000 max-size data sets here; the cap allows 10x that.
    let before = live();
    let data = vec![0xab; MAX_UDP - 16 - 4];
    let d = ipfix(now(), 0, &[set(999, &data)]);
    quiet(|| {
        for i in 0..1000 {
            decode(&c, "ipfix", &format!("198.20.{}.{}", i / 256, i % 256), d.clone());
        }
    });
    let grown = (live() - before) as f64;
    eprintln!(
        "(c) stored data: 1000 x {} B data sets -> {:.1} MiB live heap ({:.0} B/entry); \
         at the 10 000-entry cap: ~{:.0} MiB per store, two stores (IPFIX, NetFlow v9)",
        data.len(),
        grown / 1048576.0,
        grown / 1000.0,
        grown * 10.0 / 1048576.0
    );

    // (d) Replay scan cost: every template definition partitions the whole PendingSet list.
    // Fill the list to the 10 000-entry cap with tiny data sets (one datagram can stash
    // thousands of 4-byte sets), then time one datagram of empty templates.
    let small: Vec<u8> = (0..(MAX_UDP - 16) / 8).flat_map(|_| set(998, &[0; 4])).collect();
    let fill = ipfix(now(), 0, &[small]);
    quiet(|| {
        for _ in 0..3 {
            decode(&c, "ipfix", "198.21.0.1", fill.clone());
        }
    });
    let (tmpl, n) = empty_templates_datagram(256);
    let t = Instant::now();
    quiet(|| decode(&c, "ipfix", "198.21.0.2", tmpl.clone()));
    let full = t.elapsed();
    // Drain: the template the stashed sets wait for removes them all (and replays them).
    quiet(|| decode(&c, "ipfix", "198.21.0.1", ipfix(now(), 0, &[set(2, &[3, 0xe6, 0, 0]), set(4, &[0; 32])])));
    let t = Instant::now();
    quiet(|| decode(&c, "ipfix", "198.21.0.3", tmpl.clone()));
    eprintln!(
        "(d) one {}-byte datagram with {n} empty templates: {:.2?} with the IPFIX PendingSet list at its \
         10 000-entry cap, {:.2?} with it empty",
        tmpl.len(),
        full,
        t.elapsed()
    );
}
