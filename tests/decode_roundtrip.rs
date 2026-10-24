//! Round-trip property test for the template decoders (IPFIX and NetFlow v9, on both ports).
//!
//! A deterministic generator builds a random template (IPv4 or IPv6 addresses, ports, protocol,
//! octetDeltaCount in 1/2/4/8-byte encodings, MACs, flowDirection, timestamps 150-153 and
//! 21/22 in random field order) and 1-3 records with known values, encodes them as one message,
//! decodes it with `parsers::decode_datagram` and compares the flows with an independent model
//! of the documented behaviour (docs/collectors.md, the flow filter and direction swap, and
//! docs/differences-from-flowlink.md), including the kept FlowLink behaviour that unsupported IE 1
//! widths abandon the data set, and the fixes for sets in the last 32 bytes of an IPFIX message and
//! for ICMP type/code in the destination port.
//!
//! Disagreements with RFC 7011 that the documented behaviour does not cover are kept as `#[ignore]`d tests
//! named after their finding (see the fuzz report); they fail today by design.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use crossbeam_channel::{unbounded, Receiver};
use flowpilot::flow::{FlowData, FlowKey, FlowSink};
use flowpilot::metrics::Meter;
use flowpilot::parsers::{decode_datagram, ParserContext, ReceivedDatagram};

// ---------------------------------------------------------------------------------------------
// Plumbing

/// splitmix64: small, deterministic, good enough for test-case generation.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn chance(&mut self, num: u64, den: u64) -> bool {
        self.below(den) < num
    }
    fn pick<T: Copy>(&mut self, v: &[T]) -> T {
        v[self.below(v.len() as u64) as usize]
    }
    fn bytes<const N: usize>(&mut self) -> [u8; N] {
        std::array::from_fn(|_| self.next() as u8)
    }
}

/// The parsers log to stdout through `log_line!` with no quiet switch, which would bury the test
/// output under thousands of "Created template" lines. Point fd 1 at /dev/null while a case
/// batch runs and restore it afterwards (also on panic). Serialised: fd 1 is process-wide.
struct Quiet {
    saved: i32,
    _guard: std::sync::MutexGuard<'static, ()>,
}

static QUIET: Mutex<()> = Mutex::new(());

impl Quiet {
    fn new() -> Self {
        let guard = QUIET.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: plain libc fd juggling on fd 1; restored in Drop.
        let saved = unsafe {
            let saved = libc::dup(1);
            let null = libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY);
            if null >= 0 {
                libc::dup2(null, 1);
                libc::close(null);
            }
            saved
        };
        Self { saved, _guard: guard }
    }
}

impl Drop for Quiet {
    fn drop(&mut self) {
        if self.saved >= 0 {
            // SAFETY: restores the fd saved in `new`.
            unsafe {
                libc::dup2(self.saved, 1);
                libc::close(self.saved);
            }
        }
    }
}

struct Decoder {
    ctx: ParserContext,
    rx: Receiver<FlowData>,
}

/// Device addresses are unique per process: tests run in parallel and share the static stores.
static DEVICES: AtomicU64 = AtomicU64::new(0);

impl Decoder {
    fn new() -> Self {
        let (tx, rx) = unbounded();
        Self { ctx: ParserContext::new(Meter::new(), FlowSink::new(tx), Default::default()), rx }
    }

    /// Decode with a device address no other case used (the template stores are static).
    fn decode(&mut self, kind: &str, buf: Vec<u8>) -> (String, Vec<FlowData>) {
        let dev = format!("prop-{}", DEVICES.fetch_add(1, Ordering::Relaxed));
        let pd = ReceivedDatagram { device_addr: dev.clone(), seq_id: String::new(), transport: "udp".into(), buf };
        decode_datagram(kind, &pd, &self.ctx);
        (dev, self.rx.try_iter().collect())
    }
}

// ---------------------------------------------------------------------------------------------
// Generated cases

#[derive(Clone, Copy, Debug, PartialEq)]
enum Flavor {
    Ipfix,
    V9,
}

/// One template field with its encoded value for each record.
#[derive(Clone, Debug)]
struct Field {
    id: u16,
    len: u16,
    values: Vec<Vec<u8>>,
}

#[derive(Debug)]
struct Case {
    flavor: Flavor,
    kind: &'static str,
    fields: Vec<Field>,
    records: usize,
    time: u32,
    uptime: u32,
    seq: u32,
    /// IPFIX: an ignored set after the data set (it kept the data set out of FlowLink's
    /// 32-byte cut-off; now it only checks that the set after the data does no harm).
    filler: bool,
    pad: usize,
}

fn v4(r: &mut Rng) -> [u8; 4] {
    match r.below(24) {
        0 => [0, 0, 0, 0],
        1 => [224, 0, 0, r.next() as u8],
        2 => [255, 255, 255, 255],
        3 => [240 | (r.next() as u8 & 0x0f), 1, 2, 3],
        _ => r.bytes(),
    }
}

fn v6(r: &mut Rng) -> [u8; 16] {
    match r.below(24) {
        0 => [0; 16],
        1 => {
            let mut a = [0u8; 16];
            a[0] = 0xff;
            a[1] = 0x02;
            a[15] = 1;
            a
        }
        2 => Ipv4Addr::from(v4(r)).to_ipv6_mapped().octets(),
        3 => {
            let mut a = [0u8; 16];
            a[15] = r.next() as u8; // ::x, text starts with ':'
            a
        }
        _ => {
            let mut a: [u8; 16] = r.bytes();
            a[0] &= 0xfe; // keep ff00::/8 to the explicit case above
            a
        }
    }
}

fn port(r: &mut Rng) -> u16 {
    match r.below(6) {
        0 => 0,
        1 => r.pick(&[22, 53, 80, 443, 3389]),
        2 => 32768 + r.below(32768) as u16,
        3 => r.pick(&[32767, 32768, 32769]),
        _ => r.next() as u16,
    }
}

fn mac(r: &mut Rng) -> [u8; 6] {
    match r.below(24) {
        0 => [0x01, 0x00, 0x5e, 0, 0, 1],
        1 => [0xff; 6],
        2 => [0x33, 0x33, 0, 0, 0, 1],
        _ => r.bytes(),
    }
}

fn gen_case(r: &mut Rng) -> Case {
    let flavor = if r.chance(1, 2) { Flavor::Ipfix } else { Flavor::V9 };
    // v10 on the NetFlow port and v9 on the IPFIX port take the same code paths.
    let kind = match (flavor, r.chance(1, 4)) {
        (Flavor::Ipfix, false) | (Flavor::V9, true) => "ipfix",
        _ => "netflow",
    };
    let records = 1 + r.below(3) as usize;
    let mut fields = Vec::new();
    let mut field = |id: u16, len: u16, gen: &mut dyn FnMut(&mut Rng) -> Vec<u8>, r: &mut Rng| {
        let values = (0..records).map(|_| gen(r)).collect();
        fields.push(Field { id, len, values });
    };
    if r.chance(1, 2) {
        field(8, 4, &mut |r| v4(r).to_vec(), r);
        field(12, 4, &mut |r| v4(r).to_vec(), r);
    } else {
        field(27, 16, &mut |r| v6(r).to_vec(), r);
        field(28, 16, &mut |r| v6(r).to_vec(), r);
    }
    if r.chance(4, 5) {
        field(7, 2, &mut |r| port(r).to_be_bytes().to_vec(), r);
    }
    if r.chance(4, 5) {
        field(11, 2, &mut |r| port(r).to_be_bytes().to_vec(), r);
    }
    if r.chance(4, 5) {
        field(4, 1, &mut |r| vec![r.pick(&[6, 17, 1, 58, 47, 0, 43])], r);
    }
    if r.chance(4, 5) {
        // RFC 7011 §6.2 reduced-size encoding; 1 and 2 bytes hit Q5 (see below).
        let len = r.pick(&[1u16, 2, 4, 4, 4, 4, 8, 8, 8, 8, 8, 8]);
        field(1, len, &mut |r| (r.next() >> 1).to_be_bytes()[8 - usize::from(len)..].to_vec(), r);
    }
    if r.chance(1, 3) {
        field(56, 6, &mut |r| mac(r).to_vec(), r);
        field(57, 6, &mut |r| mac(r).to_vec(), r);
    }
    if r.chance(1, 3) {
        field(61, 1, &mut |r| vec![r.pick(&[0, 1, 2])], r);
    }
    let base: u64 = 1_700_000_000;
    let mut times: Vec<(u16, u16)> = vec![(150, 4), (151, 4), (152, 8), (153, 8)];
    if flavor == Flavor::V9 {
        times.extend([(21, 4), (22, 4)]);
    }
    for (id, len) in times {
        if r.chance(1, 3) {
            field(
                id,
                len,
                &mut |r| match id {
                    150 | 151 => ((base + r.below(1_000_000)) as u32).to_be_bytes().to_vec(),
                    152 | 153 => ((base + r.below(1_000_000)) * 1000 + r.below(1000)).to_be_bytes().to_vec(),
                    _ => (r.next() as u32).to_be_bytes().to_vec(), // 21/22: any uptime, wraps
                },
                r,
            );
        }
    }
    // Random field order: the decoder's last-writer-wins rules depend on it.
    for i in (1..fields.len()).rev() {
        let j = r.below(i as u64 + 1) as usize;
        fields.swap(i, j);
    }
    Case {
        flavor,
        kind,
        fields,
        records,
        time: (base + r.below(1_000_000)) as u32,
        uptime: if r.chance(1, 8) { 0 } else { r.next() as u32 },
        seq: r.next() as u32,
        filler: r.chance(3, 4),
        pad: r.below(4) as usize,
    }
}

const TID: u16 = 300;
const DOMAIN: u32 = 7;

fn set(id: u16, body: &[u8]) -> Vec<u8> {
    [&id.to_be_bytes()[..], &(body.len() as u16 + 4).to_be_bytes()[..], body].concat()
}

fn encode(c: &Case) -> Vec<u8> {
    let mut t = [TID.to_be_bytes(), (c.fields.len() as u16).to_be_bytes()].concat();
    for f in &c.fields {
        t.extend(f.id.to_be_bytes());
        t.extend(f.len.to_be_bytes());
    }
    let mut data = Vec::new();
    for i in 0..c.records {
        for f in &c.fields {
            data.extend_from_slice(&f.values[i]);
        }
    }
    data.resize(data.len() + c.pad, 0);
    let (tset, dset) = match c.flavor {
        Flavor::Ipfix => (set(2, &t), set(TID, &data)),
        Flavor::V9 => (set(0, &t), set(TID, &data)),
    };
    let filler = if c.filler && c.flavor == Flavor::Ipfix { set(4, &[0; 32]) } else { Vec::new() };
    let body = [tset, dset, filler].concat();
    let hdr: Vec<u8> = match c.flavor {
        Flavor::Ipfix => [
            &10u16.to_be_bytes()[..],
            &(16 + body.len() as u16).to_be_bytes(),
            &c.time.to_be_bytes(),
            &c.seq.to_be_bytes(),
            &DOMAIN.to_be_bytes(),
        ]
        .concat(),
        Flavor::V9 => [
            &9u16.to_be_bytes()[..],
            &2u16.to_be_bytes(), // count: two FlowSets
            &c.uptime.to_be_bytes(),
            &c.time.to_be_bytes(),
            &c.seq.to_be_bytes(),
            &DOMAIN.to_be_bytes(),
        ]
        .concat(),
    };
    [hdr, body].concat()
}

// ---------------------------------------------------------------------------------------------
// Spec model

fn be(b: &[u8]) -> u64 {
    b.iter().fold(0, |a, &x| a << 8 | u64::from(x))
}

/// Go `net.IP.String()` of a 16-byte address: IPv4-mapped prints dotted.
fn ip6_text(a: [u8; 16]) -> String {
    let ip = Ipv6Addr::from(a);
    match ip.to_ipv4_mapped() {
        Some(v4) => v4.to_string(),
        None => ip.to_string(),
    }
}

fn mac_text(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(":")
}

/// Multicast/broadcast test of the flow filter, written from its description.
fn special(ip: &str, mac: &str) -> bool {
    let idx = |c: char| ip.find(c).is_some_and(|i| i > 0);
    let parsed: Option<IpAddr> = ip.parse().ok();
    let as_v4 = match parsed {
        Some(IpAddr::V4(a)) => Some(a),
        Some(IpAddr::V6(a)) => a.to_ipv4_mapped(),
        None => None,
    };
    let v4_d = as_v4.is_some_and(|a| a.octets()[0] >= 224);
    let v6_d = as_v4.is_none() && matches!(parsed, Some(IpAddr::V6(a)) if a.octets()[0] == 0xff);
    (idx('.') && (v4_d || mac.starts_with("01:00:5E:") || mac == "FF:FF:FF:FF:FF:FF"))
        || (idx(':') && (v6_d || mac.starts_with("33:33")))
}

/// The flow filter and direction heuristic.
fn filter_flow(mut fd: FlowData) -> Option<FlowData> {
    let k = &fd.key;
    if k.src_ip.is_empty() || k.dst_ip.is_empty() || k.ip_version == 0 {
        return None;
    }
    if k.ip_version == 6 && matches!(k.protocol, 0 | 43 | 44) {
        return None;
    }
    if special(&k.src_ip, &k.src_mac) || special(&k.dst_ip, &k.dst_mac) {
        return None;
    }
    if k.dst_port > 0 && matches!(k.protocol, 1 | 58) {
        return None;
    }
    if fd.direction_ind == 2 && fd.src_port != 0 && fd.key.dst_port != 0 {
        if fd.src_port < fd.key.dst_port && fd.key.dst_port > 32768 && fd.src_port < 32768 {
            std::mem::swap(&mut fd.key.src_ip, &mut fd.key.dst_ip);
            std::mem::swap(&mut fd.key.dst_port, &mut fd.src_port);
        }
        fd.direction_ind = 0;
    }
    Some(fd)
}

/// What the collector is documented to emit for this case.
fn expected(c: &Case, dev: &str) -> Vec<FlowData> {
    // Divergence from FlowLink: every set is parsed, also in the last 32 bytes of an IPFIX message.
    // As in FlowLink: IE 1 with a width other than 4 or >= 8 abandons the data set (records before it in
    // the set are kept; it hits the first record here).
    if c.fields.iter().any(|f| f.id == 1 && f.len != 4 && f.len < 8) {
        return Vec::new();
    }
    let sys_uptime = if c.flavor == Flavor::V9 { c.uptime } else { 0 };
    let mut out = Vec::new();
    for i in 0..c.records {
        let mut fd = FlowData {
            transport: "udp".into(),
            seq_id: c.seq.to_string(),
            key: FlowKey { device_addr: dev.into(), ..Default::default() },
            flow_time: c.time.into(),
            flows: 1,
            direction_ind: 2,
            ..Default::default()
        };
        for f in &c.fields {
            let v = &f.values[i];
            let k = &mut fd.key;
            match f.id {
                8 | 12 if v != &[0; 4] => {
                    k.ip_version = 4;
                    let s = Ipv4Addr::new(v[0], v[1], v[2], v[3]).to_string();
                    *(if f.id == 8 { &mut k.src_ip } else { &mut k.dst_ip }) = s;
                }
                27 | 28 => {
                    let a: [u8; 16] = v[..].try_into().unwrap();
                    let ip = Ipv6Addr::from(a);
                    if !(ip.is_unspecified() || ip.to_ipv4_mapped() == Some(Ipv4Addr::UNSPECIFIED)) {
                        k.ip_version = 6;
                        *(if f.id == 27 { &mut k.src_ip } else { &mut k.dst_ip }) = ip6_text(a);
                    }
                }
                7 => fd.src_port = be(v) as u16,
                11 => k.dst_port = be(v) as u16,
                4 => k.protocol = v[0],
                1 => fd.octets = be(v) as i64,
                56 => k.src_mac = mac_text(v),
                57 => k.dst_mac = mac_text(v),
                61 => fd.direction_ind = v[0],
                150 => fd.flow_time = be(v) as i64,
                152 => fd.flow_time = be(v) as i64 / 1000,
                22 if sys_uptime != 0 => fd.flow_time -= i64::from(sys_uptime.wrapping_sub(be(v) as u32) / 1000),
                _ => {} // 151, 153 (flow end) and 21 (LAST_SWITCHED) are not decoded
            }
        }
        // Divergence from FlowLink: no ICMP type/code IE is generated, so for ICMP the destination
        // port carries them: type*256 + code, or the bare type below 256.
        let k = &mut fd.key;
        if matches!(k.protocol, 1 | 58) && k.dst_port != 0 {
            let p = k.dst_port;
            (k.icmp_type, k.icmp_code) = if p < 256 { (p as u8, 0) } else { ((p >> 8) as u8, (p & 0xff) as u8) };
            k.dst_port = 0;
        }
        out.extend(filter_flow(fd));
    }
    out
}

fn run_cases(seed: u64, n: usize) {
    let mut r = Rng(seed);
    let mut d = Decoder::new();
    let (mut failures, mut flows) = (Vec::new(), 0);
    {
        let _quiet = Quiet::new();
        for i in 0..n {
            let c = gen_case(&mut r);
            let buf = encode(&c);
            let (dev, got) = d.decode(c.kind, buf.clone());
            let want = expected(&c, &dev);
            flows += got.len();
            if got != want && failures.len() < 3 {
                failures.push(format!("case {i}: {c:?}\n bytes {buf:02x?}\n got  {got:?}\n want {want:?}"));
            }
        }
    }
    assert!(failures.is_empty(), "{} mismatching case(s):\n{}", failures.len(), failures.join("\n\n"));
    // Not vacuous: filters and quirks drop many records, but most cases must still emit.
    assert!(flows > n / 2, "only {flows} flows from {n} cases");
}

#[test]
fn template_records_decode_as_specified() {
    run_cases(0x5eed_f10f, 4000);
}

// ---------------------------------------------------------------------------------------------
// Findings: RFC behaviour FlowPilot does not implement, failing today by design.

/// IPFIX message with one template (IPv4 pair + IE 1 of width `w`) and one record.
fn octets_msg(w: u16, value: u64) -> Vec<u8> {
    let t: Vec<u8> = [TID, 3, 8, 4, 12, 4, 1, w].iter().flat_map(|x| x.to_be_bytes()).collect();
    // 12.12.12.12 -> 12.12.12.13 plus the counter, then an ignored set (it was needed for FlowLink's 32-byte cut-off).
    let rec = [&[12, 12, 12, 12, 12, 12, 12, 13][..], &value.to_be_bytes()[8 - usize::from(w)..]].concat();
    let body = [set(2, &t), set(TID, &rec), set(4, &[0; 32])].concat();
    [&10u16.to_be_bytes()[..], &(16 + body.len() as u16).to_be_bytes(), &1_700_000_000u32.to_be_bytes(), &[0; 8], &body]
        .concat()
}

#[test]
#[ignore = "finding F3: RFC 7011 §6.2 reduced-size octetDeltaCount (1/2/3/5/6/7 bytes) drops the whole data set (open for decision)"]
fn reduced_size_octet_delta_count_is_decoded() {
    let mut d = Decoder::new();
    for w in [1u16, 2, 3, 5, 6, 7] {
        let value = 0xab & ((1u64 << (8 * w)) - 1);
        let (_, got) = d.decode("ipfix", octets_msg(w, value));
        assert_eq!(got.len(), 1, "width {w}: record dropped");
        assert_eq!(got[0].octets, value as i64, "width {w}");
    }
}

#[test]
fn full_width_octet_delta_count_is_decoded() {
    let mut d = Decoder::new();
    for (w, v) in [(4u16, 0xdead_beefu64), (8, 0x0123_4567_89ab_cdef)] {
        let (_, got) = d.decode("ipfix", octets_msg(w, v));
        assert_eq!(got.len(), 1, "width {w}");
        assert_eq!(got[0].octets, v as i64, "width {w}");
    }
}
