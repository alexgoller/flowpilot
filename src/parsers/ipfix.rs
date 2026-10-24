//! IPFIX (v10) parser, the v9/IPFIX template store with "data before template" replay, and the
//! shared record decoder `decode_data_set` (docs/collectors.md).

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crossbeam_channel::{bounded, Receiver, Sender};

use crate::config::{Info, Properties};
use crate::flow::{icmp_from_dst_port, FlowData, FlowSink};
use crate::log::{join_bytes, check_error, debug, debug_hex, note_decode_error, take_decode_errors};
use crate::parsers::{connect_all, netflow, Parser, ParserContext, ReceivedDatagram};
use crate::stats::{CollectorStats, Proto, ThreadGuard};
use crate::{debug_log, log_line};

const NTP_UNIX_OFFSET: i64 = 2_208_988_800;
/// PendingSet replay window (120 s, inclusive).
const REPLAY_WINDOW: Duration = Duration::from_secs(120);
/// Divergence (docs/differences-from-flowlink.md, "Data before its template"): FlowLink buffers
/// PendingSet without limit. We keep at
/// most this many entries per store and drop the oldest first; which data is replayed is unchanged
/// unless an exporter has more than this many un-templated data sets outstanding.
pub(crate) const MAX_STORED: usize = 10_000;
/// The same cap in bytes (`stored_cost`): 10 000 data sets of up to 64 KiB would hold about 630 MiB.
/// Exporters normally send templates within seconds, so a few sets per exporter wait at a time.
pub(crate) const MAX_STORED_BYTES: usize = 32 << 20;
/// Divergence (docs/differences-from-flowlink.md, "Template map"): FlowLink's template map grows without limit, and its keys
/// (exporter address, domain, template id) come from unauthenticated UDP. We keep about this many
/// heap bytes of templates per store (`template_cost`) and drop the least recently (re)defined
/// first. 500 exporters with 20 templates of 100 fields each need about 7.5 MiB.
pub(crate) const MAX_TEMPLATE_BYTES: usize = 32 << 20;
/// FieldLength of a variable-length field (RFC 7011 §7; also used by v9 exporters such as H3C).
const VARLEN: u16 = 0xFFFF;

/// Sets up the IPFIX parser and its connectors.
pub fn setup(properties: &Properties, connectors: &[Info], ctx: ParserContext) -> bool {
    for k in properties.keys() {
        log_line!("Unsupported ipfix parser property:", k);
    }
    connect_all(Arc::new(IpfixParser { ctx }), connectors)
}

// ---------------------------------------------------------------------------------------------
// Wire reading helpers

/// Go io errors as returned by `binary.Read` on a `bytes.Reader`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReadError {
    Eof,
    UnexpectedEof,
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Eof => "EOF",
            Self::UnexpectedEof => "unexpected EOF",
        })
    }
}

/// `bytes.Reader` semantics: seeking past the end is allowed, a short read consumes what is left
/// and fails with `unexpected EOF` (`EOF` when nothing was left).
#[derive(Debug)]
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    pub fn seek(&mut self, n: usize) {
        self.pos = self.pos.saturating_add(n);
    }

    /// Absolute offset from the start of the datagram.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Moves to an absolute offset (may be past the end, like `seek`).
    pub fn seek_to(&mut self, pos: usize) {
        self.pos = pos;
    }

    pub fn read(&mut self, n: usize) -> Result<&'a [u8], ReadError> {
        let rem = self.remaining();
        if n == 0 {
            return Ok(&[]);
        }
        if rem == 0 {
            return Err(ReadError::Eof);
        }
        if rem < n {
            self.pos = self.buf.len();
            return Err(ReadError::UnexpectedEof);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], ReadError> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.read(N)?);
        Ok(a)
    }

    pub fn u8(&mut self) -> Result<u8, ReadError> {
        Ok(self.array::<1>()?[0])
    }

    pub fn u16(&mut self) -> Result<u16, ReadError> {
        self.array().map(u16::from_be_bytes)
    }

    pub fn u32(&mut self) -> Result<u32, ReadError> {
        self.array().map(u32::from_be_bytes)
    }

    pub fn u64(&mut self) -> Result<u64, ReadError> {
        self.array().map(u64::from_be_bytes)
    }

    /// A 4-byte pair of u16s (set header, template header or field specifier), read as one unit.
    pub fn pair(&mut self) -> Result<(u16, u16), ReadError> {
        let b: [u8; 4] = self.array()?;
        Ok((be16(&b, 0), be16(&b, 2)))
    }
}

pub(crate) fn be16(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}

pub(crate) fn be32(b: &[u8], i: usize) -> u32 {
    u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

/// Go `net.IP.String()` of a 16-byte address: IPv4-mapped prints as a dotted quad, as in FlowLink.
/// Ported from the Go standard library (`net`), BSD-3-Clause, Copyright (c) 2009 The Go Authors. See NOTICE.
fn ip6_string(b: [u8; 16]) -> String {
    let a = Ipv6Addr::from(b);
    a.to_ipv4_mapped().map_or_else(|| a.to_string(), |v4| v4.to_string())
}

/// Go `IsUnspecified()`: `::` or `::ffff:0.0.0.0`.
fn ip6_unspecified(b: [u8; 16]) -> bool {
    let a = Ipv6Addr::from(b);
    a.is_unspecified() || a.to_ipv4_mapped() == Some(Ipv4Addr::UNSPECIFIED)
}

// ---------------------------------------------------------------------------------------------
// Templates and PendingSet (shared by IPFIX and NetFlow v9, separate store instances)

/// `FieldSpec`; `%v` prints `{id len}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FieldSpec {
    pub id: u16,
    pub len: u16,
}

impl fmt::Display for FieldSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{{} {}}}", self.id, self.len)
    }
}

/// Template store key (`domain` = observation domain or v9 Source ID);
/// `%v` prints `{addr domain id}`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct TemplateKey {
    pub device_addr: String,
    pub domain: u32,
    pub template_id: u16,
}

impl fmt::Display for TemplateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{{} {} {}}}", self.device_addr, self.domain, self.template_id)
    }
}

/// The parts of a Go `time.Time` the parsers use: `Unix()` and `time.Now().Sub(t)`, which
/// uses the monotonic clock only when `t` came from `time.Now()`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Stamp {
    unix: i64,
    wall: SystemTime,
    mono: Option<Instant>,
}

impl Stamp {
    pub fn now() -> Self {
        let wall = SystemTime::now();
        let unix = wall.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
        Self { unix, wall, mono: Some(Instant::now()) }
    }

    pub fn from_unix(secs: u32) -> Self {
        Self { unix: secs.into(), wall: UNIX_EPOCH + Duration::from_secs(secs.into()), mono: None }
    }

    pub fn unix(&self) -> i64 {
        self.unix
    }

    /// `time.Now().Sub(t) <= 120s` (future times always qualify).
    fn fresh(&self) -> bool {
        match self.mono {
            Some(m) => m.elapsed() <= REPLAY_WINDOW,
            None => SystemTime::now().duration_since(self.wall).map_or(true, |age| age <= REPLAY_WINDOW),
        }
    }
}

/// A data set that arrived before its template; `data` holds the set's `data_len` bytes.
#[derive(Debug)]
pub(crate) struct PendingSet {
    key: TemplateKey,
    transport: String,
    seq_no: u32,
    time: Stamp,
    sys_uptime: u32,
    data: Vec<u8>,
}

/// Template map + PendingSet list with their two locks (one store for IPFIX, one for NetFlow v9).
pub(crate) struct TemplateStore {
    templates: Mutex<Templates>,
    stored: Mutex<Stored>,
    /// PendingSet dropped by the `MAX_STORED` cap and templates dropped by the template budget.
    evicted: AtomicU64,
    /// Template budget in `template_cost` bytes (`MAX_TEMPLATE_BYTES`).
    budget: usize,
}

impl Default for TemplateStore {
    fn default() -> Self {
        Self::with_budget(MAX_TEMPLATE_BYTES)
    }
}

/// The template map plus the order of (re)definition, oldest first, for the budget.
#[derive(Default)]
struct Templates {
    map: HashMap<TemplateKey, (Arc<[FieldSpec]>, u64)>,
    order: BTreeMap<u64, TemplateKey>,
    next: u64,
    bytes: usize,
}

/// The PendingSet list plus how many entries wait for each key, so that a template with nothing
/// waiting skips the scan of the whole list (fuzz F2).
#[derive(Default)]
struct Stored {
    list: VecDeque<PendingSet>,
    waiting: HashMap<TemplateKey, usize>,
    /// Sum of `stored_cost` over `list`, for `MAX_STORED_BYTES`.
    bytes: usize,
}

/// Approximate heap bytes of one PendingSet entry: the data, both strings and the struct itself.
fn stored_cost(sd: &PendingSet) -> usize {
    96 + sd.key.device_addr.len() + sd.transport.len() + sd.data.len()
}

/// Approximate heap bytes of one template: the map and order entries with the hash table's
/// slack, both copies of the address, and the fields. Measured in tests/template_store_growth.rs:
/// a store full of empty templates (about 98 000) holds 25 MiB of heap.
fn template_cost(key: &TemplateKey, fields: usize) -> usize {
    320 + 2 * key.device_addr.len() + 4 * fields
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl TemplateStore {
    pub fn with_budget(budget: usize) -> Self {
        Self { templates: Default::default(), stored: Default::default(), evicted: AtomicU64::new(0), budget }
    }

    pub fn get(&self, key: &TemplateKey) -> Option<Arc<[FieldSpec]>> {
        lock(&self.templates).map.get(key).map(|(f, _)| f.clone())
    }

    /// Store (overwrite) a template, log it and replay matching PendingSet. Returns records sent.
    pub fn learn(&self, key: TemplateKey, fields: Vec<FieldSpec>, sink: &FlowSink) -> u16 {
        let fields: Arc<[FieldSpec]> = fields.into();
        self.insert(key.clone(), fields.clone());
        log_line!("Created template for", key);
        // Divergence ("Template replay"): matched entries are taken out under the lock, but decoded (and sent
        // on the blocking flow channel) after it is released. Matched entries are always removed.
        let matched: VecDeque<PendingSet> = {
            let mut stored = lock(&self.stored);
            if stored.waiting.remove(&key).is_none() {
                VecDeque::new()
            } else {
                let (matched, keep): (VecDeque<_>, _) = stored.list.drain(..).partition(|sd| sd.key == key);
                stored.list = keep;
                stored.bytes -= matched.iter().map(stored_cost).sum::<usize>();
                matched
            }
        };
        matched.iter().filter(|sd| sd.time.fresh()).fold(0u16, |n, sd| {
            let mut r = Reader::new(&sd.data);
            let len = sd.data.len() as u16;
            n.wrapping_add(decode_data_set(
                &sd.key.device_addr,
                &sd.transport,
                sd.seq_no,
                sd.time.unix(),
                sd.sys_uptime,
                &fields,
                &mut r,
                len,
                sink,
            ))
        })
    }

    /// Insert or refresh a template as the newest, then drop the oldest while over the budget
    /// (divergence, see MAX_TEMPLATE_BYTES). A template never evicts itself: one is at most 64 KiB, far below the budget.
    fn insert(&self, key: TemplateKey, fields: Arc<[FieldSpec]>) {
        let mut t = lock(&self.templates);
        let (seq, cost) = (t.next, template_cost(&key, fields.len()));
        t.next += 1;
        t.order.insert(seq, key.clone());
        if let Some((old, old_seq)) = t.map.insert(key, (fields, seq)) {
            let old_key = t.order.remove(&old_seq).expect("every template is in the order");
            t.bytes -= template_cost(&old_key, old.len());
        }
        t.bytes += cost;
        while t.bytes > self.budget && t.map.len() > 1 {
            let (_, oldest) = t.order.pop_first().expect("map and order have the same entries");
            let (f, _) = t.map.remove(&oldest).expect("map and order have the same entries");
            t.bytes -= template_cost(&oldest, f.len());
            self.evicted.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Data set without template: log, read `data_len` bytes and buffer them.
    #[allow(clippy::too_many_arguments)]
    pub fn stash(
        &self,
        key: TemplateKey,
        transport: &str,
        seq_no: u32,
        time: Stamp,
        sys_uptime: u32,
        r: &mut Reader,
        data_len: u16,
    ) -> Result<(), ReadError> {
        log_line!("No template for", key, ". Storing data for later processing.");
        let data = r.read(data_len.into())?.to_vec();
        let sd = PendingSet { key, transport: transport.into(), seq_no, time, sys_uptime, data };
        let cost = stored_cost(&sd);
        let mut stored = lock(&self.stored);
        // Divergence: bounded buffer, by count and by bytes, oldest first. One entry (at most 64 KiB)
        // always fits.
        while stored.list.len() >= MAX_STORED || stored.bytes + cost > MAX_STORED_BYTES {
            let Some(old) = stored.list.pop_front() else { break };
            stored.bytes -= stored_cost(&old);
            if let Some(n) = stored.waiting.get_mut(&old.key) {
                *n -= 1;
                if *n == 0 {
                    stored.waiting.remove(&old.key);
                }
            }
            self.evicted.fetch_add(1, Ordering::Relaxed);
        }
        stored.bytes += cost;
        *stored.waiting.entry(sd.key.clone()).or_default() += 1;
        stored.list.push_back(sd);
        Ok(())
    }

    /// Templates known per exporter (all domains), in one pass under the lock: the stats output asks for every
    /// exporter at once, and the parsers need this lock for every data set.
    pub fn templates_by_device(&self) -> HashMap<String, usize> {
        count_by_device(lock(&self.templates).map.keys().map(|k| k.device_addr.as_str()))
    }

    /// PendingSet entries (data sets waiting for their template) per exporter, in one pass under the lock.
    pub fn stored_by_device(&self) -> HashMap<String, usize> {
        count_by_device(lock(&self.stored).list.iter().map(|sd| sd.key.device_addr.as_str()))
    }

    /// PendingSet entries dropped by the `MAX_STORED` cap plus templates dropped by the template
    /// budget, since start.
    pub fn evicted(&self) -> u64 {
        self.evicted.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub fn templates_for(&self, dev: &str) -> usize {
        self.templates_by_device().get(dev).copied().unwrap_or(0)
    }

    #[cfg(test)]
    pub fn stored_len(&self) -> usize {
        lock(&self.stored).list.len()
    }

    #[cfg(test)]
    pub fn stored_for(&self, dev: &str) -> usize {
        self.stored_by_device().get(dev).copied().unwrap_or(0)
    }

    #[cfg(test)]
    pub fn first_seq(&self) -> Option<u32> {
        lock(&self.stored).list.front().map(|sd| sd.seq_no)
    }
}

fn count_by_device<'a>(devices: impl Iterator<Item = &'a str>) -> HashMap<String, usize> {
    let mut out: HashMap<String, usize> = HashMap::new();
    for d in devices {
        match out.get_mut(d) {
            Some(n) => *n += 1,
            None => {
                out.insert(d.to_string(), 1);
            }
        }
    }
    out
}

/// The IPFIX template store (process-wide).
pub(crate) static IPFIX_STORE: LazyLock<TemplateStore> = LazyLock::new(TemplateStore::default);

// ---------------------------------------------------------------------------------------------
// Record decoding

enum FieldError {
    Read(ReadError),
    /// IE 1 with len ∉ {4, ≥8} or IE 3 with len < 4 (FlowLink crashes; see "`IN_BYTES` or `FLOWS` with an odd
    /// width" in docs/differences-from-flowlink.md).
    Malformed,
}

impl From<ReadError> for FieldError {
    fn from(e: ReadError) -> Self {
        Self::Read(e)
    }
}

/// One record being decoded plus its post-NAT state.
#[derive(Default)]
struct Record {
    fd: FlowData,
    /// Which byte-count IE set `fd.octets`: 0 none, 1 octetTotalCount (85),
    /// 2 initiatorOctets (231, Cisco NSEL), 3 octetDeltaCount (1). The highest wins.
    octets_from: u8,
    nat_src: String,
    nat_dst: String,
    nat_ver: u8,
    nat_src_port: u16,
    nat_dst_port: u16,
    /// IE 32, 139 or 176-179 was decoded: type/code come from the record, not the port.
    icmp_fields: bool,
}

impl Record {
    /// Decode one field. Returns extra offset (varlen prefix and payload only).
    fn decode(&mut self, f: FieldSpec, r: &mut Reader, unix_t: i64, sys_uptime: u32) -> Result<u16, FieldError> {
        let l = usize::from(f.len);
        let fd = &mut self.fd;
        let k = &mut fd.key;
        // 4/60 and the port/ICMP IEs skip leading bytes and read the low-order ones, as in FlowLink.
        let skip = |r: &mut Reader, w: usize| {
            if l > w {
                r.seek(l - w)
            }
        };
        match f.id {
            1 => {
                let b = r.read(l)?;
                fd.octets = match l {
                    4 => be32(b, 0).into(),
                    8.. => u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]) as i64,
                    _ => return Err(FieldError::Malformed),
                };
                self.octets_from = 3;
            }
            // Divergence (FlowLink reads IE 1 only): Cisco ASA NSEL sends initiatorOctets,
            // others octetTotalCount, so their flows uploaded 0 bytes. responderOctets (232)
            // is the reverse direction (Phase 5). Any width 1-8 (reduced-size encoding).
            85 | 231 if (1..=8).contains(&f.len) => {
                let b = r.read(l)?;
                let rank = if f.id == 231 { 2 } else { 1 };
                if rank > self.octets_from {
                    fd.octets = b.iter().fold(0u64, |a, &x| a << 8 | u64::from(x)) as i64;
                    self.octets_from = rank;
                }
            }
            3 => {
                let b = r.read(l)?;
                if l < 4 {
                    return Err(FieldError::Malformed);
                }
                fd.flows = be32(b, 0);
            }
            4 => {
                skip(r, 1);
                k.protocol = r.u8()?;
            }
            7 | 180 | 182 => {
                skip(r, 2);
                fd.src_port = r.u16()?;
            }
            8 | 12 => {
                let a: [u8; 4] = r.array()?;
                if a != [0; 4] {
                    k.ip_version = 4;
                    *(if f.id == 8 { &mut k.src_ip } else { &mut k.dst_ip }) = Ipv4Addr::from(a).to_string();
                }
            }
            9 | 29 => k.src_mask = r.u8()?,
            11 | 181 | 183 => {
                skip(r, 2);
                k.dst_port = r.u16()?;
            }
            13 | 30 => k.dst_mask = r.u8()?,
            22 => {
                let v = r.u32()?;
                if sys_uptime != 0 {
                    // Fuzz finding F4: after a signed 8-byte IE 150/152 near i64::MIN this overflowed
                    // (a panic in debug builds, a wrap to ~i64::MAX in release); clamp instead.
                    fd.flow_time = fd.flow_time.saturating_sub(i64::from(sys_uptime.wrapping_sub(v) / 1000));
                }
            }
            27 | 28 => {
                let a: [u8; 16] = r.array()?;
                if !ip6_unspecified(a) {
                    k.ip_version = 6;
                    *(if f.id == 27 { &mut k.src_ip } else { &mut k.dst_ip }) = ip6_string(a);
                }
            }
            32 | 139 => {
                skip(r, 2);
                let v = r.u16()?;
                (k.icmp_type, k.icmp_code) = ((v >> 8) as u8, v as u8);
                self.icmp_fields = true;
            }
            56 => k.src_mac = join_bytes(&r.array::<6>()?, ":", true),
            57 => k.dst_mac = join_bytes(&r.array::<6>()?, ":", true),
            60 => {
                skip(r, 1);
                k.ip_version = r.u8()?;
            }
            61 => fd.direction_ind = r.u8()?,
            150 | 152 => {
                let v = if l == 8 { r.u64().map(|v| v as i64) } else { r.u32().map(i64::from) };
                let v = v?;
                fd.flow_time = if f.id == 152 { v / 1000 } else { v };
            }
            154 | 156 => fd.flow_time = (r.u64()? >> 32) as i64 - NTP_UNIX_OFFSET,
            158 => {
                let v = r.u32()?;
                if fd.flow_time == unix_t {
                    fd.flow_time -= i64::from(v / 1000); // as in FlowLink
                }
            }
            176 | 178 => {
                k.icmp_type = r.u8()?;
                self.icmp_fields = true;
            }
            177 | 179 => {
                k.icmp_code = r.u8()?;
                self.icmp_fields = true;
            }
            225 | 226 => {
                let a: [u8; 4] = r.array()?;
                if a != [0; 4] {
                    *(if f.id == 225 { &mut self.nat_src } else { &mut self.nat_dst }) = Ipv4Addr::from(a).to_string();
                    self.nat_ver = 4;
                }
            }
            227 => self.nat_src_port = r.u16()?,
            228 => self.nat_dst_port = r.u16()?,
            281 | 282 => {
                let a: [u8; 16] = r.array()?;
                if !ip6_unspecified(a) {
                    *(if f.id == 281 { &mut self.nat_src } else { &mut self.nat_dst }) = ip6_string(a);
                    self.nat_ver = 6;
                }
            }
            id => return skip_field(id, f.len, r),
        }
        Ok(0)
    }

    /// Send the record through the flow filter, plus the NAT duplicate as FlowLink does. Returns records sent.
    fn send(self, sink: &FlowSink) -> u16 {
        let Record { mut fd, nat_src, nat_dst, nat_ver, nat_src_port, nat_dst_port, icmp_fields, .. } = self;
        // Divergence: ICMP type/code carried in the destination port (each record, as the NAT
        // duplicate may take a post-NAT port).
        let send = |mut fd: FlowData| {
            if !icmp_fields {
                icmp_from_dst_port(&mut fd.key);
            }
            sink.send(fd);
        };
        if nat_src.is_empty() || nat_dst.is_empty() {
            send(fd);
            return 1;
        }
        send(fd.clone());
        (fd.key.src_ip, fd.key.dst_ip, fd.key.ip_version) = (nat_src, nat_dst, nat_ver);
        if nat_dst_port != 0 {
            fd.key.dst_port = nat_dst_port;
        }
        if nat_src_port != 0 {
            fd.src_port = nat_src_port;
        }
        send(fd);
        2
    }
}

/// Unknown IEs: skip them (or hex-dump in debug), incl. RFC 7011 varlen.
fn skip_field(id: u16, len: u16, r: &mut Reader) -> Result<u16, FieldError> {
    debug_log!("Ignore field specifier:", id);
    let dump = |r: &mut Reader, n: usize, title: &str| -> Result<(), FieldError> {
        if debug() {
            debug_hex(title, r.read(n)?);
        } else {
            r.seek(n);
        }
        Ok(())
    };
    if len != VARLEN {
        if len != 0 {
            dump(r, len.into(), "field_specifier")?;
        }
        return Ok(0);
    }
    let n8 = r.u8()?;
    let (vlen, extra) = if n8 != 255 { (n8.into(), 1u16) } else { (r.u16()?, 3) };
    if vlen > 0 {
        dump(r, vlen.into(), "variable_field:")?;
    }
    Ok(extra.wrapping_add(vlen))
}

/// Where field `f` ends: after its FieldLength bytes, or after the length prefix (one byte, or
/// 255 and a u16) and the value of a variable-length field. `None` when that prefix is cut off.
fn field_end(f: FieldSpec, r: &Reader) -> Option<usize> {
    if f.len != VARLEN {
        return Some(r.pos + usize::from(f.len));
    }
    match r.buf.get(r.pos..)? {
        [255, hi, lo, ..] => Some(r.pos + 3 + usize::from(u16::from_be_bytes([*hi, *lo]))),
        [255, ..] | [] => None,
        [n, ..] => Some(r.pos + 1 + usize::from(*n)),
    }
}

/// Fuzz finding F1: a data set whose Length is below its 4-byte header (`data_len`
/// wraps to ~65 532) or runs past the end of the datagram. Decoded against its template,
/// FlowLink repeats the last partial record ("Not enough data") until `offset` reaches `data_len`:
/// up to ~65 500 records and log lines from one small datagram. Such a set ends the datagram and
/// counts as one decode error; returns true in that case. Without a template the PendingSet read
/// already fails.
pub(crate) fn malformed_data_set(set_id: u16, len: u16, r: &Reader) -> bool {
    if len >= 4 && usize::from(len - 4) <= r.remaining() {
        return false;
    }
    note_decode_error();
    debug_log!("Data set", set_id, "Length", len, "runs past the datagram - abandoning it");
    true
}

/// Decode `data_len` bytes of records. Returns records sent (u16, wraps).
#[allow(clippy::too_many_arguments)]
pub(crate) fn decode_data_set(
    device_addr: &str,
    transport: &str,
    seq_no: u32,
    unix_t: i64,
    sys_uptime: u32,
    fields: &[FieldSpec],
    r: &mut Reader,
    data_len: u16,
    sink: &FlowSink,
) -> u16 {
    // Divergence: a variable-length field counts with its minimum size, the 1-byte prefix (FlowLink
    // counts it as 65535 bytes).
    let template_bytes = fields.iter().fold(0u16, |a, f| a.wrapping_add(if f.len == VARLEN { 1 } else { f.len }));
    debug_log!("template bytes:", template_bytes);
    // Divergence: records of a template with variable-length fields are bounded by their set, and
    // the reader continues at the set end. Other templates keep FlowLink's bookkeeping.
    let set_end = fields.iter().any(|f| f.len == VARLEN).then(|| (r.pos + usize::from(data_len)).min(r.buf.len()));
    let to_set_end = |r: &mut Reader| {
        if let Some(end) = set_end {
            r.seek_to(end);
        }
    };
    let (mut offset, mut count) = (0u16, 0u16);
    while offset < data_len && data_len - offset >= template_bytes {
        let (start_offset, start_pos) = (offset, r.pos);
        let mut rec = Record::default();
        rec.fd.key.device_addr = device_addr.into();
        rec.fd.transport = transport.into();
        rec.fd.seq_id = seq_no.to_string();
        rec.fd.flow_time = unix_t;
        rec.fd.flows = 1;
        rec.fd.direction_ind = 2;
        for &f in fields {
            if let Some(end) = set_end {
                // Divergence: FlowLink treats a variable-length field as longer than the datagram and
                // sends a partial record. Here a field (a variable one with its prefix) past the set end is malformed.
                if field_end(f, r).is_none_or(|e| e > end) {
                    note_decode_error();
                    debug_log!("Field", f, "runs past its data set - abandoning it");
                    to_set_end(r);
                    return count;
                }
            } else if usize::from(f.len) > r.remaining() {
                log_line!("Not enough data: ", f, "remaining:", r.remaining());
                offset = offset.wrapping_add(r.remaining() as u16);
                break; // the partial record is still sent, as in FlowLink
            }
            // A variable-length value is skipped whatever its IE: FlowPilot reads none of them.
            let decoded =
                if f.len == VARLEN { skip_field(f.id, f.len, r) } else { rec.decode(f, r, unix_t, sys_uptime) };
            match decoded {
                Ok(extra) => offset = offset.wrapping_add(extra),
                Err(FieldError::Read(e)) => {
                    check_error(Some(e));
                    to_set_end(r);
                    return count;
                }
                Err(FieldError::Malformed) => {
                    note_decode_error();
                    debug_log!("Malformed field", f, "- abandoning data set");
                    to_set_end(r);
                    return count;
                }
            }
            if f.len != VARLEN {
                offset = offset.wrapping_add(f.len);
            }
        }
        // Divergence: a record that consumed nothing would repeat forever in FlowLink
        // (empty templates, or a set longer than the datagram); stop instead of sending it.
        if offset == start_offset && r.pos == start_pos {
            break;
        }
        count = count.wrapping_add(rec.send(sink));
    }
    if set_end.is_some() {
        to_set_end(r); // skips the padding, and any drift of the reader
        return count;
    }
    let pad = data_len.wrapping_sub(offset); // after a short set this jumps past the datagram end, as in FlowLink
    if pad != 0 {
        r.seek(pad.into());
    }
    count
}

// ---------------------------------------------------------------------------------------------
// IPFIX message parsing

/// The IPFIX header fields the parser uses (Version is dispatched on, Length is unused, as in FlowLink).
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct V10Header {
    pub export_time: u32,
    pub seq: u32,
    pub domain: u32,
}

/// Parse the sets of one IPFIX message. Returns records sent.
pub(crate) fn decode_ipfix_message(dev: &str, transport: &str, hdr: V10Header, r: &mut Reader, sink: &FlowSink) -> u16 {
    let mut count = 0u16;
    if let Err(e) = read_ipfix_sets(dev, transport, hdr, r, sink, &mut count) {
        check_error(Some(e));
    }
    count
}

fn read_ipfix_sets(dev: &str, transport: &str, hdr: V10Header, r: &mut Reader, sink: &FlowSink, count: &mut u16) -> Result<(), ReadError> {
    let t = if hdr.export_time != 0 { Stamp::from_unix(hdr.export_time) } else { Stamp::now() };
    let key = |template_id| TemplateKey { device_addr: dev.into(), domain: hdr.domain, template_id };
    // Divergence ("Sets in the last 32 bytes of an IPFIX message"): FlowLink does not parse a small
    // template or data set at the end of a message. Every set
    // header that fits is read now; fewer than 4 bytes left, or an all-zero set header (padding),
    // end the message quietly.
    while r.remaining() >= 4 {
        let (set_id, len) = r.pair()?;
        if (set_id, len) == (0, 0) {
            break;
        }
        match set_id {
            2 => {
                // Divergence: the set length bounds the templates, and padding after the last one
                // is skipped instead of being read as more templates.
                let end = r.pos() + usize::from(len.saturating_sub(4));
                while end.saturating_sub(r.pos()) >= 4 {
                    let (tid, field_count) = r.pair()?;
                    if tid < 256 {
                        break; // padding
                    }
                    let mut fields = Vec::new();
                    for _ in 0..field_count {
                        let (id, flen) = r.pair()?;
                        if id & 0x8000 != 0 {
                            r.u32()?; // enterprise number, discarded
                        }
                        fields.push(FieldSpec { id, len: flen });
                    }
                    if r.pos() > end {
                        break; // the field list overruns the set: not a template
                    }
                    *count = count.wrapping_add(IPFIX_STORE.learn(key(tid), fields, sink));
                }
                r.seek_to(end);
            }
            3 => {
                log_line!("Ignoring Ipfix SetID", set_id);
                r.seek(len.wrapping_sub(4).into());
            }
            256.. => {
                let data_len = len.wrapping_sub(4); // stored as is, as in FlowLink (F1 with a template)
                match IPFIX_STORE.get(&key(set_id)) {
                    Some(_) if malformed_data_set(set_id, len, r) => return Ok(()),
                    Some(f) => {
                        let n = decode_data_set(dev, transport, hdr.seq, t.unix(), 0, &f, r, data_len, sink);
                        *count = count.wrapping_add(n);
                    }
                    None => IPFIX_STORE.stash(key(set_id), transport, hdr.seq, t, 0, r, data_len)?,
                }
            }
            _ => {
                log_line!("Ignoring invalid Ipfix SetID", set_id);
                r.seek(len.wrapping_sub(4).into());
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Parser

/// The IPFIX parser.
pub struct IpfixParser {
    ctx: ParserContext,
}

/// Per-worker "log once" flags, never reset.
#[derive(Debug)]
pub(crate) struct OnceFlags {
    v9: bool,
    non_v10: bool,
}

impl Default for OnceFlags {
    fn default() -> Self {
        Self { v9: true, non_v10: true }
    }
}

impl IpfixParser {
    #[cfg(test)]
    pub(crate) fn for_test(ctx: ParserContext) -> Self {
        Self { ctx }
    }

    /// Decodes one datagram synchronously (for `parsers::decode_datagram`).
    pub(crate) fn decode_one(ctx: &ParserContext, pd: &ReceivedDatagram) {
        Self { ctx: ctx.clone() }.handle(pd, &mut OnceFlags::default());
    }

    /// Worker loop. Divergence: the loop ends when the channel is closed instead of spinning.
    fn parse(&self, rx: Receiver<ReceivedDatagram>) {
        let mut once = OnceFlags::default();
        for pd in rx.iter() {
            self.handle(&pd, &mut once);
        }
    }

    /// One iteration of the worker loop, counted in the collector stats.
    pub(crate) fn handle(&self, pd: &ReceivedDatagram, once: &mut OnceFlags) {
        take_decode_errors(); // errors before this datagram are not its own
        let (proto, n) = self.decode(pd, once);
        self.ctx.stats.datagram(&pd.device_addr, proto, pd.buf.len(), n.into(), take_decode_errors());
    }

    /// Decode one datagram: the protocol seen (if any) and the records sent (what is metered).
    fn decode(&self, pd: &ReceivedDatagram, once: &mut OnceFlags) -> (Option<Proto>, u16) {
        let mut r = Reader::new(&pd.buf);
        let h: [u8; 16] = match r.array() {
            Ok(h) => h,
            Err(e) => {
                check_error(Some(e));
                return (None, 0);
            }
        };
        let sink = &self.ctx.sink;
        let (proto, n) = match be16(&h, 0) {
            10 => {
                let hdr = V10Header { export_time: be32(&h, 4), seq: be32(&h, 8), domain: be32(&h, 12) };
                (Proto::Ipfix, decode_ipfix_message(&pd.device_addr, &pd.transport, hdr, &mut r, sink))
            }
            9 => {
                if once.v9 {
                    log_line!("Ipfix parser handling misdirected Netflow V9 data from", pd.device_addr);
                }
                once.v9 = false;
                let source_id = match r.u32() {
                    Ok(v) => v,
                    Err(e) => {
                        check_error(Some(e));
                        return (Some(Proto::NetflowV9), 0);
                    }
                };
                let v9 = netflow::V9Header {
                    count: be16(&h, 2),
                    sys_uptime: be32(&h, 4),
                    unix_secs: be32(&h, 8),
                    seq: be32(&h, 12),
                    source_id,
                };
                (Proto::NetflowV9, netflow::decode_v9_packet(&pd.device_addr, &pd.transport, &v9, &mut r, sink))
            }
            _ => {
                if once.non_v10 {
                    log_line!("Ignoring non-version 10 Ipfix data from ", pd.device_addr);
                    once.non_v10 = false;
                }
                note_decode_error();
                return (None, 0);
            }
        };
        self.ctx.meter.mark(n.into());
        (Some(proto), n)
    }
}

impl Parser for IpfixParser {
    fn type_name(&self) -> &'static str {
        "ipfix"
    }

    fn default_port(&self) -> u16 {
        4739
    }

    fn supports_connector(&self, conn_type: &str) -> bool {
        conn_type == "udp"
    }

    fn stats(&self) -> Arc<CollectorStats> {
        self.ctx.stats.clone()
    }

    fn start_workers(self: Arc<Self>, n: usize) -> Sender<ReceivedDatagram> {
        let (tx, rx) = bounded(n.saturating_mul(10));
        for _ in 0..n {
            let (p, rx) = (self.clone(), rx.clone());
            thread::spawn(move || {
                let _guard = ThreadGuard::core("ipfix parser");
                p.parse(rx)
            });
        }
        tx
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::flow::FlowKey;
    use crate::log::take_decode_errors;
    use crate::metrics::Meter;
    use crate::stats::{CollectorStats, Proto};
    use crossbeam_channel::unbounded;

    /// Fluent big-endian byte builder for hand-made packets.
    #[derive(Clone, Default)]
    pub(crate) struct B(pub Vec<u8>);
    impl B {
        pub fn u8(mut self, v: u8) -> Self {
            self.0.push(v);
            self
        }
        pub fn u16(mut self, v: u16) -> Self {
            self.0.extend(v.to_be_bytes());
            self
        }
        pub fn u32(mut self, v: u32) -> Self {
            self.0.extend(v.to_be_bytes());
            self
        }
        pub fn u64(mut self, v: u64) -> Self {
            self.0.extend(v.to_be_bytes());
            self
        }
        pub fn bytes(mut self, v: &[u8]) -> Self {
            self.0.extend_from_slice(v);
            self
        }
    }

    pub(crate) fn sink() -> (FlowSink, Receiver<FlowData>) {
        let (tx, rx) = unbounded();
        (FlowSink::new(tx), rx)
    }

    pub(crate) fn ctx() -> (ParserContext, Receiver<FlowData>) {
        ctx_with(Arc::new(CollectorStats::default()))
    }

    pub(crate) fn ctx_with(stats: Arc<CollectorStats>) -> (ParserContext, Receiver<FlowData>) {
        let (sink, rx) = sink();
        (ParserContext::new(Meter::new(), sink, stats), rx)
    }

    pub(crate) fn pd(dev: &str, buf: Vec<u8>) -> ReceivedDatagram {
        ReceivedDatagram { device_addr: dev.into(), seq_id: String::new(), transport: "udp".into(), buf }
    }

    pub(crate) fn now_secs() -> u32 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32
    }

    /// A set (or v9 FlowSet): header with Length = body + 4.
    pub(crate) fn set(id: u16, body: &[u8]) -> Vec<u8> {
        B::default().u16(id).u16(body.len() as u16 + 4).bytes(body).0
    }

    /// One template record: template id and field count, then (id, len) pairs.
    pub(crate) fn tmpl(tid: u16, fields: &[(u16, u16)]) -> Vec<u8> {
        fields.iter().fold(B::default().u16(tid).u16(fields.len() as u16), |b, &(i, l)| b.u16(i).u16(l)).0
    }

    fn msg(export: u32, seq: u32, domain: u32, sets: &[Vec<u8>]) -> Vec<u8> {
        let body: Vec<u8> = sets.concat();
        B::default().u16(10).u16(16 + body.len() as u16).u32(export).u32(seq).u32(domain).bytes(&body).0
    }

    fn parser() -> (IpfixParser, Receiver<FlowData>) {
        let (ctx, rx) = ctx();
        (IpfixParser { ctx }, rx)
    }

    /// 10 fields, 38-byte records (data set 42 B > 32, template set 48 B > 32: FlowLink's 32-byte cut-off).
    const T1: &[(u16, u16)] =
        &[(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 8), (56, 6), (57, 6), (61, 1), (150, 4)];

    fn t1_record(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        B::default()
            .bytes(&src)
            .bytes(&dst)
            .u16(50000)
            .u16(443)
            .u8(6)
            .u64(1000)
            .bytes(&[0x00, 0x1b, 0x21, 0xaa, 0xbb, 0xcc])
            .bytes(&[0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f])
            .u8(1)
            .u32(1_700_000_000)
            .0
    }

    fn t1_expected(dev: &str, seq: &str, src: &str, dst: &str) -> FlowData {
        FlowData {
            transport: "udp".into(),
            seq_id: seq.into(),
            key: FlowKey {
                device_addr: dev.into(),
                src_ip: src.into(),
                dst_ip: dst.into(),
                dst_port: 443,
                ip_version: 4,
                protocol: 6,
                src_mac: "00:1B:21:AA:BB:CC".into(),
                dst_mac: "0A:0B:0C:0D:0E:0F".into(),
                ..Default::default()
            },
            src_port: 50000,
            flow_time: 1_700_000_000,
            flows: 1,
            octets: 1000,
            direction_ind: 1,
        }
    }

    fn flows(rx: &Receiver<FlowData>) -> Vec<FlowData> {
        rx.try_iter().collect()
    }

    fn fields(f: &[(u16, u16)]) -> Vec<FieldSpec> {
        f.iter().map(|&(id, len)| FieldSpec { id, len }).collect()
    }

    /// Run decode_data_set on `data` with `data_len = data.len()`.
    fn decode(f: &[(u16, u16)], data: &[u8], unix_t: i64, uptime: u32) -> (u16, Vec<FlowData>) {
        let (s, rx) = sink();
        let n = decode_data_set("10.9.9.9", "udp", 5, unix_t, uptime, &fields(f), &mut Reader::new(data), data.len() as u16, &s);
        (n, flows(&rx))
    }

    const V4: &[(u16, u16)] = &[(8, 4), (12, 4)];
    fn v4_pair() -> B {
        B::default().bytes(&[10, 3, 0, 1]).bytes(&[10, 3, 0, 2])
    }

    #[test]
    fn parser_contract() {
        let (p, _rx) = parser();
        assert_eq!((p.type_name(), p.default_port()), ("ipfix", 4739));
        assert!(p.supports_connector("udp") && !p.supports_connector("tcp"));
        let (ctx, _rx) = ctx();
        let props = Properties::from([("foo".to_string(), "1".to_string())]);
        assert!(!setup(&props, &[Info { kind: "tcp".into(), properties: Properties::new() }], ctx));
    }

    #[test]
    fn template_then_data_in_one_message() {
        let (p, rx) = parser();
        let m = msg(1_600_000_000, 7, 1, &[set(2, &tmpl(256, T1)), set(256, &t1_record([10, 1, 0, 1], [10, 1, 0, 2]))]);
        p.handle(&pd("192.0.2.1", m), &mut OnceFlags::default());
        assert_eq!(flows(&rx), vec![t1_expected("192.0.2.1", "7", "10.1.0.1", "10.1.0.2")]);
        assert_eq!(p.ctx.meter.count(), 1);
    }

    #[test]
    fn data_before_template_is_replayed_once() {
        let (p, rx) = parser();
        let dev = "192.0.2.2";
        let now = now_secs();
        let data = msg(now, 3, 9, &[set(300, &t1_record([10, 1, 0, 3], [10, 1, 0, 4]))]);
        p.handle(&pd(dev, data), &mut OnceFlags::default());
        assert!(flows(&rx).is_empty());
        assert_eq!(IPFIX_STORE.stored_for(dev), 1);
        assert_eq!(p.ctx.meter.count(), 0);

        let t = msg(now, 4, 9, &[set(2, &tmpl(300, T1))]);
        p.handle(&pd(dev, t.clone()), &mut OnceFlags::default());
        let mut want = t1_expected(dev, "3", "10.1.0.3", "10.1.0.4");
        want.flow_time = 1_700_000_000;
        assert_eq!(flows(&rx), vec![want]);
        assert_eq!(p.ctx.meter.count(), 1, "replayed records count toward the template message");
        assert_eq!(IPFIX_STORE.stored_for(dev), 0);

        p.handle(&pd(dev, t), &mut OnceFlags::default()); // refresh: nothing left to replay
        assert!(flows(&rx).is_empty());
    }

    #[test]
    fn stale_stored_data_is_dropped() {
        let (p, rx) = parser();
        let dev = "192.0.2.3";
        let old = now_secs() - 300;
        p.handle(&pd(dev, msg(old, 1, 0, &[set(256, &t1_record([10, 1, 0, 5], [10, 1, 0, 6]))])), &mut OnceFlags::default());
        assert_eq!(IPFIX_STORE.stored_for(dev), 1);
        p.handle(&pd(dev, msg(old, 2, 0, &[set(2, &tmpl(256, T1))])), &mut OnceFlags::default());
        assert!(flows(&rx).is_empty());
        assert_eq!(IPFIX_STORE.stored_for(dev), 0, "matched entries are removed even when stale");
    }

    #[test]
    fn small_sets_at_the_end_are_decoded() {
        let (p, rx) = parser();
        // A 16-byte template set and a 12-byte data set: 28 bytes, all within the last 32.
        let dev = "192.0.2.4";
        let m = msg(1_600_000_000, 1, 0, &[set(2, &tmpl(256, V4)), set(256, &v4_pair().0)]);
        take_decode_errors();
        let (_, n) = p.decode(&pd(dev, m), &mut OnceFlags::default());
        let got = flows(&rx);
        assert_eq!((n, got.len(), take_decode_errors()), (1, 1, 0));
        assert_eq!((got[0].key.src_ip.as_str(), got[0].key.dst_ip.as_str()), ("10.3.0.1", "10.3.0.2"));
        // A 28-byte data set without its template is stored.
        let dev = "192.0.2.14";
        p.handle(&pd(dev, msg(now_secs(), 1, 0, &[set(256, &[1u8; 24])])), &mut OnceFlags::default());
        assert!(flows(&rx).is_empty());
        assert_eq!(IPFIX_STORE.stored_for(dev), 1);
    }

    #[test]
    fn short_or_zero_tail_ends_the_message_quietly() {
        let (p, rx) = parser();
        let good = msg(1_600_000_000, 1, 0, &[set(2, &tmpl(256, V4)), set(256, &v4_pair().0)]);
        let after = set(256, &v4_pair().0);
        // 1-3 bytes left, zero padding, and a zero set header before another set.
        let tails = [vec![0xaa], vec![0xaa; 3], vec![0; 4], vec![0; 7], [vec![0; 4], after].concat()];
        for (i, tail) in tails.into_iter().enumerate() {
            let dev = format!("192.0.2.{}", 60 + i);
            take_decode_errors();
            let (_, n) = p.decode(&pd(&dev, [&good[..], &tail].concat()), &mut OnceFlags::default());
            assert_eq!((n, flows(&rx).len(), take_decode_errors()), (1, 1, 0), "tail {tail:?}");
        }
    }

    #[test]
    fn options_template_and_enterprise_fields_are_skipped() {
        let (p, rx) = parser();
        let dev = "192.0.2.5";
        let opts = set(3, &[0xee; 20]);
        // Enterprise IE 0x8001 (len 4) carries a 4-byte enterprise number in the template.
        let t = B::default().u16(256).u16(3).u16(8).u16(4).u16(0x8001).u16(4).u32(9).u16(12).u16(4).0;
        let tset = B::default().u16(2).u16(4 + t.len() as u16).bytes(&t).0;
        let rec = B::default().bytes(&[10, 1, 0, 7]).u32(0xdead_beef).bytes(&[10, 1, 0, 8]).0;
        let data = set(256, &[rec.clone(), rec.clone(), rec].concat()); // 40 B > 32
        p.handle(&pd(dev, msg(1_600_000_000, 5, 0, &[opts, tset, data])), &mut OnceFlags::default());
        let got = flows(&rx);
        assert_eq!(got.len(), 3);
        assert_eq!((got[0].key.src_ip.as_str(), got[0].key.dst_ip.as_str()), ("10.1.0.7", "10.1.0.8"));
        assert_eq!(got[0].direction_ind, 2); // no ports: direction stays "unknown"
        assert_eq!(got[0].flow_time, 1_600_000_000);
    }

    #[test]
    fn template_set_padding_is_skipped() {
        let (p, rx) = parser();
        for (i, pad) in [2usize, 4].into_iter().enumerate() {
            let dev = format!("192.0.2.{}", 40 + i);
            let tset = set(2, &[tmpl(256, T1), vec![0; pad]].concat());
            let data = set(256, &t1_record([10, 1, 0, 9], [10, 1, 0, 10]));
            p.handle(&pd(&dev, msg(1_600_000_000, 7, 1, &[tset, data])), &mut OnceFlags::default());
            assert_eq!(flows(&rx), vec![t1_expected(&dev, "7", "10.1.0.9", "10.1.0.10")], "{pad} padding bytes");
        }
    }

    #[test]
    fn template_overrunning_its_set_is_not_learned() {
        let (p, rx) = parser();
        let dev = "192.0.2.42";
        // The set length covers only the template header, not its field list.
        let t = tmpl(256, T1);
        let tset = B::default().u16(2).u16(8).bytes(&t).0;
        let data = set(256, &t1_record([10, 1, 0, 11], [10, 1, 0, 12]));
        p.handle(&pd(dev, msg(1_600_000_000, 1, 1, &[tset, data])), &mut OnceFlags::default());
        assert!(flows(&rx).is_empty());
    }

    #[test]
    fn nsel_and_total_octets_when_delta_is_absent() {
        let f = [V4[0], V4[1], (231, 4), (232, 4)];
        let (_, got) = decode(&f, &v4_pair().u32(81).u32(763).0, 100, 0);
        assert_eq!(got[0].octets, 81, "initiatorOctets (NSEL); responderOctets waits for Phase 5");
        let (_, got) = decode(&[V4[0], V4[1], (85, 8)], &v4_pair().u64(12_345).0, 100, 0);
        assert_eq!(got[0].octets, 12_345, "octetTotalCount");
        let (_, got) = decode(&[V4[0], V4[1], (231, 2)], &v4_pair().u16(300).0, 100, 0);
        assert_eq!(got[0].octets, 300, "reduced-size encoding");
        let (_, got) = decode(&[V4[0], V4[1], (85, 8), (231, 4)], &v4_pair().u64(5).u32(6).0, 100, 0);
        assert_eq!(got[0].octets, 6, "initiatorOctets beats octetTotalCount");
    }

    #[test]
    fn octet_delta_count_wins_over_other_byte_fields() {
        let f = [V4[0], V4[1], (231, 4), (1, 8), (85, 8)];
        let (_, got) = decode(&f, &v4_pair().u32(7).u64(1000).u64(9).0, 100, 0);
        assert_eq!(got[0].octets, 1000);
    }

    #[test]
    fn ipv6_icmp_and_macs() {
        let f = [(27, 16), (28, 16), (4, 1), (176, 1), (177, 1), (56, 6)];
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "::ffff:10.0.0.9".parse().unwrap();
        let d = B::default().bytes(&src.octets()).bytes(&dst.octets()).u8(58).u8(128).u8(0).bytes(&[1, 2, 3, 4, 5, 0xfe]).0;
        let (n, got) = decode(&f, &d, 100, 0);
        assert_eq!(n, 1);
        let k = &got[0].key;
        assert_eq!((k.src_ip.as_str(), k.dst_ip.as_str(), k.ip_version), ("2001:db8::1", "10.0.0.9", 6));
        assert_eq!((k.protocol, k.icmp_type, k.icmp_code), (58, 128, 0));
        assert_eq!(k.src_mac, "01:02:03:04:05:FE");
    }

    #[test]
    fn icmp_type_code_ie32_and_wide_ports() {
        let f = [(8, 4), (12, 4), (4, 1), (32, 4), (7, 4)];
        let d = v4_pair().u8(1).u32(0x0000_0303).u32(0x0001_0050).0;
        let (_, got) = decode(&f, &d, 100, 0);
        assert_eq!((got[0].key.icmp_type, got[0].key.icmp_code), (3, 3));
        assert_eq!(got[0].src_port, 0x50, "wide port fields skip the leading bytes");
    }

    #[test]
    fn icmp_type_code_from_the_destination_port() {
        let f = [(8, 4), (12, 4), (4, 1), (7, 2), (11, 2)];
        let rec = |proto: u8, sport: u16, dport: u16| v4_pair().u8(proto).u16(sport).u16(dport).0;
        // type*256+code (nProbe, softflowd); a bare type below 256 (Cisco IPFIX, Procera);
        // TCP and an ICMP record without a port are untouched.
        let d = [rec(58, 0, 0x8000), rec(1, 0, 0x0303), rec(58, 136, 135), rec(1, 0, 8), rec(6, 50000, 443), rec(1, 0, 0)]
            .concat();
        let (n, got) = decode(&f, &d, 100, 0);
        assert_eq!((n, got.len()), (6, 6), "none is dropped as ICMP with a port");
        let k: Vec<_> = got.iter().map(|g| (g.key.protocol, g.key.icmp_type, g.key.icmp_code, g.key.dst_port, g.src_port)).collect();
        assert_eq!(k, [(58, 128, 0, 0, 0), (1, 3, 3, 0, 0), (58, 135, 0, 0, 136), (1, 8, 0, 0, 0), (6, 0, 0, 443, 50000), (1, 0, 0, 0, 0)]);
    }

    #[test]
    fn icmp_fields_keep_the_destination_port() {
        // A record that carries type/code (IE 32, or 176/177 as Cisco ASA does) keeps the values
        // and the port, so it is still dropped as ICMP with a port.
        for (ie, len) in [(32, 2), (139, 2), (176, 1), (177, 1), (178, 1), (179, 1)] {
            let f = [(8, 4), (12, 4), (4, 1), (11, 2), (ie, len)];
            let d = v4_pair().u8(1).u16(0x448d).bytes(&vec![0; len.into()]).0;
            let (n, got) = decode(&f, &d, 100, 0);
            assert_eq!((n, got.len()), (1, 0), "IE {ie}");
        }
        let f = [(8, 4), (12, 4), (4, 1), (11, 2), (32, 2)];
        let (_, got) = decode(&f, &v4_pair().u8(1).u16(0).u16(0x0b00).0, 100, 0);
        assert_eq!((got[0].key.icmp_type, got[0].key.icmp_code, got[0].key.dst_port), (11, 0, 0));
    }

    #[test]
    fn icmp_in_the_nat_duplicate() {
        let f = [(8, 4), (12, 4), (4, 1), (11, 2), (225, 4), (226, 4), (228, 2)];
        let d = v4_pair().u8(1).u16(0x0800).bytes(&[192, 0, 2, 10]).bytes(&[198, 51, 100, 7]).u16(0x0000).0;
        let (n, got) = decode(&f, &d, 100, 0);
        assert_eq!((n, got.len()), (2, 2));
        for g in &got {
            assert_eq!((g.key.icmp_type, g.key.icmp_code, g.key.dst_port), (8, 0, 0));
        }
    }

    #[test]
    fn unspecified_addresses_leave_ip_empty() {
        let f = [(8, 4), (27, 16)];
        let mapped_zero: Ipv6Addr = "::ffff:0.0.0.0".parse().unwrap();
        let d = B::default().u32(0).bytes(&mapped_zero.octets()).0;
        let (n, got) = decode(&f, &d, 100, 0);
        assert_eq!((n, got.len()), (1, 0), "record counted, then discarded as empty by the sink");
    }

    #[test]
    fn flow_start_variants() {
        let t = |f: (u16, u16), v: B| decode(&[V4[0], V4[1], f], &[v4_pair().0, v.0].concat(), 1000, 10_000).1[0].flow_time;
        assert_eq!(t((150, 4), B::default().u32(1_700_000_001)), 1_700_000_001);
        assert_eq!(t((150, 8), B::default().u64(1_700_000_002)), 1_700_000_002);
        assert_eq!(t((152, 8), B::default().u64(1_700_000_123_456)), 1_700_000_123);
        assert_eq!(t((152, 4), B::default().u32(4_000_000)), 4000);
        assert_eq!(t((154, 8), B::default().u64((1_700_000_000u64 + 2_208_988_800) << 32 | 0xffff)), 1_700_000_000);
        assert_eq!(t((156, 8), B::default().u64((1_600_000_000u64 + 2_208_988_800) << 32)), 1_600_000_000);
        assert_eq!(t((158, 4), B::default().u32(5_000_000)), 1000 - 5000, "µs/1000 subtracted from seconds");
        assert_eq!(t((22, 4), B::default().u32(4_000)), 1000 - 6, "FIRST_SWITCHED with sysUptime 10000");
        // 158 only applies while the flow time is still the base time.
        let f = [V4[0], V4[1], (150, 4), (158, 4)];
        let d = v4_pair().u32(50_000).u32(5_000_000).0;
        assert_eq!(decode(&f, &d, 1000, 0).1[0].flow_time, 50_000);
        // FIRST_SWITCHED ignored without sysUptime (IPFIX).
        let d = v4_pair().u32(4_000).0;
        assert_eq!(decode(&[V4[0], V4[1], (22, 4)], &d, 1000, 0).1[0].flow_time, 1000);
        // F4: a signed 8-byte flowStart near i64::MIN, then FIRST_SWITCHED, stops at i64::MIN.
        let f = [V4[0], V4[1], (150, 8), (22, 4)];
        let d = v4_pair().u64(1 << 63).u32(5_000).0;
        assert_eq!(decode(&f, &d, 1000, 10_000).1[0].flow_time, i64::MIN);
    }

    #[test]
    fn nat_duplicate_record() {
        let f = [(8, 4), (12, 4), (7, 2), (11, 2), (1, 4), (225, 4), (226, 4), (227, 2), (228, 2)];
        let d = v4_pair().u16(50000).u16(80).u32(77).bytes(&[192, 0, 2, 10]).bytes(&[198, 51, 100, 7]).u16(0).u16(8080).0;
        let (n, got) = decode(&f, &d, 100, 0);
        assert_eq!(n, 2);
        assert_eq!((got[0].key.src_ip.as_str(), got[0].key.dst_port), ("10.3.0.1", 80));
        let nat = &got[1];
        assert_eq!((nat.key.src_ip.as_str(), nat.key.dst_ip.as_str()), ("192.0.2.10", "198.51.100.7"));
        assert_eq!((nat.src_port, nat.key.dst_port, nat.octets), (50000, 8080, 77));
        // Only a post-NAT source: no duplicate.
        let (n, _) = decode(&f[..6], &v4_pair().u16(1).u16(2).u32(3).bytes(&[192, 0, 2, 10]).0, 100, 0);
        assert_eq!(n, 1);
    }

    #[test]
    fn octets_and_flows_widths() {
        let f = [V4[0], V4[1], (1, 4), (3, 8)];
        let d = v4_pair().u32(1234).u64(0x0000_0002_0000_0001).0;
        let got = decode(&f, &d, 0, 0).1;
        assert_eq!((got[0].octets, got[0].flows), (1234, 2), "FLOWS len 8 takes the high word");
        let f = [V4[0], V4[1], (1, 12)];
        let d = v4_pair().u64(99).u32(0xffff_ffff).0;
        assert_eq!(decode(&f, &d, 0, 0).1[0].octets, 99);
    }

    #[test]
    fn short_octets_or_flows_do_not_panic() {
        for l in [0u16, 1, 2, 3, 5, 6, 7] {
            let d = [v4_pair().0, vec![0u8; l as usize]].concat();
            assert_eq!(decode(&[V4[0], V4[1], (1, l)], &d, 0, 0), (0, vec![]), "IE 1 len {l}");
        }
        for l in [0u16, 1, 2, 3] {
            let d = [v4_pair().0, vec![0u8; l as usize]].concat();
            assert_eq!(decode(&[V4[0], V4[1], (3, l)], &d, 0, 0), (0, vec![]), "IE 3 len {l}");
        }
    }

    #[test]
    fn zero_byte_templates_terminate() {
        assert_eq!(decode(&[], &[0u8; 10], 0, 0), (0, vec![]));
        assert_eq!(decode(&[(2, 0), (300, 0)], &[0u8; 10], 0, 0), (0, vec![]));
    }

    #[test]
    fn not_enough_data_sends_partial_record_once() {
        let (s, rx) = sink();
        let data = v4_pair().u16(7).0; // 10 bytes but the set claims 16
        let mut r = Reader::new(&data);
        let n = decode_data_set("10.9.9.9", "udp", 1, 5, 0, &fields(&[(8, 4), (12, 4), (1, 8)]), &mut r, 16, &s);
        assert_eq!(n, 1);
        let got = flows(&rx);
        assert_eq!((got.len(), got[0].octets, got[0].key.dst_ip.as_str()), (1, 0, "10.3.0.2"));
    }

    #[test]
    fn set_padding_is_skipped() {
        let (s, _rx) = sink();
        let data = [v4_pair().0, vec![0, 0, 0], vec![0xaa]].concat();
        let mut r = Reader::new(&data);
        assert_eq!(decode_data_set("10.9.9.9", "udp", 1, 5, 0, &fields(V4), &mut r, 11, &s), 1);
        assert_eq!(r.remaining(), 1);
    }

    /// A variable-length value with its length prefix: one byte below 255, else 255 and a u16.
    fn var(v: &[u8]) -> Vec<u8> {
        match u8::try_from(v.len()) {
            Ok(n) if n < 255 => [&[n][..], v].concat(),
            _ => B::default().u8(255).u16(v.len() as u16).bytes(v).0,
        }
    }

    /// Source and destination address and source port of a decoded record.
    fn addrs_port(f: &FlowData) -> (&str, &str, u16) {
        (f.key.src_ip.as_str(), f.key.dst_ip.as_str(), f.src_port)
    }

    #[test]
    fn variable_length_field_is_skipped() {
        // Empty, short, 254/255 bytes, long, and a short value in the 3-byte form.
        let long_form = B::default().u8(255).u16(3).bytes(b"abc").0;
        let values = [var(&[]), var(b"abc"), var(&[0x5a; 254]), var(&[0x5a; 255]), var(&[0x5a; 300]), long_form];
        let (a, port) = (v4_pair().0, B::default().u16(80).0);
        for v in values {
            // first, middle and last field
            for (f, d) in [
                ([(100, VARLEN), V4[0], V4[1], (7, 2)], [&v[..], &a, &port].concat()),
                ([V4[0], V4[1], (100, VARLEN), (7, 2)], [&a[..], &v, &port].concat()),
                ([V4[0], V4[1], (7, 2), (100, VARLEN)], [&a[..], &port, &v].concat()),
            ] {
                take_decode_errors();
                let (n, got) = decode(&f, &d, 0, 0);
                assert_eq!((n, got.len(), take_decode_errors()), (1, 1, 0), "{f:?}, {} bytes", v.len());
                assert_eq!(addrs_port(&got[0]), ("10.3.0.1", "10.3.0.2", 80), "{f:?}, {} bytes", v.len());
            }
        }
        // A known IE sent as variable-length is skipped too: the record keeps the template's other fields.
        let (n, got) = decode(&[V4[0], V4[1], (7, VARLEN)], &[a, var(&[0, 80])].concat(), 0, 0);
        assert_eq!((n, addrs_port(&got[0])), (1, ("10.3.0.1", "10.3.0.2", 0)));
    }

    /// Records of [8, 12, varlen, 7] (minimum 11 bytes).
    const VT: &[(u16, u16)] = &[(8, 4), (12, 4), (100, VARLEN), (7, 2)];

    fn vt_record(a: u8, v: &[u8], port: u16) -> Vec<u8> {
        B::default().bytes(&[10, 3, 0, a]).bytes(&[10, 3, 0, 2]).bytes(&var(v)).u16(port).0
    }

    #[test]
    fn records_with_variable_fields_share_a_set_and_its_padding_is_skipped() {
        // Two records, 3 padding bytes (less than the 11-byte minimum), then the next set.
        let data = [vt_record(1, b"abcdef", 80), vt_record(5, &[7; 400], 81), vec![0; 3], vec![0xaa]].concat();
        let (s, rx) = sink();
        let mut r = Reader::new(&data);
        take_decode_errors();
        let n = decode_data_set("10.9.9.9", "udp", 1, 5, 0, &fields(VT), &mut r, data.len() as u16 - 1, &s);
        let got = flows(&rx);
        assert_eq!((n, got.len(), take_decode_errors()), (2, 2, 0));
        assert_eq!(addrs_port(&got[0]), ("10.3.0.1", "10.3.0.2", 80));
        assert_eq!(addrs_port(&got[1]), ("10.3.0.5", "10.3.0.2", 81));
        assert_eq!(r.remaining(), 1, "the reader ends at the set boundary");
    }

    #[test]
    fn variable_length_past_the_set_end_abandons_the_set() {
        let f = [V4[0], V4[1], (100, VARLEN)];
        let good = [v4_pair().0, var(b"ab")].concat();
        // The value runs past the set end (1- and 3-byte prefix); the 3-byte prefix is cut off.
        for bad in [vec![5, 1, 2], vec![255, 0, 9, 1], vec![255, 0], vec![255]] {
            let data = [&good[..], &v4_pair().0, &bad, &[0xaa; 9]].concat();
            let (s, rx) = sink();
            let mut r = Reader::new(&data);
            take_decode_errors();
            let n = decode_data_set("10.9.9.9", "udp", 1, 5, 0, &fields(&f), &mut r, data.len() as u16 - 9, &s);
            assert_eq!((n, flows(&rx).len(), take_decode_errors()), (1, 1, 1), "{bad:?}");
            assert_eq!(r.remaining(), 9, "{bad:?}: the reader ends at the set boundary");
        }
    }

    #[test]
    fn sets_after_variable_length_records_are_decoded() {
        let (p, rx) = parser();
        let dev = "198.51.100.50";
        let tmpls = set(2, &[tmpl(256, T1), tmpl(257, VT)].concat());
        let t1 = set(256, &t1_record([10, 1, 0, 1], [10, 1, 0, 2]));
        let ok = set(257, &[vt_record(1, b"x", 80), vt_record(2, &[1; 300], 81)].concat());
        let bad = set(257, &[vt_record(3, b"y", 82), v4_pair().u8(200).u16(1).0].concat()); // 11 bytes: not padding
        let m = msg(1_600_000_000, 7, 1, &[tmpls, ok, bad, t1]);
        take_decode_errors();
        let (_, n) = p.decode(&pd(dev, m), &mut OnceFlags::default());
        let got = flows(&rx);
        assert_eq!((n, got.len(), take_decode_errors()), (4, 4, 1));
        let ports: Vec<u16> = got.iter().map(|f| f.src_port).collect();
        assert_eq!(ports, [80, 81, 82, 50000], "the bad set's first record is kept, the set after it decoded");
    }

    #[test]
    fn stored_data_is_capped() {
        let store = TemplateStore::default();
        let key = TemplateKey { device_addr: "x".into(), domain: 0, template_id: 256 };
        for seq in 0..(MAX_STORED as u32 + 5) {
            store.stash(key.clone(), "udp", seq, Stamp::from_unix(1), 0, &mut Reader::new(&[1, 2]), 2).unwrap();
        }
        assert_eq!(store.stored_len(), MAX_STORED);
        assert_eq!(store.first_seq(), Some(5), "oldest entries are dropped first");
        assert_eq!(store.evicted(), 5);
    }

    #[test]
    fn stored_data_bytes_are_capped() {
        let (s, _rx) = sink();
        let store = TemplateStore::default();
        let key = |template_id| TemplateKey { device_addr: "z".into(), domain: 0, template_id };
        let big = vec![0u8; 65_535];
        let n = MAX_STORED_BYTES / big.len() + 10;
        for seq in 0..n as u32 {
            store.stash(key(256), "udp", seq, Stamp::from_unix(1), 0, &mut Reader::new(&big), 65_535).unwrap();
        }
        let held = store.stored_len();
        assert!(held < n && held * big.len() <= MAX_STORED_BYTES, "{held} sets of 64 KiB held");
        assert_eq!(store.evicted(), (n - held) as u64);
        assert_eq!(store.first_seq(), Some((n - held) as u32), "oldest entries are dropped first");
        store.learn(key(256), fields(&[]), &s);
        assert_eq!((store.stored_len(), lock(&store.stored).bytes), (0, 0), "replayed entries give their bytes back");
    }

    #[test]
    fn waiting_counts_follow_the_stored_list_f2() {
        let (s, _rx) = sink();
        let store = TemplateStore::default();
        let key = |template_id| TemplateKey { device_addr: "y".into(), domain: 0, template_id };
        let stash = |t| store.stash(key(t), "udp", 0, Stamp::now(), 0, &mut Reader::new(&[1, 2]), 2).unwrap();
        stash(256);
        (0..MAX_STORED).for_each(|_| stash(257)); // the cap pushes 256 out
        store.learn(key(256), fields(&[]), &s);
        assert_eq!(store.stored_len(), MAX_STORED);
        stash(258); // and one of 257
        store.learn(key(257), fields(&[]), &s);
        assert_eq!(store.stored_len(), 1);
        store.learn(key(258), fields(&[]), &s);
        assert_eq!(store.stored_len(), 0);
        assert!(lock(&store.stored).waiting.is_empty());
    }

    #[test]
    fn templates_counted_per_exporter() {
        let (s, _rx) = sink();
        let store = TemplateStore::default();
        let key = |dev: &str, template_id| TemplateKey { device_addr: dev.into(), domain: 0, template_id };
        store.learn(key("a", 256), fields(V4), &s);
        store.learn(key("a", 257), fields(V4), &s);
        store.learn(key("a", 257), fields(V4), &s); // overwritten, not added
        store.learn(key("b", 256), fields(V4), &s);
        assert_eq!((store.templates_for("a"), store.templates_for("b"), store.templates_for("c")), (2, 1, 0));
    }

    #[test]
    fn template_budget_drops_the_oldest_definition() {
        let (s, _rx) = sink();
        let key = |dev: &str| TemplateKey { device_addr: dev.into(), domain: 0, template_id: 256 };
        let store = TemplateStore::with_budget(3 * template_cost(&key("a"), V4.len()));
        for dev in ["a", "b", "c", "a"] {
            store.learn(key(dev), fields(V4), &s); // "a" again: a refresh makes it the newest
        }
        assert_eq!(store.evicted(), 0);
        store.learn(key("d"), fields(V4), &s);
        assert_eq!(store.evicted(), 1);
        let known: Vec<bool> = ["a", "b", "c", "d"].iter().map(|d| store.get(&key(d)).is_some()).collect();
        assert_eq!(known, [true, false, true, true]);
        // A template bigger than the whole budget is still kept (alone).
        store.learn(key("e"), fields(&[(2, 4); 200]), &s);
        assert!(store.get(&key("e")).is_some());
        assert_eq!((store.evicted(), store.templates_for("d")), (4, 0));
    }

    #[test]
    fn template_budget_fits_a_large_deployment() {
        let store = TemplateStore::default();
        let wide: Arc<[FieldSpec]> = (0..100).map(|i| FieldSpec { id: 100 + i, len: 4 }).collect();
        for e in 0..1000u32 {
            for t in 0..20 {
                let key = TemplateKey { device_addr: format!("2001:db8::{e:x}"), domain: e, template_id: 256 + t };
                store.insert(key, wide.clone());
            }
        }
        assert_eq!((store.evicted(), store.templates_for("2001:db8::3e7")), (0, 20));
    }

    #[test]
    fn malformed_field_is_a_decode_error() {
        let (s, _rx) = sink();
        take_decode_errors();
        let mut r = Reader::new(&[0; 8]);
        decode_data_set("10.9.9.8", "udp", 1, 5, 0, &fields(&[(1, 2)]), &mut r, 8, &s);
        assert_eq!(take_decode_errors(), 1);
    }

    #[test]
    fn data_set_running_past_the_datagram_ends_it_f1() {
        let (p, rx) = parser();
        for (i, len) in [0u16, 3, 200].into_iter().enumerate() {
            let dev = format!("198.51.100.4{i}");
            let good = [set(2, &tmpl(256, T1)), set(256, &t1_record([10, 1, 0, 1], [10, 1, 0, 2]))];
            // Length < 4 wraps data_len; 200 is past the end.
            let m = [msg(1_600_000_000, 7, 1, &good), B::default().u16(256).u16(len).bytes(&[0x20; 40]).0].concat();
            take_decode_errors();
            let (_, n) = p.decode(&pd(&dev, m), &mut OnceFlags::default());
            assert_eq!((n, flows(&rx).len(), take_decode_errors()), (1, 1, 1), "Length {len}");
        }
    }

    #[test]
    fn stats_per_datagram_on_ipfix_port() {
        let stats = Arc::new(CollectorStats::new("ipfix-stats", "ipfix"));
        let (ctx, _rx) = ctx_with(stats.clone());
        let p = IpfixParser::for_test(ctx);
        let dev = "198.51.100.40";
        let m = msg(0, 7, 0, &[set(2, &tmpl(300, T1)), set(300, &t1_record([10, 9, 0, 1], [10, 9, 0, 2]))]);
        p.handle(&pd(dev, m), &mut OnceFlags::default());
        p.handle(&pd(dev, vec![0, 9, 0, 0]), &mut OnceFlags::default()); // short header
        p.handle(&pd(dev, [vec![0, 7], vec![0; 14]].concat()), &mut OnceFlags::default()); // not v9/v10
        let row = stats.exporters(SystemTime::now()).remove(0);
        assert_eq!(row.protocols, [Proto::Ipfix]);
        assert_eq!((row.datagrams, row.flows, row.decode_errors), (3, 1, 2));
        assert_eq!(p.stats().counters().forwarded, 1);
    }

    #[test]
    fn reader_mimics_bytes_reader() {
        let mut r = Reader::new(&[1, 2, 3]);
        assert_eq!(r.read(2).unwrap(), &[1, 2]);
        assert_eq!(r.read(2).unwrap_err().to_string(), "unexpected EOF");
        assert_eq!(r.remaining(), 0);
        assert_eq!(r.read(1).unwrap_err().to_string(), "EOF");
        r.seek(100);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn malformed_and_truncated_input_never_panics() {
        let (p, _rx) = parser();
        let m = msg(1_600_000_000, 7, 1, &[set(2, &tmpl(256, T1)), set(256, &t1_record([10, 1, 0, 1], [10, 1, 0, 2]))]);
        for n in 0..=m.len() {
            p.handle(&pd("198.18.0.1", m[..n].to_vec()), &mut OnceFlags::default());
        }
        // Deterministic garbage with valid-looking headers (LCG).
        let mut x: u64 = 0x2545_f491_4f6c_dd1d;
        let mut next = || {
            x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            (x >> 33) as u8
        };
        for i in 0..3000 {
            let len = next() as usize;
            let mut b: Vec<u8> = (0..len).map(|_| next()).collect();
            if b.len() >= 22 {
                b[0..2].copy_from_slice(&[0, if i % 2 == 0 { 10 } else { 9 }]);
                b[16..18].copy_from_slice(&[0, [2u8, 3, 1, 0][i % 4]]);
            }
            p.handle(&pd("198.18.0.2", b), &mut OnceFlags::default());
        }
    }
}
