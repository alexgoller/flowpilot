//! Generic text/syslog-style flow parser (docs/collectors.md).
//!
//! Each datagram is split into lines, each line into fields and each field optionally into
//! `key<attr_sep>value`. The keymap aliases select which field supplies each flow attribute.
//! Timestamps are parsed with a port of Go's `time.ParseInLocation` restricted to the layout
//! tokens `compile_timestamp_format` can produce (the `timestamp_format` tokens in docs/collectors.md).
//! That port, and the other functions marked so below, come from the Go standard library
//! (BSD-3-Clause, Copyright (c) 2009 The Go Authors; see NOTICE).

use std::sync::Arc;
use std::thread;

use chrono::{DateTime, Local, NaiveDate, Offset, TimeZone};
use crossbeam_channel::Sender;

use crate::config::{Info, Properties};
use crate::flow::{parse_ip, FlowData, FlowKey, FlowSink};
use crate::metrics::Meter;
use crate::parsers::{connect_all, Parser, ParserContext, ReceivedDatagram};
use crate::stats::{CollectorStats, Proto, ThreadGuard};
use crate::{debug_log, log, log_line};

/// Unix seconds of Go's zero `time.Time` (year 1, Jan 1, 00:00:00 UTC).
const ZERO_UNIX: i64 = -62_135_596_800;
const REQUIRED: [&str; 4] = ["src_ip", "dst_ip", "dst_port", "protocol"];

/// Keymap attributes. The declaration order is the fixed processing order used by the parser
/// (divergence: FlowLink processes them in random order).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Attr {
    Protocol,
    SrcIp,
    DstIp,
    DstPort,
    IcmpType,
    IcmpCode,
    Octets,
    SrcMac,
    DstMac,
    Timestamp,
}

impl Attr {
    fn from_key(k: &str) -> Option<Self> {
        Some(match k {
            "protocol" => Self::Protocol,
            "src_ip" => Self::SrcIp,
            "dst_ip" => Self::DstIp,
            "dst_port" => Self::DstPort,
            "icmp_type" => Self::IcmpType,
            "icmp_code" => Self::IcmpCode,
            "octets" => Self::Octets,
            "src_mac" => Self::SrcMac,
            "dst_mac" => Self::DstMac,
            "timestamp" => Self::Timestamp,
            _ => return None,
        })
    }
}

/// A timestamp format. The location is always Local, so it is not stored.
#[derive(Clone, Debug, PartialEq)]
pub struct DateTimeInfo {
    pub format: String,
    pub element_count: usize,
    pub go_format: String,
}

impl Default for DateTimeInfo {
    /// FlowLink's default timestamp format.
    fn default() -> Self {
        Self {
            format: "yyyy-mm-ddTHH:MM:SS-HH:MM".into(),
            element_count: 1,
            go_format: "2006-01-02T15:04:05-07:00".into(),
        }
    }
}

/// The configuration part of the text parser.
#[derive(Clone, Debug, PartialEq)]
pub struct TextConfig {
    pub field_sep: String,
    pub attr_sep: String,
    /// Configured attributes with their aliases, in `Attr` order.
    pub keymap: Vec<(Attr, Vec<String>)>,
    pub only_recs: Vec<Vec<String>>,
    pub dt: DateTimeInfo,
}

/// Why `configure` failed: `Invalid` makes setup return false, `Exit` logs every line and exits 1.
#[derive(Debug, PartialEq)]
pub enum SetupError {
    Invalid(String),
    Exit(Vec<String>),
}

/// Sets up the text parser and its connectors.
pub fn setup(properties: &Properties, connectors: &[Info], ctx: ParserContext) -> bool {
    let cfg = match configure(properties) {
        Ok(c) => c,
        Err(SetupError::Invalid(msg)) => {
            log_line!(msg);
            return false;
        }
        Err(SetupError::Exit(lines)) => {
            lines.iter().for_each(|l| log_line!(l));
            std::process::exit(1);
        }
    };
    debug_log!(format!("text parser config:\n{cfg:?}"));
    // True when at least one connector started.
    connect_all(Arc::new(TextParser::new(cfg, ctx)), connectors)
}

/// The property handling of `setup` without the process exits.
/// Properties are read in sorted (BTreeMap) order instead of Go's random map order.
pub fn configure(props: &Properties) -> Result<TextConfig, SetupError> {
    let mut cfg = TextConfig {
        field_sep: " ".into(),
        attr_sep: "=".into(),
        keymap: Vec::new(),
        only_recs: Vec::new(),
        dt: DateTimeInfo::default(),
    };
    for (key, value) in props {
        if let Some(attr) = Attr::from_key(key) {
            // Comma-separated aliases (tag names or 1-based field numbers).
            cfg.keymap.push((attr, value.split(',').map(|s| s.trim().to_string()).collect()));
            continue;
        }
        match key.as_str() {
            "field_separator" => cfg.field_sep = value.clone(),
            "attribute_separator" => cfg.attr_sep = value.clone(),
            "timestamp_format" => {
                compile_timestamp_format(value, &mut cfg.dt).map_err(|m| SetupError::Exit(vec![m]))?
            }
            "only_recs" => match parse_only_recs(value) {
                Some(recs) => cfg.only_recs.extend(recs),
                None => return Err(SetupError::Invalid(format!("Invalid only_recs expression: {value}"))),
            },
            _ => log_line!("Unsupported text parser property:", key),
        }
    }
    // A non-default field separator makes a timestamp one field long. FlowPilot applies this after
    // all properties; in FlowLink the result depends on property order. The default is already 1.
    if cfg.field_sep != " " {
        cfg.dt.element_count = 1;
    }
    cfg.keymap.sort_by_key(|(a, _)| *a);
    let missing: Vec<String> = REQUIRED
        .iter()
        .filter(|r| !props.contains_key(**r))
        .map(|r| format!("Missing required text parser attribute: {r}"))
        .collect();
    if !missing.is_empty() {
        return Err(SetupError::Exit(missing));
    }
    Ok(cfg)
}

/// `only_recs` parsing: operators at odd, terms at even positions; `None` if invalid.
fn parse_only_recs(value: &str) -> Option<Vec<Vec<String>>> {
    value
        .split(',')
        .map(|clause| {
            clause
                .split_whitespace()
                .enumerate()
                .map(|(i, tok)| (matches!(tok, "&&" | "||") == (i % 2 == 1)).then(|| tok.to_string()))
                .collect()
        })
        .collect()
}

/// True when the record must be skipped. As in FlowLink, `||` is a no-op,
/// so `A || B` evaluates as B; clauses are ANDed; terms are case-sensitive substrings.
fn skips_record(only_recs: &[Vec<String>], rec: &str) -> bool {
    let mut matched = true;
    for clause in only_recs {
        for (i, tok) in clause.iter().enumerate() {
            if i % 2 == 0 {
                matched = rec.contains(tok.as_str());
            } else if tok == "&&" && !matched {
                return true;
            }
        }
        if !matched {
            return true;
        }
    }
    false
}

/// Validates `timestamp_format`. `Err` holds the message logged before exiting 1.
pub fn compile_timestamp_format(format: &str, dti: &mut DateTimeInfo) -> Result<(), String> {
    if dti.format == format {
        return Ok(());
    }
    dti.format = format.to_string();
    if format == "unix" {
        dti.element_count = 1;
        dti.go_format = "unix".into();
        return Ok(());
    }
    let mut go_format = String::new();
    for word in format.split_whitespace() {
        let mut elem = word;
        let mut ge = String::new();
        while !elem.is_empty() {
            let run = |c: char| elem.chars().take_while(|&x| x == c).count();
            let n = if elem.starts_with("yyyy") {
                ge += "2006";
                4
            } else if elem.starts_with("yy") {
                ge += "06";
                2
            } else if elem.starts_with("mm") {
                let k = run('m');
                ge += ["01", "Jan", "January"][(k - 2).min(2)];
                k
            } else if elem.starts_with("dd") {
                let k = run('d');
                ge += ["02", "Mon", "Monday"][(k - 2).min(2)];
                k
            } else if elem.starts_with("_d") {
                ge += "_2";
                2
            } else if elem.starts_with("ZZZ") {
                ge += "MST";
                3
            } else if elem.starts_with("HH") {
                ge += "15";
                2
            } else if elem.starts_with("MM") {
                // After a zone hour in the same word, MM means zone minutes.
                ge += if ge.contains("07") { "00" } else { "04" };
                2
            } else if elem.starts_with("SS") {
                ge += "05";
                2
            } else if elem.starts_with(".0") {
                if !ge.ends_with("05") {
                    return Err("Invalid time format.".into());
                }
                let k = 1 + elem[1..].chars().take_while(|&c| c == '0').count();
                ge += &elem[..k];
                k
            } else if elem.starts_with("ZHH") || elem.starts_with("-HH") {
                ge += &elem[..1];
                ge += "07";
                3
            } else if elem.starts_with('Z') {
                ge += "Z07";
                1
            } else if elem.starts_with(['T', ',', '-', ':']) {
                ge += &elem[..1];
                1
            } else {
                return Err(format!("Unrecognized element: {elem} in time format: {format}"));
            };
            elem = &elem[n..];
        }
        go_format.push(' ');
        go_format += &ge;
    }
    dti.element_count = format.split_whitespace().count();
    dti.go_format = go_format.trim().to_string();
    debug_log!(format!("timestamp format:\n{dti:?}"));
    Ok(())
}

/// Go `strings.Split`: an empty separator splits into UTF-8 characters.
fn go_split<'a>(s: &'a str, sep: &str) -> Vec<&'a str> {
    if sep.is_empty() {
        s.char_indices().map(|(i, c)| &s[i..i + c.len_utf8()]).collect()
    } else {
        s.split(sep).collect()
    }
}

/// Go `strconv.ParseUint(s, 10, bits)`: digits only (no sign).
fn parse_uint(s: &str, max: u64) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u64>().ok().filter(|&v| v <= max)
}

/// Go `net.ParseMAC` validity: 6, 8 or 20 octets as `xx:xx..`, `xx-xx..` or `xxxx.xxxx..`.
/// Ported from the Go standard library (`net`), BSD-3-Clause, Copyright (c) 2009 The Go Authors. See NOTICE.
fn parse_mac(s: &str) -> bool {
    let b = s.as_bytes();
    let hex2 = |p: &[u8]| p.len() >= 2 && p[..2].iter().all(u8::is_ascii_hexdigit);
    // xtoi2: two hex digits, followed by `sep` unless at the end.
    let group = |p: &[u8], sep: u8| hex2(p) && (p.len() == 2 || p[2] == sep);
    if b.len() < 14 {
        return false;
    }
    if b[2] == b':' || b[2] == b'-' {
        let n = (b.len() + 1) / 3;
        (b.len() + 1).is_multiple_of(3) && matches!(n, 6 | 8 | 20) && (0..n).all(|i| group(&b[i * 3..], b[2]))
    } else if b[4] == b'.' {
        let n = 2 * (b.len() + 1) / 5;
        (b.len() + 1).is_multiple_of(5)
            && matches!(n, 6 | 8 | 20)
            && (0..n / 2).all(|i| hex2(&b[i * 5..]) && group(&b[i * 5 + 2..], b'.'))
    } else {
        false
    }
}

/// Outcome of one line.
#[derive(Debug, PartialEq)]
pub enum LineResult {
    Ignored,
    Discarded(String),
    Flow(FlowData),
}

/// The text parser.
pub struct TextParser {
    cfg: TextConfig,
    meter: Meter,
    sink: FlowSink,
    stats: Arc<CollectorStats>,
}

impl TextParser {
    pub fn new(cfg: TextConfig, ctx: ParserContext) -> Self {
        Self { cfg, meter: ctx.meter, sink: ctx.sink, stats: ctx.stats }
    }

    /// One iteration of the worker loop for a received datagram, counted in the collector stats.
    fn handle_datagram(&self, pd: &ReceivedDatagram, log_invalid: &mut bool) {
        log::take_decode_errors(); // errors before this datagram are not its own
        let flows = self.decode_datagram(pd, log_invalid);
        self.stats.datagram(&pd.device_addr, Some(Proto::Text), pd.buf.len(), flows, log::take_decode_errors());
    }

    /// Decode one datagram. Returns the flow lines (discarded and ignored lines are metered, not counted).
    fn decode_datagram(&self, pd: &ReceivedDatagram, log_invalid: &mut bool) -> u64 {
        // Drop non-ASCII datagrams, logging at most once per worker.
        if !pd.buf.is_ascii() {
            if *log_invalid {
                log_line!("Ignoring invalid text data from:", pd.device_addr);
            }
            *log_invalid = false;
            log::note_decode_error();
            return 0;
        }
        let mut flows = 0;
        let data = String::from_utf8_lossy(&pd.buf);
        debug_log!("<<<<<<<<< Text Parser Received Data:", data);
        // The TCP path keeps an unterminated last line as `partial` for the next read.
        // TCP is deferred in this build; for UDP every datagram is self-contained.
        for line in data.split('\n') {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            self.meter.mark(1); // Counts ignored and discarded lines too.
            match self.parse_line(line, pd) {
                LineResult::Flow(fd) => {
                    flows += 1;
                    self.sink.send(fd);
                }
                LineResult::Discarded(reason) => {
                    log::note_decode_error();
                    log_line!("Discarding flow due to", reason);
                    log_line!(line);
                }
                LineResult::Ignored => debug_log!("Ignoring record:", line),
            }
        }
        flows
    }

    /// Filter, extract and timestamp one trimmed, non-empty line.
    fn parse_line(&self, line: &str, pd: &ReceivedDatagram) -> LineResult {
        let cfg = &self.cfg;
        if !cfg.only_recs.is_empty() && skips_record(&cfg.only_recs, line) {
            return LineResult::Ignored;
        }
        let mut fd = FlowData {
            transport: pd.transport.clone(),
            seq_id: pd.seq_id.clone(),
            key: FlowKey { device_addr: pd.device_addr.clone(), ..FlowKey::default() },
            flows: 1,
            direction_ind: 2,
            ..FlowData::default()
        };
        let fields = go_split(line, &cfg.field_sep);
        if log::debug() {
            for (i, v) in fields.iter().enumerate() {
                log_line!("i:", i, "v:", v);
            }
        }
        let mut time = None;
        let res = self.extract(&fields, &mut fd, &mut time);
        let missing = fd.key.src_ip.is_empty() || fd.key.dst_ip.is_empty() || fd.key.ip_version == 0;
        match res {
            Err(reason) => return LineResult::Discarded(reason),
            Ok(()) if missing => return LineResult::Discarded("missing data:".into()),
            Ok(()) => {}
        }
        fd.flow_time = time.unwrap_or_else(|| self.fallback_time(&fields));
        LineResult::Flow(fd)
    }

    /// Attribute extraction. `Err` is the discard reason.
    fn extract(&self, fields: &[&str], fd: &mut FlowData, time: &mut Option<i64>) -> Result<(), String> {
        let k = &mut fd.key;
        for (attr, aliases) in &self.cfg.keymap {
            let Some((idx, v)) = self.find(aliases, fields) else { continue };
            match attr {
                Attr::SrcIp | Attr::DstIp => {
                    let src = *attr == Attr::SrcIp;
                    if parse_ip(v).is_none() {
                        return Err(format!("invalid {} IP: {v}", if src { "source" } else { "destination" }));
                    }
                    let ver = if v.contains('.') { 4 } else { 6 };
                    if src && ver == 6 && k.protocol == 1 {
                        k.protocol = 58; // src_ip only
                    }
                    if k.ip_version != 0 && ver != k.ip_version {
                        // As in FlowLink, the two messages differ in capitalisation.
                        let m = if src { "Mixed" } else { "mixed" };
                        return Err(format!("{m} IP addresses. Ignoring record"));
                    }
                    *(if src { &mut k.src_ip } else { &mut k.dst_ip }) = v.to_string(); // raw, as in FlowLink
                    k.ip_version = ver;
                }
                Attr::DstPort => {
                    k.dst_port = parse_uint(v, u16::MAX.into()).ok_or(format!("invalid destination port: {v}"))? as u16
                }
                Attr::Protocol => {
                    k.protocol = match v {
                        "TCP" | "tcp" => 6,
                        "UDP" | "udp" => 17,
                        "ICMP" | "icmp" if k.ip_version == 6 => 58,
                        "ICMP" | "icmp" => 1,
                        _ => parse_uint(v, u8::MAX.into()).ok_or(format!("invalid protocol: {v}"))? as u8,
                    }
                }
                Attr::IcmpType => {
                    k.icmp_type = parse_uint(v, u8::MAX.into()).ok_or(format!("invalid icmp type: {v}"))? as u8
                }
                Attr::IcmpCode => {
                    k.icmp_code = parse_uint(v, u8::MAX.into()).ok_or(format!("invalid icmp code: {v}"))? as u8
                }
                Attr::Octets => fd.octets = v.parse::<i32>().map_err(|_| format!("invalid byte count: {v}"))?.into(),
                Attr::SrcMac | Attr::DstMac => {
                    let src = *attr == Attr::SrcMac;
                    if parse_mac(v) {
                        *(if src { &mut k.src_mac } else { &mut k.dst_mac }) = v.to_string();
                    } else {
                        // As in FlowLink: logged, but the record is kept.
                        let which = if src { "source" } else { "destination" };
                        log_line!(format!("Invalid {which} MAC addr:"), v, "Ignoring");
                    }
                }
                Attr::Timestamp => *time = self.keyed_time(v, idx, fields),
            }
        }
        Ok(())
    }

    /// Alias lookup: first alias, then first field. A `key<sep>value` field matches
    /// by tag name; any other field matches by its 1-based number, as in FlowLink.
    fn find<'a>(&self, aliases: &[String], fields: &[&'a str]) -> Option<(usize, &'a str)> {
        aliases.iter().find_map(|name| {
            fields.iter().enumerate().find_map(|(idx, raw)| {
                let f = raw.trim();
                let kv = go_split(f, &self.cfg.attr_sep);
                if kv.len() == 2 {
                    (kv[0] == name).then_some((idx, kv[1]))
                } else {
                    ((idx + 1).to_string() == *name).then_some((idx, f))
                }
            })
        })
    }

    /// Keyed timestamp. `None` means Go's zero time (fall back later).
    fn keyed_time(&self, v: &str, idx: usize, fields: &[&str]) -> Option<i64> {
        let dt = &self.cfg.dt;
        if dt.format == "unix" {
            return v.parse::<i64>().ok().filter(|&n| n != ZERO_UNIX);
        }
        let s = keyed_time_string(v, idx, fields, dt.element_count);
        match go_parse(&dt.go_format, &s) {
            Ok((secs, nsec)) => (secs != ZERO_UNIX || nsec != 0).then_some(secs),
            Err(e) => {
                log_line!("Invalid time:", s, "err:", e);
                None
            }
        }
    }

    /// Timestamp fallback: the first `element_count` fields, otherwise now().
    fn fallback_time(&self, fields: &[&str]) -> i64 {
        let dt = &self.cfg.dt;
        if dt.format == "unix" {
            return chrono::Utc::now().timestamp();
        }
        // Divergence: FlowLink panics with fewer fields than the element count; here the available
        // fields are parsed, which then fails as an invalid time.
        let s = fields.iter().take(dt.element_count).copied().collect::<Vec<_>>().join(" ");
        let s = s.trim();
        go_parse(&dt.go_format, s).map(|t| t.0).unwrap_or_else(|e| {
            log_line!("Invalid time:", s, "err:", e, "Using current time");
            chrono::Utc::now().timestamp()
        })
    }
}

/// The keyed timestamp string: the value plus the next `element_count`-1 raw fields, trimmed, with
/// the `Z` -> `Z00` fixup (as in FlowLink). Divergence: fields past the end are skipped
/// instead of panicking; the shortened string then fails to parse.
fn keyed_time_string(v: &str, idx: usize, fields: &[&str], ec: usize) -> String {
    let rest = (1..ec).filter_map(|j| fields.get(idx + j).copied());
    let mut s = std::iter::once(v).chain(rest).collect::<Vec<_>>().join(" ").trim().to_string();
    if s.ends_with('Z') {
        s += "00";
    }
    s
}

impl Parser for TextParser {
    fn type_name(&self) -> &'static str {
        "text"
    }

    fn default_port(&self) -> u16 {
        6514
    }

    /// Always true; `connectors::start_connector` rejects the deferred types itself.
    fn supports_connector(&self, _conn_type: &str) -> bool {
        true
    }

    fn stats(&self) -> Arc<CollectorStats> {
        self.stats.clone()
    }

    /// Channel capacity 30*n, n workers.
    fn start_workers(self: Arc<Self>, n: usize) -> Sender<ReceivedDatagram> {
        let (tx, rx) = crossbeam_channel::bounded(30 * n);
        for _ in 0..n {
            let (p, rx) = (self.clone(), rx.clone());
            thread::spawn(move || {
                let _guard = ThreadGuard::core("text parser");
                let mut log_invalid = true;
                // Divergence: FlowLink spins on a closed channel; the worker exits instead.
                for pd in rx {
                    p.handle_datagram(&pd, &mut log_invalid);
                }
            });
        }
        tx
    }
}

// ---- Go time.ParseInLocation(layout, value, Local), for the layouts compile_timestamp_format builds ----

#[derive(Clone, Copy, Debug, PartialEq)]
enum Tz {
    Short,    // -07
    Hm,       // -0700
    ColonHm,  // -07:00
    Hms,      // -070000
    ColonHms, // -07:00:00
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Std {
    LongYear,
    Year,
    ZeroMonth,
    NumMonth,
    Month,
    LongMonth,
    ZeroDay,
    Day,
    UnderDay,
    WeekDay,
    LongWeekDay,
    Hour,
    ZeroMinute,
    Minute,
    ZeroSecond,
    Second,
    Frac(usize),
    Abbrev,
    NumTz(Tz),
    IsoTz(Tz),
}

/// (literal prefix, std chunk and its layout text, remaining layout).
type Chunk<'a> = (&'a [u8], Option<(Std, &'a [u8])>, &'a [u8]);

/// Go `nextStdChunk` for the subset of std chunks reachable from validated formats. The
/// 12-hour, AM/PM, `.999` and year-day chunks cannot be produced and are treated as literals.
/// Ported from the Go standard library (`time`), BSD-3-Clause, Copyright (c) 2009 The Go Authors. See NOTICE.
fn next_std_chunk(l: &[u8]) -> Chunk<'_> {
    use Std::*;
    for i in 0..l.len() {
        let r = &l[i..];
        let lower_after = |n: usize| r.get(n).is_some_and(u8::is_ascii_lowercase);
        let hit = match r[0] {
            b'J' if r.starts_with(b"January") => Some((LongMonth, 7)),
            b'J' if r.starts_with(b"Jan") && !lower_after(3) => Some((Month, 3)),
            b'M' if r.starts_with(b"Monday") => Some((LongWeekDay, 6)),
            b'M' if r.starts_with(b"Mon") && !lower_after(3) => Some((WeekDay, 3)),
            b'M' if r.starts_with(b"MST") && !lower_after(3) => Some((Abbrev, 3)),
            b'0' => match r.get(1) {
                Some(b'1') => Some((ZeroMonth, 2)),
                Some(b'2') => Some((ZeroDay, 2)),
                Some(b'4') => Some((ZeroMinute, 2)),
                Some(b'5') => Some((ZeroSecond, 2)),
                Some(b'6') => Some((Year, 2)),
                _ => None,
            },
            b'1' => Some(if r.starts_with(b"15") { (Hour, 2) } else { (NumMonth, 1) }),
            b'2' => Some(if r.starts_with(b"2006") { (LongYear, 4) } else { (Day, 1) }),
            b'_' if r.get(1) == Some(&b'2') => {
                if r[1..].starts_with(b"2006") {
                    return (&l[..i + 1], Some((LongYear, &l[i + 1..i + 5])), &l[i + 5..]);
                }
                Some((UnderDay, 2))
            }
            b'4' => Some((Minute, 1)),
            b'5' => Some((Second, 1)),
            c @ (b'-' | b'Z') => {
                let forms: [(&[u8], Tz); 5] = [
                    (b"070000", Tz::Hms),
                    (b"07:00:00", Tz::ColonHms),
                    (b"0700", Tz::Hm),
                    (b"07:00", Tz::ColonHm),
                    (b"07", Tz::Short),
                ];
                forms.iter().find(|(f, _)| r[1..].starts_with(f)).map(|(f, tz)| {
                    (if c == b'-' { NumTz(*tz) } else { IsoTz(*tz) }, 1 + f.len())
                })
            }
            b'.' | b',' if r.get(1) == Some(&b'0') => {
                let j = 1 + r[1..].iter().take_while(|&&c| c == b'0').count();
                (!r.get(j).is_some_and(u8::is_ascii_digit)).then_some((Frac(j - 1), j))
            }
            _ => None,
        };
        if let Some((std, n)) = hit {
            return (&l[..i], Some((std, &l[i..i + n])), &l[i + n..]);
        }
    }
    (l, None, &[])
}

/// Go `time.quote`.
/// Ported from the Go standard library (`time`), BSD-3-Clause, Copyright (c) 2009 The Go Authors. See NOTICE.
fn go_quote(s: &[u8]) -> String {
    let mut o = String::from('"');
    for &c in s {
        if !(b' '..0x80).contains(&c) {
            o += &format!("\\x{c:02x}");
        } else {
            if c == b'"' || c == b'\\' {
                o.push('\\');
            }
            o.push(c as char);
        }
    }
    o.push('"');
    o
}

fn digit(s: &[u8], i: usize) -> bool {
    s.get(i).is_some_and(u8::is_ascii_digit)
}

/// Go `time.getnum`: one or two digits (exactly two when `fixed`).
/// Ported from the Go standard library (`time`), BSD-3-Clause, Copyright (c) 2009 The Go Authors. See NOTICE.
fn getnum(s: &[u8], fixed: bool) -> Result<(i64, &[u8]), ChunkErr> {
    if !digit(s, 0) {
        return Err(ChunkErr::Bad);
    }
    if !digit(s, 1) {
        return if fixed { Err(ChunkErr::Bad) } else { Ok(((s[0] - b'0').into(), &s[1..])) };
    }
    Ok((i64::from(s[0] - b'0') * 10 + i64::from(s[1] - b'0'), &s[2..]))
}

/// Go `time.atoi`: optional sign, then digits (none is 0).
/// Ported from the Go standard library (`time`), BSD-3-Clause, Copyright (c) 2009 The Go Authors. See NOTICE.
fn atoi(s: &[u8]) -> Result<i64, ChunkErr> {
    let (neg, d) = match s.first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    if !d.iter().all(u8::is_ascii_digit) {
        return Err(ChunkErr::Bad);
    }
    let x = d
        .iter()
        .try_fold(0i64, |a, &c| a.checked_mul(10)?.checked_add(i64::from(c - b'0')))
        .ok_or(ChunkErr::Bad)?;
    Ok(if neg { -x } else { x })
}

/// Go `time.lookup` with ASCII case folding.
/// Ported from the Go standard library (`time`), BSD-3-Clause, Copyright (c) 2009 The Go Authors. See NOTICE.
fn lookup<'a>(tab: &[&str], v: &'a [u8]) -> Result<(usize, &'a [u8]), ChunkErr> {
    tab.iter()
        .position(|n| v.len() >= n.len() && v[..n.len()].eq_ignore_ascii_case(n.as_bytes()))
        .map(|i| (i, &v[tab[i].len()..]))
        .ok_or(ChunkErr::Bad)
}

const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const LONG_MONTHS: [&str; 12] = [
    "January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November",
    "December",
];
const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const LONG_DAYS: [&str; 7] = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

/// Go `time.parseSignedOffset`.
/// Ported from the Go standard library (`time`), BSD-3-Clause, Copyright (c) 2009 The Go Authors. See NOTICE.
fn parse_signed_offset(v: &[u8]) -> usize {
    if !matches!(v.first(), Some(b'-' | b'+')) {
        return 0;
    }
    let n = v[1..].iter().take_while(|c| c.is_ascii_digit()).count();
    match atoi(&v[1..1 + n]) {
        Ok(x) if n > 0 && x <= 12 => 1 + n,
        _ => 0,
    }
}

/// Go `time.parseTimeZone`: length of a zone abbreviation at the start of `v`.
/// Ported from the Go standard library (`time`), BSD-3-Clause, Copyright (c) 2009 The Go Authors. See NOTICE.
fn parse_time_zone(v: &[u8]) -> Option<usize> {
    if v.len() < 3 {
        return None;
    }
    if v.starts_with(b"ChST") || v.starts_with(b"MeST") {
        return Some(4);
    }
    if v.starts_with(b"GMT") {
        return Some(3 + if v.len() == 3 { 0 } else { parse_signed_offset(&v[3..]) });
    }
    if matches!(v[0], b'+' | b'-') {
        return Some(parse_signed_offset(v)).filter(|&n| n > 0);
    }
    match v.iter().take(6).take_while(|c| c.is_ascii_uppercase()).count() {
        3 => Some(3),
        4 if v[3] == b'T' || v.starts_with(b"WITA") => Some(4),
        5 if v[4] == b'T' => Some(5),
        _ => None,
    }
}

enum ChunkErr {
    Bad,
    Range(&'static str),
}

/// Parsed fields; `month`/`day` of -1 mean "not given".
struct Fields<'a> {
    year: i64,
    month: i64,
    day: i64,
    hour: i64,
    min: i64,
    sec: i64,
    nsec: i64,
    utc: bool,
    offset: Option<i64>,
    zone: Option<&'a [u8]>,
}

/// Go `time.parseNanoseconds`.
/// Ported from the Go standard library (`time`), BSD-3-Clause, Copyright (c) 2009 The Go Authors. See NOTICE.
fn parse_nanos(v: &[u8], nbytes: usize) -> Result<i64, ChunkErr> {
    if !matches!(v[0], b'.' | b',') {
        return Err(ChunkErr::Bad);
    }
    let nb = nbytes.min(10);
    let ns = atoi(&v[1..nb])?;
    if ns < 0 {
        return Err(ChunkErr::Range("fractional second"));
    }
    Ok(ns * 10i64.pow((10 - nb) as u32))
}

/// One std chunk of Go's `parse` loop. `rest` is the remaining layout.
fn parse_chunk<'a>(std: Std, v: &mut &'a [u8], rest: &[u8], f: &mut Fields<'a>) -> Result<(), ChunkErr> {
    use ChunkErr::{Bad, Range};
    let range = |ok: bool, what| if ok { Ok(()) } else { Err(Range(what)) };
    match std {
        Std::LongYear => {
            if v.len() < 4 || !digit(v, 0) {
                return Err(Bad);
            }
            f.year = atoi(&v[..4])?;
            *v = &v[4..];
        }
        Std::Year => {
            if v.len() < 2 {
                return Err(Bad);
            }
            let y = atoi(&v[..2])?;
            f.year = y + if y >= 69 { 1900 } else { 2000 };
            *v = &v[2..];
        }
        Std::ZeroMonth | Std::NumMonth => {
            (f.month, *v) = getnum(v, std == Std::ZeroMonth)?;
            range((1..=12).contains(&f.month), "month")?;
        }
        Std::Month | Std::LongMonth => {
            let (i, r) = lookup(if std == Std::Month { &MONTHS } else { &LONG_MONTHS }, v)?;
            (f.month, *v) = (i as i64 + 1, r);
        }
        Std::WeekDay | Std::LongWeekDay => *v = lookup(if std == Std::WeekDay { &DAYS } else { &LONG_DAYS }, v)?.1,
        Std::ZeroDay | Std::Day | Std::UnderDay => {
            if std == Std::UnderDay && v.first() == Some(&b' ') {
                *v = &v[1..];
            }
            (f.day, *v) = getnum(v, std == Std::ZeroDay)?; // validated after parsing
        }
        Std::Hour => {
            (f.hour, *v) = getnum(v, false)?;
            range((0..24).contains(&f.hour), "hour")?;
        }
        Std::ZeroMinute | Std::Minute => {
            (f.min, *v) = getnum(v, std == Std::ZeroMinute)?;
            range((0..60).contains(&f.min), "minute")?;
        }
        Std::ZeroSecond | Std::Second => {
            (f.sec, *v) = getnum(v, std == Std::ZeroSecond)?;
            range((0..60).contains(&f.sec), "second")?;
            // A fractional second in the value although the layout has none right here.
            if v.len() >= 2 && matches!(v[0], b'.' | b',') && digit(v, 1) {
                if matches!(next_std_chunk(rest).1, Some((Std::Frac(_), _))) {
                    return Ok(());
                }
                let n = 2 + v[2..].iter().take_while(|c| c.is_ascii_digit()).count();
                f.nsec = parse_nanos(v, n)?;
                *v = &v[n..];
            }
        }
        Std::Frac(digits) => {
            let n = 1 + digits;
            if v.len() < n {
                return Err(Bad);
            }
            f.nsec = parse_nanos(v, n)?;
            *v = &v[n..];
        }
        Std::Abbrev => {
            if v.starts_with(b"UTC") {
                f.utc = true;
                *v = &v[3..];
            } else {
                let n = parse_time_zone(v).ok_or(Bad)?;
                f.zone = Some(&v[..n]);
                *v = &v[n..];
            }
        }
        Std::IsoTz(_) if v.first() == Some(&b'Z') => {
            f.utc = true;
            *v = &v[1..];
        }
        Std::IsoTz(tz) | Std::NumTz(tz) => {
            let s = *v;
            let (len, h, m, sec): (usize, usize, Option<usize>, Option<usize>) = match tz {
                Tz::Short => (3, 1, None, None),
                Tz::Hm => (5, 1, Some(3), None),
                Tz::ColonHm => (6, 1, Some(4), None),
                Tz::Hms => (7, 1, Some(3), Some(5)),
                Tz::ColonHms => (9, 1, Some(4), Some(7)),
            };
            if s.len() < len {
                return Err(Bad);
            }
            if matches!(tz, Tz::ColonHm | Tz::ColonHms) && s[3] != b':' || tz == Tz::ColonHms && s[6] != b':' {
                return Err(Bad);
            }
            let num = |i: Option<usize>| i.map_or(Ok(0), |i| getnum(&s[i..i + 2], true).map(|x| x.0));
            let (hr, mm, ss) = (num(Some(h)), num(m), num(sec));
            let bad = hr.is_err() || mm.is_err() || ss.is_err();
            let (hr, mm, ss) = (hr.unwrap_or(0), mm.unwrap_or(0), ss.unwrap_or(0));
            range(hr <= 24, "time zone offset hour")?;
            range(mm <= 60, "time zone offset minute")?;
            range(ss <= 60, "time zone offset second")?;
            let off = (hr * 60 + mm) * 60 + ss;
            f.offset = Some(match s[0] {
                b'+' if !bad => off,
                b'-' if !bad => -off,
                _ => return Err(Bad),
            });
            *v = &s[len..];
        }
    }
    Ok(())
}

/// Go `time.ParseInLocation(layout, value, time.Local)`. Returns unix seconds and nanoseconds,
/// or the Go `*ParseError` text.
/// Ported from the Go standard library (`time`), BSD-3-Clause, Copyright (c) 2009 The Go Authors. See NOTICE.
fn go_parse(layout: &str, value: &str) -> Result<(i64, u32), String> {
    let (alayout, avalue) = (layout.as_bytes(), value.as_bytes());
    let cannot = |lelem: &[u8], velem: &[u8]| {
        format!(
            "parsing time {} as {}: cannot parse {} as {}",
            go_quote(avalue),
            go_quote(alayout),
            go_quote(velem),
            go_quote(lelem)
        )
    };
    let msg = |m: String| format!("parsing time {}{m}", go_quote(avalue));
    let mut f = Fields {
        year: 0,
        month: -1,
        day: -1,
        hour: 0,
        min: 0,
        sec: 0,
        nsec: 0,
        utc: false,
        offset: None,
        zone: None,
    };
    let (mut l, mut v) = (alayout, avalue);
    loop {
        let (prefix, std, suffix) = next_std_chunk(l);
        v = skip(v, prefix).map_err(|rest| cannot(prefix, rest))?;
        let Some((std, stdstr)) = std else {
            if !v.is_empty() {
                return Err(msg(format!(": extra text: {}", go_quote(v))));
            }
            break;
        };
        l = suffix;
        let hold = v;
        match parse_chunk(std, &mut v, l, &mut f) {
            Ok(()) => {}
            Err(ChunkErr::Range(what)) => return Err(msg(format!(": {what} out of range"))),
            Err(ChunkErr::Bad) => return Err(cannot(stdstr, hold)),
        }
    }
    let (month, day) = (if f.month < 0 { 1 } else { f.month }, if f.day < 0 { 1 } else { f.day });
    let date = NaiveDate::from_ymd_opt(f.year as i32, month as u32, day as u32)
        .ok_or_else(|| msg(": day out of range".into()))?;
    let naive = date.and_hms_opt(0, 0, 0).expect("midnight").and_utc().timestamp() + f.hour * 3600 + f.min * 60 + f.sec;
    let secs = if f.utc {
        naive
    } else if let Some(off) = f.offset {
        naive - off
    } else if let Some(zone) = f.zone {
        // Unknown abbreviations keep a zero offset (Go: FixedZone(name, 0), or GMT+N which only
        // changes the location, not the instant).
        naive - local_zone_offset(&String::from_utf8_lossy(zone), naive).unwrap_or(0)
    } else {
        local_date(naive)
    };
    Ok((secs, f.nsec as u32))
}

/// Go `time.skip`: a layout space matches any run of spaces (or none at the end).
/// Ported from the Go standard library (`time`), BSD-3-Clause, Copyright (c) 2009 The Go Authors. See NOTICE.
fn skip<'a>(mut v: &'a [u8], mut prefix: &[u8]) -> Result<&'a [u8], &'a [u8]> {
    let cut = |s: &'a [u8]| -> &'a [u8] { &s[s.iter().take_while(|&&c| c == b' ').count()..] };
    while let Some(&p) = prefix.first() {
        if p == b' ' {
            if v.first().is_some_and(|&c| c != b' ') {
                return Err(v);
            }
            prefix = &prefix[prefix.iter().take_while(|&&c| c == b' ').count()..];
            v = cut(v);
            continue;
        }
        if v.first() != Some(&p) {
            return Err(v);
        }
        prefix = &prefix[1..];
        v = &v[1..];
    }
    Ok(v)
}

/// UTC offset (seconds east) of the local zone at a unix time.
fn local_offset(secs: i64) -> i64 {
    DateTime::from_timestamp(secs, 0)
        .map_or(0, |d| Local.offset_from_utc_datetime(&d.naive_utc()).fix().local_minus_utc().into())
}

/// Go `time.Date(..., Local)` for wall-clock seconds `wall` (the wall time read as UTC):
/// look up the offset at `wall`, and again at the corrected instant if that differs.
fn local_date(wall: i64) -> i64 {
    let off = local_offset(wall);
    let again = local_offset(wall - off);
    wall - if again != off { again } else { off }
}

/// Approximation of Go `Location.lookupName` on Local: probes the zone in effect at `wall`, at
/// the corrected instant and half a year either side, matching by abbreviation (libc tm_zone;
/// chrono has no zone names).
fn local_zone_offset(name: &str, wall: i64) -> Option<i64> {
    const HALF_YEAR: i64 = 182 * 86_400;
    let zones: Vec<(String, i64)> =
        [wall, wall - HALF_YEAR, wall + HALF_YEAR].into_iter().filter_map(local_zone_at).collect();
    zones
        .iter()
        .filter(|(n, _)| n == name)
        .find_map(|(_, off)| local_zone_at(wall - off).filter(|(n, _)| n == name).map(|z| z.1))
        .or_else(|| zones.iter().find(|(n, _)| n == name).map(|z| z.1))
}

#[cfg(unix)]
fn local_zone_at(secs: i64) -> Option<(String, i64)> {
    let t = libc::time_t::try_from(secs).ok()?;
    // SAFETY: an all-zero `tm` is valid; localtime_r only writes into it, and tm_zone (when set)
    // points to a NUL-terminated string in libc's static zone data.
    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&t, &mut tm).is_null() || tm.tm_zone.is_null() {
            return None;
        }
        let name = std::ffi::CStr::from_ptr(tm.tm_zone).to_string_lossy().into_owned();
        #[allow(clippy::useless_conversion)] // c_long is i32 on 32-bit targets
        Some((name, tm.tm_gmtoff.into()))
    }
}

#[cfg(not(unix))]
fn local_zone_at(_secs: i64) -> Option<(String, i64)> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Local, NaiveDate, TimeZone};
    use crossbeam_channel::Receiver;
    use std::time::Duration;

    fn props(kv: &[(&str, &str)]) -> Properties {
        kv.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    /// The text parser properties from original/usr/local/illumio/config.yaml.example.
    fn example() -> Properties {
        props(&[
            ("src_ip", "sip"),
            ("dst_ip", "dip"),
            ("dst_port", "dport"),
            ("protocol", "prot"),
            ("timestamp", "date_time, 1"),
            ("timestamp_format", "mmm dd yyyy HH:MM:SS"),
        ])
    }

    fn with(mut p: Properties, kv: &[(&str, &str)]) -> Properties {
        p.extend(props(kv));
        p
    }

    fn parser(p: &Properties) -> (TextParser, Receiver<FlowData>) {
        let (tx, rx) = crossbeam_channel::unbounded();
        let ctx = ParserContext::new(Meter::new(), FlowSink::new(tx), Arc::new(CollectorStats::default()));
        (TextParser::new(configure(p).expect("valid config"), ctx), rx)
    }

    fn pd(buf: &str) -> ReceivedDatagram {
        ReceivedDatagram { device_addr: "192.0.2.9".into(), seq_id: String::new(), transport: "udp".into(), buf: buf.into() }
    }

    fn flow(tp: &TextParser, line: &str) -> FlowData {
        match tp.parse_line(line, &pd("")) {
            LineResult::Flow(fd) => fd,
            other => panic!("expected a flow for {line:?}, got {other:?}"),
        }
    }

    fn discard(tp: &TextParser, line: &str) -> String {
        match tp.parse_line(line, &pd("")) {
            LineResult::Discarded(r) => r,
            other => panic!("expected a discard for {line:?}, got {other:?}"),
        }
    }

    fn local(y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> i64 {
        let n = NaiveDate::from_ymd_opt(y, mo, d).unwrap().and_hms_opt(h, mi, s).unwrap();
        Local.from_local_datetime(&n).earliest().unwrap().timestamp()
    }

    fn utc(y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> i64 {
        NaiveDate::from_ymd_opt(y, mo, d).unwrap().and_hms_opt(h, mi, s).unwrap().and_utc().timestamp()
    }

    fn assert_now(t: i64) {
        let now = chrono::Utc::now().timestamp();
        assert!((now - 5..=now).contains(&t), "{t} is not now ({now})");
    }

    const REC: &str = "date_time=Jan 02 2020 10:00:00 sip=10.0.0.1 dip=10.0.0.2 dport=443 prot=tcp action=Established";

    // ---- setup / configure ----

    #[test]
    fn configure_example_config() {
        let c = configure(&example()).unwrap();
        assert_eq!((c.field_sep.as_str(), c.attr_sep.as_str()), (" ", "="));
        assert!(c.only_recs.is_empty());
        let ts = c.keymap.iter().find(|(k, _)| *k == Attr::Timestamp).unwrap();
        assert_eq!(ts.1, vec!["date_time", "1"]);
        assert_eq!(c.keymap.iter().find(|(k, _)| *k == Attr::SrcIp).unwrap().1, vec!["sip"]);
        assert_eq!(c.dt.go_format, "Jan 02 2006 15:04:05");
        assert_eq!(c.dt.element_count, 4);
        // Divergence: fixed processing order, protocol first.
        let order: Vec<Attr> = c.keymap.iter().map(|(k, _)| *k).collect();
        assert_eq!(order, vec![Attr::Protocol, Attr::SrcIp, Attr::DstIp, Attr::DstPort, Attr::Timestamp]);
    }

    #[test]
    fn configure_defaults_and_unsupported_property() {
        let p = props(&[("src_ip", "1"), ("dst_ip", "2"), ("dst_port", "3"), ("protocol", "4"), ("bogus", "x")]);
        let c = configure(&p).unwrap();
        assert_eq!(c.dt, DateTimeInfo::default());
        assert_eq!(c.dt.go_format, "2006-01-02T15:04:05-07:00");
        assert_eq!(c.dt.format, "yyyy-mm-ddTHH:MM:SS-HH:MM");
        // An empty value still counts as present.
        let p = props(&[("src_ip", ""), ("dst_ip", "2"), ("dst_port", "3"), ("protocol", "4")]);
        assert_eq!(configure(&p).unwrap().keymap[1], (Attr::SrcIp, vec![String::new()]));
    }

    #[test]
    fn configure_missing_required_exits() {
        let p = props(&[("src_ip", "sip"), ("octets", "bytes")]);
        assert_eq!(
            configure(&p),
            Err(SetupError::Exit(vec![
                "Missing required text parser attribute: dst_ip".into(),
                "Missing required text parser attribute: dst_port".into(),
                "Missing required text parser attribute: protocol".into(),
            ]))
        );
    }

    #[test]
    fn configure_only_recs() {
        let c = configure(&with(example(), &[("only_recs", "action=Established")])).unwrap();
        assert_eq!(c.only_recs, vec![vec!["action=Established".to_string()]]);
        let c = configure(&with(example(), &[("only_recs", " a && b , c || d,e &&,")])).unwrap();
        let want: Vec<Vec<&str>> = vec![vec!["a", "&&", "b"], vec!["c", "||", "d"], vec!["e", "&&"], vec![]];
        assert_eq!(c.only_recs, want);
        for bad in ["&& a", "a b", "a && || b", "a, || b"] {
            assert_eq!(
                configure(&with(example(), &[("only_recs", bad)])),
                Err(SetupError::Invalid(format!("Invalid only_recs expression: {bad}")))
            );
        }
    }

    #[test]
    fn configure_invalid_format_exits() {
        let p = with(example(), &[("timestamp_format", "yyyy/mm/dd")]);
        assert_eq!(
            configure(&p),
            Err(SetupError::Exit(vec!["Unrecognized element: /mm/dd in time format: yyyy/mm/dd".into()]))
        );
    }

    #[test]
    fn configure_field_separator_forces_single_element() {
        // Divergence: applied after all properties, independent of map order.
        let c = configure(&with(example(), &[("field_separator", ",")])).unwrap();
        assert_eq!((c.dt.element_count, c.dt.go_format.as_str()), (1, "Jan 02 2006 15:04:05"));
        let c = configure(&with(example(), &[("field_separator", " "), ("attribute_separator", ":")])).unwrap();
        assert_eq!((c.dt.element_count, c.attr_sep.as_str()), (4, ":"));
    }

    // ---- compile_timestamp_format ----

    #[test]
    fn date_format_tokens() {
        let cases: &[(&str, &str, usize)] = &[
            ("yyyy", "2006", 1),
            ("yy", "06", 1),
            ("mm", "01", 1),
            ("mmm", "Jan", 1),
            ("mmmm", "January", 1),
            ("mmmmm", "January", 1),
            ("dd", "02", 1),
            ("ddd", "Mon", 1),
            ("dddd", "Monday", 1),
            ("_d", "_2", 1),
            ("ZZZ", "MST", 1),
            ("HH", "15", 1),
            ("MM", "04", 1),
            ("SS", "05", 1),
            ("SS.000", "05.000", 1),
            ("HH:MM:SS.0", "15:04:05.0", 1),
            ("ZHH", "Z07", 1),
            ("-HH", "-07", 1),
            ("Z", "Z07", 1),
            ("-HH:MM", "-07:00", 1),
            ("-HHMM", "-0700", 1),
            ("ZHH:MM", "Z07:00", 1),
            ("ZHHMM", "Z0700", 1),
            ("ZMM", "Z0700", 1),
            ("-HH MM", "-07 04", 2),
            ("dd,mm", "02,01", 1),
            ("yyyy-mm-ddTHH:MM:SS", "2006-01-02T15:04:05", 1),
            ("mmm dd yyyy HH:MM:SS", "Jan 02 2006 15:04:05", 4),
            ("yyyy-mm-ddTHH:MM:SS.000ZHH:MM", "2006-01-02T15:04:05.000Z07:00", 1),
            ("ddd, dd mmm yyyy HH:MM:SS -HHMM", "Mon, 02 Jan 2006 15:04:05 -0700", 6),
            ("  yyyy \t mm  ", "2006 01", 2),
            ("unix", "unix", 1),
        ];
        for (fmt, go, ec) in cases {
            let mut d = DateTimeInfo::default();
            assert_eq!(compile_timestamp_format(fmt, &mut d), Ok(()), "{fmt}");
            assert_eq!((d.format.as_str(), d.go_format.as_str(), d.element_count), (*fmt, *go, *ec), "{fmt}");
        }
    }

    #[test]
    fn date_format_same_as_current_is_noop() {
        let mut d = DateTimeInfo { element_count: 7, ..DateTimeInfo::default() };
        let f = d.format.clone();
        assert_eq!(compile_timestamp_format(&f, &mut d), Ok(()));
        assert_eq!(d.element_count, 7);
    }

    #[test]
    fn date_format_invalid() {
        let un = |e: &str, f: &str| format!("Unrecognized element: {e} in time format: {f}");
        let cases = [
            ("yyyy/mm", un("/mm", "yyyy/mm")),
            ("SS.x", un(".x", "SS.x")),
            ("y", un("y", "y")),
            ("m", un("m", "m")),
            ("hh:MM", un("hh:MM", "hh:MM")),
            ("HH AM", un("AM", "HH AM")),
            ("12", un("12", "12")),
            ("+HH", un("+HH", "+HH")),
            (".000", "Invalid time format.".to_string()),
            ("HH.000", "Invalid time format.".to_string()),
        ];
        for (fmt, msg) in cases {
            assert_eq!(compile_timestamp_format(fmt, &mut DateTimeInfo::default()), Err(msg), "{fmt}");
        }
    }

    // ---- Go time.ParseInLocation ----

    #[test]
    fn go_parse_fields() {
        let t = |l: &str, v: &str| go_parse(l, v).map(|x| x.0);
        assert_eq!(t("Jan 02 2006 15:04:05", "jAN 02 2020 10:00:00"), Ok(local(2020, 1, 2, 10, 0, 0)));
        assert_eq!(t("January 2 2006 15:04:05", "march 7 2020 9:05:00"), Ok(local(2020, 3, 7, 9, 5, 0)));
        // The weekday must be a valid name but is otherwise ignored.
        assert_eq!(t("Monday, 02 Jan 2006", "Sunday, 07 Jan 2020"), Ok(local(2020, 1, 7, 0, 0, 0)));
        assert_eq!(t("Mon 02 Jan 2006", "TUE 07 Jan 2020"), Ok(local(2020, 1, 7, 0, 0, 0)));
        assert!(t("Mon 02 Jan 2006", "Fun 07 Jan 2020").is_err());
        assert_eq!(t("06-01-02", "69-12-31"), Ok(local(1969, 12, 31, 0, 0, 0)));
        assert_eq!(t("06-01-02", "68-12-31"), Ok(local(2068, 12, 31, 0, 0, 0)));
        // "_2" accepts a leading space; a missing year is year 0.
        assert_eq!(t("Jan _2 15:04:05 MST", "Jan  5 10:00:00 UTC"), Ok(utc(0, 1, 5, 10, 0, 0)));
        assert_eq!(t("Jan _2 15:04:05", "Jan 15 10:00:00"), Ok(local(0, 1, 15, 10, 0, 0)));
        // Fixed two-digit fields; "15" takes one or two digits.
        assert!(t("2006-01-02", "2020-1-02").is_err());
        assert_eq!(t("2006-01-02 15", "2020-01-02 9"), Ok(local(2020, 1, 2, 9, 0, 0)));
        // Fractional seconds.
        assert_eq!(go_parse("15:04:05 2006 MST", "10:00:00.25 2020 UTC"), Ok((utc(2020, 1, 1, 10, 0, 0), 250_000_000)));
        assert_eq!(go_parse("2006 05.000 MST", "2020 01.123 UTC"), Ok((utc(2020, 1, 1, 0, 0, 1), 123_000_000)));
        assert!(t("2006 05.000", "2020 01.12").is_err());
        // Spaces in the layout match runs of spaces.
        assert_eq!(t("2006 01", "2020    03"), Ok(local(2020, 3, 1, 0, 0, 0)));
    }

    #[test]
    fn go_parse_zones() {
        let t = |l: &str, v: &str| go_parse(l, v).map(|x| x.0);
        let base = utc(2020, 1, 2, 10, 0, 0);
        assert_eq!(t("2006-01-02T15:04:05Z07:00", "2020-01-02T10:00:00Z"), Ok(base));
        assert_eq!(t("2006-01-02T15:04:05Z07:00", "2020-01-02T10:00:00+02:00"), Ok(base - 7200));
        assert_eq!(t("2006-01-02T15:04:05-07:00", "2020-01-02T10:00:00-01:30"), Ok(base + 5400));
        assert_eq!(t("2006-01-02T15:04:05-0700", "2020-01-02T10:00:00+0100"), Ok(base - 3600));
        assert_eq!(t("2006-01-02T15:04:05Z0700", "2020-01-02T10:00:00Z"), Ok(base));
        assert_eq!(t("2006-01-02T15:04:05-07", "2020-01-02T10:00:00-03"), Ok(base + 3 * 3600));
        assert!(t("2006-01-02T15:04:05-07", "2020-01-02T10:00:00 03").is_err()); // sign required
        assert!(t("2006-01-02T15:04:05-07:00", "2020-01-02T10:00:00Z").is_err());
        assert_eq!(t("2006-01-02 15:04:05 MST", "2020-01-02 10:00:00 UTC"), Ok(base));
        // An unknown abbreviation gets a zero offset.
        assert_eq!(t("2006-01-02 15:04:05 MST", "2020-01-02 10:00:00 QQT"), Ok(base));
        assert_eq!(t("2006-01-02 15:04:05 MST", "2020-01-02 10:00:00 GMT+3"), Ok(base));
        assert!(t("2006-01-02 15:04:05 MST", "2020-01-02 10:00:00 xx").is_err());
        // Year 1 Jan 1 UTC is Go's zero time.
        assert_eq!(go_parse("2006-01-02T15:04:05Z07:00", "0001-01-01T00:00:00Z"), Ok((ZERO_UNIX, 0)));
    }

    #[test]
    fn go_parse_local_abbreviation() {
        // An abbreviation of the local zone uses that zone's offset.
        let wall = utc(2020, 1, 2, 10, 0, 0);
        if let Some((name, off)) = local_zone_at(wall).filter(|(n, _)| n.len() >= 3 && n.bytes().all(|c| c.is_ascii_uppercase())) {
            let got = go_parse("2006-01-02 15:04:05 MST", &format!("2020-01-02 10:00:00 {name}")).unwrap().0;
            assert_eq!(got, wall - off, "{name}");
        }
    }

    #[test]
    fn go_parse_errors_match_go() {
        assert_eq!(
            go_parse("Jan 02 2006", "Foo 02 2020"),
            Err(r#"parsing time "Foo 02 2020" as "Jan 02 2006": cannot parse "Foo 02 2020" as "Jan""#.into())
        );
        assert_eq!(
            go_parse("2006-01", "2020/01"),
            Err(r#"parsing time "2020/01" as "2006-01": cannot parse "/01" as "-""#.into())
        );
        assert_eq!(go_parse("2006", "2020 x"), Err(r#"parsing time "2020 x": extra text: " x""#.into()));
        assert_eq!(go_parse("01", "13"), Err(r#"parsing time "13": month out of range"#.into()));
        assert_eq!(go_parse("15:04", "24:00"), Err(r#"parsing time "24:00": hour out of range"#.into()));
        assert_eq!(go_parse("Jan 02 2006", "Feb 30 2020"), Err(r#"parsing time "Feb 30 2020": day out of range"#.into()));
        assert_eq!(
            go_parse("2006", "\"x\\\x01"),
            Err(r#"parsing time "\"x\\\x01" as "2006": cannot parse "\"x\\\x01" as "2006""#.into())
        );
        assert_eq!(
            go_parse("2006-01-02T15:04:05-07:00", "2020-01-02T10:00:00Z00"),
            Err(r#"parsing time "2020-01-02T10:00:00Z00" as "2006-01-02T15:04:05-07:00": cannot parse "Z00" as "-07:00""#.into())
        );
    }

    // ---- Parse ----

    #[test]
    fn example_config_keyed_record() {
        let (tp, _rx) = parser(&example());
        let fd = flow(&tp, REC);
        assert_eq!(fd.transport, "udp");
        assert_eq!(fd.key.device_addr, "192.0.2.9");
        assert_eq!((fd.key.src_ip.as_str(), fd.key.dst_ip.as_str()), ("10.0.0.1", "10.0.0.2"));
        assert_eq!((fd.key.dst_port, fd.key.protocol, fd.key.ip_version), (443, 6, 4));
        assert_eq!((fd.src_port, fd.flows, fd.octets, fd.direction_ind), (0, 1, 0, 2));
        assert_eq!(fd.flow_time, local(2020, 1, 2, 10, 0, 0));
        // The "1" alias: field 1 when there is no date_time tag.
        let fd = flow(&tp, "Mar 05 2021 23:59:58 sip=10.0.0.1 dip=10.0.0.2 dport=22 prot=6");
        assert_eq!(fd.flow_time, local(2021, 3, 5, 23, 59, 58));
    }

    #[test]
    fn example_config_only_recs() {
        let (tp, _rx) = parser(&with(example(), &[("only_recs", "action=Established")]));
        assert!(matches!(tp.parse_line(REC, &pd("")), LineResult::Flow(_)));
        assert_eq!(tp.parse_line(&REC.replace("Established", "Denied"), &pd("")), LineResult::Ignored);
    }

    #[test]
    fn only_recs_semantics() {
        let ign = |expr: &str, rec: &str| skips_record(&parse_only_recs(expr).unwrap(), rec);
        assert!(ign("a || b", "a")); // as in FlowLink: `A || B` == B
        assert!(!ign("a || b", "b"));
        assert!(!ign("a || b", "x b"));
        assert!(ign("a && b", "a"));
        assert!(ign("a && b", "b"));
        assert!(!ign("a && b", "b a"));
        assert!(ign("a, b", "a"));
        assert!(!ign("a, b", "ab"));
        assert!(!ign("a &&", "a"));
        assert!(ign("a &&", "x"));
        assert!(!ign("", "x"));
        assert!(ign("Est", "est")); // case-sensitive substring
        assert!(ign("a && b || c", "c")); // the `&&` fails early when a is missing
        assert!(ign("a && b || c", "b c"));
        assert!(!ign("a && b || c", "a c")); // b is ignored by the `||`
    }

    #[test]
    fn positional_fields_and_default_timestamp() {
        let p = props(&[("src_ip", "2"), ("dst_ip", "3"), ("dst_port", "4"), ("protocol", "5"), ("octets", "6")]);
        let (tp, _rx) = parser(&p);
        let fd = flow(&tp, "2020-01-02T10:00:00+01:00 10.0.0.1 10.0.0.2 443 17 -1500");
        assert_eq!((fd.key.src_ip.as_str(), fd.key.dst_ip.as_str()), ("10.0.0.1", "10.0.0.2"));
        assert_eq!((fd.key.dst_port, fd.key.protocol, fd.octets), (443, 17, -1500));
        assert_eq!(fd.flow_time, utc(2020, 1, 2, 9, 0, 0));
        // Empty fields from repeated separators count toward the numbering.
        // Field 5 is now the port.
        assert_eq!(discard(&tp, "2020-01-02T10:00:00Z  10.0.0.1 10.0.0.2 443 6"), "invalid protocol: 443");
    }

    #[test]
    fn alias_rules() {
        let p = props(&[("src_ip", "sip, 2"), ("dst_ip", "1"), ("dst_port", "dport"), ("protocol", "prot")]);
        let (tp, _rx) = parser(&p);
        // First alias wins.
        let fd = flow(&tp, "10.0.0.9 10.0.0.1 sip=10.0.0.3 dport=1 prot=6");
        assert_eq!((fd.key.src_ip.as_str(), fd.key.dst_ip.as_str()), ("10.0.0.3", "10.0.0.9"));
        let fd = flow(&tp, "10.0.0.9 10.0.0.1 dport=1 prot=6");
        assert_eq!(fd.key.src_ip, "10.0.0.1");
        // A field with exactly one separator is never matched by its number.
        assert_eq!(discard(&tp, "x=10.0.0.9 10.0.0.1 dport=1 prot=6"), "missing data:");
        // ... but a field with two separators is, and keeps its full text.
        assert_eq!(discard(&tp, "a=b=c 10.0.0.1 dport=1 prot=6"), "invalid destination IP: a=b=c");
        // The value after the separator is not trimmed again; the field is.
        assert_eq!(discard(&tp, "\t10.0.0.9 10.0.0.1 dport= 1 prot=6"), "invalid destination port: ");
    }

    #[test]
    fn protocols() {
        let (tp, _rx) = parser(&example());
        let proto = |p: &str, sip: &str, dip: &str| {
            let line = format!("sip={sip} dip={dip} dport=0 prot={p}");
            match tp.parse_line(&line, &pd("")) {
                LineResult::Flow(fd) => Ok(fd.key.protocol),
                LineResult::Discarded(r) => Err(r),
                LineResult::Ignored => unreachable!(),
            }
        };
        let (v4, v4b, v6, v6b) = ("10.0.0.1", "10.0.0.2", "2001:db8::1", "2001:db8::2");
        assert_eq!(proto("tcp", v4, v4b), Ok(6));
        assert_eq!(proto("TCP", v4, v4b), Ok(6));
        assert_eq!(proto("udp", v4, v4b), Ok(17));
        assert_eq!(proto("UDP", v4, v4b), Ok(17));
        assert_eq!(proto("icmp", v4, v4b), Ok(1));
        assert_eq!(proto("ICMP", v4, v4b), Ok(1));
        assert_eq!(proto("icmp", v6, v6b), Ok(58));
        assert_eq!(proto("1", v6, v6b), Ok(58)); // divergence: deterministic
        assert_eq!(proto("58", v6, v6b), Ok(58));
        assert_eq!(proto("47", v4, v4b), Ok(47));
        assert_eq!(proto("0", v4, v4b), Ok(0));
        assert_eq!(proto("Tcp", v4, v4b), Err("invalid protocol: Tcp".into()));
        assert_eq!(proto("256", v4, v4b), Err("invalid protocol: 256".into()));
        assert_eq!(proto("+6", v4, v4b), Err("invalid protocol: +6".into()));
        assert_eq!(proto("", v4, v4b), Err("invalid protocol: ".into()));
    }

    #[test]
    fn ip_handling() {
        let (tp, _rx) = parser(&example());
        let fd = flow(&tp, "sip=2001:DB8::1 dip=2001:db8:0::2 dport=53 prot=udp");
        assert_eq!((fd.key.src_ip.as_str(), fd.key.dst_ip.as_str()), ("2001:DB8::1", "2001:db8:0::2"));
        assert_eq!(fd.key.ip_version, 6);
        // As in FlowLink, IPv4-mapped counts as IPv4 because it contains a '.'.
        let fd = flow(&tp, "sip=::ffff:10.0.0.1 dip=10.0.0.2 dport=53 prot=udp");
        assert_eq!((fd.key.src_ip.as_str(), fd.key.ip_version), ("::ffff:10.0.0.1", 4));
        assert_eq!(discard(&tp, "sip=::ffff:10.0.0.1 dip=::2 dport=53 prot=udp"), "mixed IP addresses. Ignoring record");
        assert_eq!(discard(&tp, "sip=10.0.0.256 dip=10.0.0.2 dport=53 prot=udp"), "invalid source IP: 10.0.0.256");
        assert_eq!(discard(&tp, "sip=10.0.0.1 dip=01.0.0.2 dport=53 prot=udp"), "invalid destination IP: 01.0.0.2");
        assert_eq!(discard(&tp, "sip=fe80::1%en0 dip=::2 dport=53 prot=udp"), "invalid source IP: fe80::1%en0");
        assert_eq!(discard(&tp, "sip=[::1] dip=::2 dport=53 prot=udp"), "invalid source IP: [::1]");
    }

    #[test]
    fn mac_handling() {
        let (tp, _rx) = parser(&with(example(), &[("src_mac", "smac"), ("dst_mac", "dmac")]));
        let fd = flow(&tp, "sip=10.0.0.1 dip=10.0.0.2 dport=1 prot=6 smac=00:11:22:aA:bB:cC dmac=0011.2233.4455");
        assert_eq!((fd.key.src_mac.as_str(), fd.key.dst_mac.as_str()), ("00:11:22:aA:bB:cC", "0011.2233.4455"));
        // As in FlowLink, an invalid MAC is logged and left empty; the record is kept.
        let fd = flow(&tp, "sip=10.0.0.1 dip=10.0.0.2 dport=1 prot=6 smac=zz dmac=00:11:22:33:44");
        assert_eq!((fd.key.src_mac.as_str(), fd.key.dst_mac.as_str()), ("", ""));

        for ok in [
            "00:00:5e:00:53:01",
            "00-00-5E-00-53-01",
            "02:00:5e:10:00:00:00:01",
            "00:00:00:00:fe:80:00:00:00:00:00:00:02:00:5e:10:00:00:00:01",
            "0000.5e00.5301",
            "0200.5e10.0000.0001",
        ] {
            assert!(parse_mac(ok), "{ok}");
        }
        for bad in ["", "00:00:5e:00:53", "00:00:5e:00:53:01:02", "00-00:5e-00-53-01", "000:05e:005:301", "00005e005301", "0000.5e00.530g", "g0:00:5e:00:53:01"] {
            assert!(!parse_mac(bad), "{bad}");
        }
    }

    #[test]
    fn discard_reasons() {
        let p = with(example(), &[("icmp_type", "it"), ("icmp_code", "ic"), ("octets", "bytes")]);
        let (tp, _rx) = parser(&p);
        let base = "sip=10.0.0.1 dip=10.0.0.2 dport=443 prot=6";
        assert_eq!(discard(&tp, "sip=10.0.0.1 dport=443 prot=6"), "missing data:");
        assert_eq!(discard(&tp, "dip=10.0.0.1 dport=443 prot=6"), "missing data:");
        assert_eq!(discard(&tp, "sip=10.0.0.1 dip=10.0.0.2 dport=99999 prot=6"), "invalid destination port: 99999");
        assert_eq!(discard(&tp, "sip=10.0.0.1 dip=10.0.0.2 dport=+80 prot=6"), "invalid destination port: +80");
        assert_eq!(discard(&tp, &format!("{base} it=256")), "invalid icmp type: 256");
        assert_eq!(discard(&tp, &format!("{base} ic=x")), "invalid icmp code: x");
        assert_eq!(discard(&tp, &format!("{base} bytes=1e3")), "invalid byte count: 1e3");
        assert_eq!(discard(&tp, &format!("{base} bytes=2147483648")), "invalid byte count: 2147483648");
        let fd = flow(&tp, &format!("{base} it=3 ic=1 bytes=-2147483648"));
        assert_eq!((fd.key.icmp_type, fd.key.icmp_code, fd.octets), (3, 1, -2147483648));
        // dst_port is optional for the parser (only the four required keys must be configured).
        assert_eq!(flow(&tp, "sip=10.0.0.1 dip=10.0.0.2 prot=6").key.dst_port, 0);
    }

    #[test]
    fn unix_timestamps() {
        let p = with(example(), &[("timestamp", "ts"), ("timestamp_format", "unix")]);
        let (tp, _rx) = parser(&p);
        let base = "sip=10.0.0.1 dip=10.0.0.2 dport=443 prot=6";
        assert_eq!(flow(&tp, &format!("{base} ts=1577959200")).flow_time, 1577959200);
        assert_eq!(flow(&tp, &format!("{base} ts=-5")).flow_time, -5);
        assert_now(flow(&tp, &format!("{base} ts=abc")).flow_time);
        assert_now(flow(&tp, base).flow_time);
    }

    #[test]
    fn z_fixup_only_on_keyed_path() {
        let p = with(example(), &[("timestamp", "1"), ("timestamp_format", "yyyy-mm-ddTHH:MM:SSZHH:MM")]);
        let (tp, _rx) = parser(&p);
        // Keyed: "...Z" becomes "...Z00" which fails ("extra text"); the field-0 fallback has no
        // fixup and succeeds.
        let fd = flow(&tp, "2020-01-02T10:00:00Z sip=10.0.0.1 dip=10.0.0.2 dport=443 prot=6");
        assert_eq!(fd.flow_time, utc(2020, 1, 2, 10, 0, 0));
        assert_eq!(keyed_time_string("2020-01-02T10:00:00Z", 0, &[], 1), "2020-01-02T10:00:00Z00");
        assert_eq!(keyed_time_string("Jan", 1, &["x", "Jan", "02", "2020 "], 3), "Jan 02 2020");
        // Divergence: missing trailing fields are skipped instead of panicking.
        assert_eq!(keyed_time_string("Jan", 1, &["x", "Jan", "02"], 4), "Jan 02");
    }

    #[test]
    fn timestamp_past_last_field_falls_back_to_now() {
        let (tp, _rx) = parser(&example());
        assert_now(flow(&tp, "sip=10.0.0.1 dip=10.0.0.2 dport=443 prot=6 date_time=Jan").flow_time);
        // Fewer fields than the element count on the fallback path (divergence: no panic).
        let p = with(example(), &[("src_ip", "1"), ("dst_ip", "2"), ("dst_port", "3"), ("protocol", "3")]);
        let (tp, _rx) = parser(&p);
        let fd = flow(&tp, "10.0.0.1 10.0.0.2 6");
        assert_eq!((fd.key.dst_port, fd.key.protocol), (6, 6));
        assert_now(fd.flow_time);
        // An unparseable keyed timestamp also falls back to now().
        let (tp, _rx) = parser(&example());
        assert_now(flow(&tp, "date_time=Foo 02 2020 10:00:00 sip=10.0.0.1 dip=10.0.0.2 dport=1 prot=6").flow_time);
    }

    #[test]
    fn year_zero_layout() {
        let p = with(example(), &[("timestamp_format", "mmm dd HH:MM:SS")]);
        let (tp, _rx) = parser(&p);
        let fd = flow(&tp, "Jan 02 10:00:00 sip=10.0.0.1 dip=10.0.0.2 dport=1 prot=6");
        assert_eq!(fd.flow_time, local(0, 1, 2, 10, 0, 0));
        assert!(fd.flow_time < -62_000_000_000);
    }

    #[test]
    fn separators() {
        let p = props(&[
            ("src_ip", "s"),
            ("dst_ip", "d"),
            ("dst_port", "p"),
            ("protocol", "4"),
            ("field_separator", ";"),
            ("attribute_separator", ":"),
            ("timestamp", "t"),
            ("timestamp_format", "mmm dd yyyy HH:MM:SS"),
        ]);
        let (tp, _rx) = parser(&p);
        // ':' inside the IPv6 value means kv has more than two parts: the IPv6 field must be positional.
        let fd = flow(&tp, " s:10.0.0.1 ; d:10.0.0.2;p:80;tcp;t:Jan 02 2020 10:00:00");
        assert_eq!((fd.key.src_ip.as_str(), fd.key.dst_port, fd.key.protocol), ("10.0.0.1", 80, 6));
        // t:Jan 02 2020 10:00:00 splits into "t", "Jan 02 2020 10", "00", "00": not a kv pair.
        assert_now(fd.flow_time);
        // An empty field separator splits into characters.
        let p = props(&[("src_ip", "1"), ("dst_ip", "1"), ("dst_port", "2"), ("protocol", "3"), ("field_separator", "")]);
        let (tp, _rx) = parser(&p);
        assert_eq!(discard(&tp, "x56"), "invalid source IP: x");
    }

    #[test]
    fn garbage_input_never_panics() {
        let configs = [
            example(),
            with(example(), &[("field_separator", ""), ("attribute_separator", "")]),
            with(example(), &[("timestamp_format", "unix"), ("only_recs", "a || b, =")]),
            with(example(), &[("timestamp", "1, 99, date_time"), ("timestamp_format", "ddd, dd mmm yyyy HH:MM:SS.000 -HHMM")]),
            props(&[("src_ip", "1"), ("dst_ip", "2"), ("dst_port", "3"), ("protocol", "4"), ("timestamp", "5"), ("src_mac", "6")]),
        ];
        let long = "x".repeat(70_000);
        let garbage = [
            "=", "==", "a=b=c", "1 2 3 4 5 6 7 8", "\0\x01\x02", "sip= dip= dport= prot=", "äöü=ß é", "date_time=",
            "date_time=Jan 99 2020 25:61:61", "sip=10.0.0.1 dip=10.0.0.2 dport=1 prot=6 date_time=Jan 02",
            ". . . .", "ZZZZ Z Z00", "-07:00 Z07:00", &long, "9999999999999999999999 1 2 3", "  \t ",
        ];
        for c in &configs {
            let (tp, _rx) = parser(c);
            for g in &garbage {
                let _ = tp.parse_line(g, &pd(""));
            }
        }
        for l in ["Jan 02 2006 15:04:05", "Monday, 02-Jan-06 15:04:05.000 MST", "2006-01-02T15:04:05Z07:00:00", "_2 -070000 .000"] {
            for v in ["", " ", "Z", "-", "+99:99", "Jan", "ChST", "GMT+99", "30 Feb", "\u{1F600}", "2020-01-02T10:00:00.1234567891234Z"] {
                let _ = go_parse(l, v);
            }
        }
    }

    // ---- datagrams, workers, trait ----

    #[test]
    fn datagram_lines_meter_and_sink() {
        let (tp, rx) = parser(&with(example(), &[("only_recs", "prot")]));
        let mut log_invalid = true;
        let data = format!("{REC}\r\n\n   \nsip=10.0.0.1 dip=10.0.0.3\nnot matching\n{}", REC.replace("10.0.0.2", "10.0.0.4"));
        tp.handle_datagram(&pd(&data), &mut log_invalid);
        // Every non-empty line is counted, including ignored and discarded ones.
        assert_eq!(tp.meter.count(), 4);
        let got: Vec<FlowData> = rx.try_iter().collect();
        assert_eq!(got.iter().map(|f| f.key.dst_ip.as_str()).collect::<Vec<_>>(), vec!["10.0.0.2", "10.0.0.4"]);
        assert!(log_invalid);

        // A non-ASCII datagram is dropped whole; the log flag is cleared.
        tp.handle_datagram(&ReceivedDatagram { buf: vec![b'a', 0x80, b'\n'], ..pd("") }, &mut log_invalid);
        assert!(!log_invalid);
        assert_eq!(tp.meter.count(), 4);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn stats_per_datagram() {
        let (tp, _rx) = parser(&example());
        let mut log_invalid = true;
        let bad = "sip=10.0.0.256 dip=10.0.0.2 dport=53 prot=udp";
        tp.handle_datagram(&pd(&format!("{REC}\n{bad}\n")), &mut log_invalid);
        let row = tp.stats().exporters(std::time::SystemTime::now()).remove(0);
        assert_eq!((row.address.as_str(), row.protocols.as_slice()), ("192.0.2.9", [Proto::Text].as_slice()));
        assert_eq!((row.datagrams, row.flows, row.decode_errors), (1, 1, 1));
        // A non-ASCII datagram is one decode error.
        tp.handle_datagram(&ReceivedDatagram { buf: vec![b'a', 0x80], ..pd("") }, &mut log_invalid);
        let c = tp.stats().counters();
        assert_eq!((c.datagrams, c.flows, c.forwarded, c.decode_errors), (2, 1, 1, 2));
    }

    #[test]
    fn parser_trait_and_workers() {
        let (tp, rx) = parser(&example());
        assert_eq!((tp.type_name(), tp.default_port()), ("text", 6514));
        assert!(tp.supports_connector("udp") && tp.supports_connector("tcp") && tp.supports_connector("kafka"));
        let tx = Arc::new(tp).start_workers(2);
        assert_eq!(tx.capacity(), Some(60));
        tx.send(pd(REC)).unwrap();
        let fd = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(fd.key.dst_port, 443);
        drop(tx); // workers exit when the channel closes (divergence)
    }

    #[test]
    fn setup_without_connectors_or_with_bad_only_recs_fails() {
        let (tx, _rx) = crossbeam_channel::unbounded();
        let ctx = ParserContext::new(Meter::new(), FlowSink::new(tx), Arc::new(CollectorStats::default()));
        assert!(!setup(&example(), &[], ctx.clone()));
        assert!(!setup(&with(example(), &[("only_recs", "&&")]), &[], ctx));
    }
}
