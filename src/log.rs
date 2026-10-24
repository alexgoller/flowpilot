//! Logging and process-wide flags.
//!
//! Every line goes to stdout as `<local ts> <operands joined by one space>\n`, serialised by a
//! global lock, in FlowLink's log format (Go `fmt.Fprintln` operand spacing).

use std::cell::Cell;
use std::fmt::Display;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

/// `-debug` flag.
pub static DEBUG: AtomicBool = AtomicBool::new(false);
/// Set by the signal handler.
pub static SHUTDOWN: AtomicBool = AtomicBool::new(false);

static LOG_LOCK: Mutex<()> = Mutex::new(());

pub fn debug() -> bool {
    DEBUG.load(Ordering::Relaxed)
}

pub fn shutdown() -> bool {
    SHUTDOWN.load(Ordering::Relaxed)
}

/// Log line: timestamp `2006-01-02T15:04:05.000000-07:00` (local time) plus the operands.
pub fn write_line(parts: &[String]) {
    let ts = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.6f%:z");
    let line = format!("{} {}\n", ts, parts.join(" "));
    let _guard = LOG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(line.as_bytes());
    let _ = out.flush();
}

/// `log_line(a, b, ...)`: always printed.
#[macro_export]
macro_rules! log_line {
    ($($a:expr),* $(,)?) => {
        $crate::log::write_line(&[$(format!("{}", $a)),*])
    };
}

/// Debug log line: printed only with `-debug`.
#[macro_export]
macro_rules! debug_log {
    ($($a:expr),* $(,)?) => {
        if $crate::log::debug() {
            $crate::log_line!($($a),*)
        }
    };
}

thread_local! {
    /// Decode errors on this thread since the last `take_decode_errors` (stats: one parser worker decodes one
    /// datagram at a time, so the parsers take it before and after each datagram).
    static DECODE_ERRORS: Cell<u64> = const { Cell::new(0) };
}

/// Count one decode error for the datagram this thread is decoding.
pub fn note_decode_error() {
    DECODE_ERRORS.with(|c| c.set(c.get().wrapping_add(1)));
}

/// Decode errors noted on this thread since the last call, resetting the count.
pub fn take_decode_errors() -> u64 {
    DECODE_ERRORS.with(|c| c.replace(0))
}

/// Logs `Error: <err>` and returns true when `err` is an error. In debug mode it logs `Exiting.` and
/// exits 1.
pub fn check_error<E: Display>(err: Option<E>) -> bool {
    let Some(e) = err else { return false };
    // Only parser threads consume this count; on other threads it is never read (harmless).
    note_decode_error();
    crate::log_line!("Error:", e);
    if debug() {
        crate::log_line!("Exiting.");
        std::process::exit(1);
    }
    true
}

/// Go `%v` of a slice: `[a b c]`.
pub fn go_slice<T: Display>(items: &[T]) -> String {
    let parts: Vec<String> = items.iter().map(|i| i.to_string()).collect();
    format!("[{}]", parts.join(" "))
}

/// Bytes as decimal (`%v`) or hex text joined by `delim`, as in FlowLink's debug output.
pub fn join_bytes(a: &[u8], delim: &str, as_hex: bool) -> String {
    let s = if as_hex {
        a.iter().map(|b| format!("{b:02X} ")).collect::<String>()
    } else {
        go_slice(a)
    };
    let joined = s.split_whitespace().collect::<Vec<_>>().join(delim);
    let cut: Vec<char> = "[]".chars().chain(delim.chars()).collect();
    joined.trim_matches(|c| cut.contains(&c)).to_string()
}

/// Go `hex.Dump` format.
/// Ported from the Go standard library (`encoding/hex`), BSD-3-Clause, Copyright (c) 2009 The Go Authors. See NOTICE.
pub fn hex_dump(data: &[u8]) -> String {
    let mut out = String::new();
    for (row, chunk) in data.chunks(16).enumerate() {
        out.push_str(&format!("{:08x} ", row * 16));
        for i in 0..16 {
            if i == 8 {
                out.push(' ');
            }
            match chunk.get(i) {
                Some(b) => out.push_str(&format!(" {b:02x}")),
                None => out.push_str("   "),
            }
        }
        out.push_str("  |");
        for &b in chunk {
            out.push(if (32..=126).contains(&b) { b as char } else { '.' });
        }
        out.push_str("|\n");
    }
    out
}

/// Hex dump of `data` under `title`: debug only.
pub fn debug_hex(title: &str, data: &[u8]) {
    if !debug() {
        return;
    }
    let hdr = if title.is_empty() { "\n".to_string() } else { format!("{title}:\n") };
    crate::log_line!(format!("{hdr}{}", hex_dump(data)));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_bytes_formats_macs_in_upper_hex() {
        assert_eq!(join_bytes(&[0x01, 0x00, 0x5e, 0xaa, 0xbb, 0xcc], ":", true), "01:00:5E:AA:BB:CC");
        assert_eq!(join_bytes(&[1, 2, 3], ".", false), "1.2.3");
        assert_eq!(join_bytes(&[], ":", true), "");
    }

    #[test]
    fn hex_dump_matches_go() {
        let d: Vec<u8> = (0x41..0x52).collect();
        assert_eq!(
            hex_dump(&d),
            "00000000  41 42 43 44 45 46 47 48  49 4a 4b 4c 4d 4e 4f 50  |ABCDEFGHIJKLMNOP|\n\
             00000010  51                                                |Q|\n"
        );
    }

    #[test]
    fn go_slice_formats() {
        assert_eq!(go_slice(&["a", "b"]), "[a b]");
        assert_eq!(go_slice::<String>(&[]), "[]");
    }
}
