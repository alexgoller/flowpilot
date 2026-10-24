//! FlowLink-compatible instance UUID and its `.uuid` file.

use std::io::{ErrorKind, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::secrets::{go_join, go_path_error, go_read};

/// Read `<data_dir>/.uuid` (untrimmed) or generate and write it (mode 0600).
/// Write/read failures are logged and non-fatal; any other stat error yields "" silently.
pub fn load_or_create(data_dir: &str) -> String {
    let p = go_join(data_dir, ".uuid");
    match std::fs::metadata(&p) {
        Err(e) if e.kind() == ErrorKind::NotFound => {
            let id = generate();
            if let Err(err) = write_0600(&p, id.as_bytes()) {
                crate::log_line!("Unable to write FlowPilot UUID:", err);
            }
            id
        }
        // Contents are used untrimmed, as in FlowLink.
        Ok(_) => go_read(&p)
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_else(|err| {
                crate::log_line!("Unable to read FlowPilot UUID:", err);
                String::new()
            }),
        Err(_) => String::new(),
    }
}

/// `os.WriteFile(p, data, 0600)` with Go's error text.
fn write_0600(p: &str, data: &[u8]) -> Result<(), String> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(p)
        .map_err(|e| go_path_error("open", p, &e))?;
    f.write_all(data).map_err(|e| go_path_error("write", p, &e))
}

/// A new instance UUID in FlowLink's non-RFC 4122 layout.
pub fn generate() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as i64);
    layout(nanos / 100, &hardware_addrs())
}

/// FlowLink's layout: 100 ns Unix-epoch timestamp (no Gregorian offset), version nibble 1, bytes 8-9 `00 01`
/// (no variant bits), node = hardware address copied from every interface in index order until one
/// of at least 6 bytes is found (shorter ones are copied partially first, like Go's `copy`).
fn layout(t: i64, hw_addrs: &[Vec<u8>]) -> String {
    let mut u = [0u8; 16];
    u[0..4].copy_from_slice(&(t as u32).to_be_bytes());
    u[4..6].copy_from_slice(&((t >> 32) as u16).to_be_bytes());
    u[6..8].copy_from_slice(&((t >> 48) as u16 | 0x1000).to_be_bytes());
    u[8..10].copy_from_slice(&[0, 1]);
    for hw in hw_addrs {
        let n = hw.len().min(6);
        u[10..10 + n].copy_from_slice(&hw[..n]);
        if hw.len() > 5 {
            break;
        }
    }
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    format!(
        "{}-{}-{}-{}-{}",
        hex(&u[0..4]),
        hex(&u[4..6]),
        hex(&u[6..8]),
        hex(&u[8..10]),
        hex(&u[10..16])
    )
}

/// Go `net.Interfaces()` hardware addresses in interface-index order (Linux: sysfs instead of
/// netlink). Like Go, all-zero addresses (e.g. loopback) and IP-tunnel addresses of IP length are
/// dropped. Other platforms: none, so the node is zeros.
fn hardware_addrs() -> Vec<Vec<u8>> {
    #[cfg(target_os = "linux")]
    {
        let read = |p: std::path::PathBuf| {
            std::fs::read_to_string(p)
                .ok()
                .map(|s| s.trim().to_string())
        };
        let mut ifs: Vec<(u32, Vec<u8>)> = std::fs::read_dir("/sys/class/net")
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let dir = e.path();
                let index = read(dir.join("ifindex"))?.parse().ok()?;
                let kind: u32 = read(dir.join("type"))
                    .and_then(|t| t.parse().ok())
                    .unwrap_or(0);
                let addr = read(dir.join("address")).unwrap_or_default();
                let hw: Vec<u8> = addr
                    .split(':')
                    .filter_map(|h| u8::from_str_radix(h, 16).ok())
                    .collect();
                // ARPHRD_TUNNEL/SIT/IPGRE (IPv4 length), ARPHRD_TUNNEL6/IP6GRE (IPv6 length).
                let tunnel = matches!((hw.len(), kind), (4, 768 | 776 | 778) | (16, 769 | 823));
                let hw = if tunnel || hw.iter().all(|b| *b == 0) {
                    Vec::new()
                } else {
                    hw
                };
                Some((index, hw))
            })
            .collect();
        ifs.sort_by_key(|(i, _)| *i);
        ifs.into_iter().map(|(_, hw)| hw).collect()
    }
    #[cfg(not(target_os = "linux"))]
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn layout_matches_go() {
        let t: i64 = 0x0123_4567_89ab_cdef;
        let mac = vec![0x02, 0x42, 0xac, 0x11, 0x00, 0x02];
        assert_eq!(
            layout(t, &[vec![], mac.clone(), vec![9; 6]]),
            "89abcdef-4567-1123-0001-0242ac110002"
        );
        assert_eq!(layout(t, &[]), "89abcdef-4567-1123-0001-000000000000");
        // A short address is copied, then overwritten by the first >= 6-byte one.
        assert_eq!(
            layout(t, &[vec![0xff; 4]]),
            "89abcdef-4567-1123-0001-ffffffff0000"
        );
        assert_eq!(
            layout(t, &[vec![0xff; 4], mac]),
            "89abcdef-4567-1123-0001-0242ac110002"
        );
    }

    #[test]
    fn generated_format() {
        let id = generate();
        let parts: Vec<&str> = id.split('-').collect();
        assert_eq!(
            parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
            [8, 4, 4, 4, 12],
            "{id}"
        );
        assert!(
            id.chars()
                .all(|c| c == '-' || c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "{id}"
        );
        assert!(parts[2].starts_with('1'));
        assert_eq!(parts[3], "0001");
        // Unix-epoch 100 ns units: the top timestamp bits are small, not RFC 4122 Gregorian.
        let t = (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            / 100) as u64;
        assert_eq!(&parts[2][1..], &format!("{:04x}", (t >> 48) as u16)[1..]);
    }

    #[test]
    fn uuid_file_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_str().unwrap();
        let id = load_or_create(d);
        let p = dir.path().join(".uuid");
        assert_eq!(std::fs::read_to_string(&p).unwrap(), id);
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(load_or_create(d), id);
        // Not trimmed, as in FlowLink.
        std::fs::write(&p, "abc\n").unwrap();
        assert_eq!(load_or_create(&format!("{d}/")), "abc\n");
    }

    #[test]
    fn unwritable_dir_is_not_fatal() {
        let id = load_or_create("/nonexistent-dir-xyz");
        assert_eq!(id.len(), 36);
    }
}
