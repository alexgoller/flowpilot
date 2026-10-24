//! Persistence of the reported IPs: every IP ever announced as new.
//!
//! Divergence (docs/differences-from-flowlink.md, "Reported IPs are stored as JSON"): FlowLink appends a Go
//! gob stream to
//! `<dir>/<pce_addr>-org<org>-reported_ips.dat` without truncating or closing it. We store a
//! sorted JSON array in `...-reported_ips.json`, written atomically, and import FlowLink's
//! `.dat` file once when no JSON file exists yet.

use std::collections::HashSet;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub struct ReportedIpsStore {
    json: PathBuf,
    legacy: PathBuf,
}

impl ReportedIpsStore {
    pub fn new(dir: &Path, pce_addr: &str, org_id: i32) -> Self {
        let base = format!("{pce_addr}-org{org_id}-reported_ips");
        Self { json: dir.join(format!("{base}.json")), legacy: dir.join(format!("{base}.dat")) }
    }

    /// Load the set; errors are ignored, as in FlowLink.
    pub fn load(&self) -> HashSet<String> {
        if let Ok(data) = fs::read(&self.json) {
            return serde_json::from_slice::<Vec<String>>(&data).map(|v| v.into_iter().collect()).unwrap_or_default();
        }
        fs::read(&self.legacy).ok().and_then(|d| decode_gob_string_set(&d)).unwrap_or_default()
    }

    pub fn save(&self, ips: &HashSet<String>) -> io::Result<()> {
        let mut sorted: Vec<&String> = ips.iter().collect();
        sorted.sort();
        let tmp = self.json.with_extension("json.tmp");
        let mut f = open_0640(&tmp)?;
        f.write_all(&serde_json::to_vec(&sorted)?)?;
        f.sync_all()?;
        fs::rename(&tmp, &self.json)
    }
}

pub(crate) fn open_0640(path: &Path) -> io::Result<fs::File> {
    let mut o = fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o640);
    o.open(path)
}

/// Decode a gob stream holding one `map[string]struct{}` (the only value FlowLink writes).
/// Message = uint length, int type id, payload. Negative ids are type definitions (skipped);
/// the value message is: singleton delta 0, uint count, count × (uint len + bytes, struct end 0).
pub fn decode_gob_string_set(mut data: &[u8]) -> Option<HashSet<String>> {
    let mut out = HashSet::new();
    while !data.is_empty() {
        let len = gob_uint(&mut data)? as usize;
        let mut msg = data.get(..len)?;
        data = &data[len..];
        let id = gob_uint(&mut msg)?;
        let type_id = if id & 1 == 1 { !(id >> 1) as i64 } else { (id >> 1) as i64 };
        if type_id < 0 {
            continue;
        }
        if gob_uint(&mut msg)? != 0 {
            return None;
        }
        for _ in 0..gob_uint(&mut msg)? {
            let n = gob_uint(&mut msg)? as usize;
            let s = msg.get(..n)?;
            out.insert(String::from_utf8(s.to_vec()).ok()?);
            msg = &msg[n..];
            if gob_uint(&mut msg)? != 0 {
                return None;
            }
        }
    }
    Some(out)
}

/// gob unsigned integer: < 128 is one byte, otherwise a negated byte count then big-endian bytes.
fn gob_uint(data: &mut &[u8]) -> Option<u64> {
    let (&b, rest) = data.split_first()?;
    *data = rest;
    if b < 0x80 {
        return Some(b as u64);
    }
    let n = (!b).wrapping_add(1) as usize;
    if n > 8 {
        return None;
    }
    let bytes = data.get(..n)?;
    *data = &data[n..];
    Some(bytes.iter().fold(0u64, |acc, &x| acc << 8 | x as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_go_gob_fixtures() {
        let set = decode_gob_string_set(include_bytes!("../tests/fixtures/reported_ips.gob")).unwrap();
        let mut v: Vec<_> = set.into_iter().collect();
        v.sort();
        assert_eq!(v, ["10.0.0.1", "192.168.1.20", "2001:db8::5"]);
        assert!(decode_gob_string_set(include_bytes!("../tests/fixtures/reported_ips_empty.gob")).unwrap().is_empty());
        assert!(decode_gob_string_set(&[0x05, 0xff]).is_none());
    }

    #[test]
    fn json_round_trip_and_legacy_import() {
        let dir = tempfile::tempdir().unwrap();
        let store = ReportedIpsStore::new(dir.path(), "pce.example.com:8443", 1);
        assert!(store.load().is_empty());
        fs::write(dir.path().join("pce.example.com:8443-org1-reported_ips.dat"), include_bytes!("../tests/fixtures/reported_ips.gob")).unwrap();
        let mut ips = store.load();
        assert_eq!(ips.len(), 3);
        ips.insert("10.9.9.9".into());
        store.save(&ips).unwrap();
        assert_eq!(store.load(), ips);
    }
}
