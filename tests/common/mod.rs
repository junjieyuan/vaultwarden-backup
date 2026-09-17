//! Shared helpers for the integration test crates: sample-data fixtures,
//! archive inspection, and gpg keyring utilities. Included with
//! `mod common;` — the subdirectory keeps this module from being treated as
//! a test target of its own. Each test crate only uses a subset of these,
//! so dead_code is allowed here.

#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use flate2::read::GzDecoder;
use rusqlite::Connection;
use tar::Archive;

pub const DB: &str = "db.sqlite3";

/// Build a realistic vaultwarden data directory under `root`: a WAL-mode
/// database plus the usual files and directories, with `db.sqlite3-wal`
/// actually present on disk.
pub fn make_sample_source(root: &Path) -> PathBuf {
    let src = root.join("data");
    fs::create_dir_all(src.join("attachments/u1")).unwrap();
    fs::create_dir_all(src.join("sends/s1")).unwrap();
    fs::create_dir_all(src.join("icon_cache")).unwrap();

    let conn = Connection::open(src.join(DB)).unwrap();
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         CREATE TABLE notes(id INTEGER PRIMARY KEY, body TEXT);
         INSERT INTO notes(body) VALUES ('one');",
    )
    .unwrap();
    // Make sure the WAL exists on disk (uncommitted to a checkpoint yet).
    conn.execute_batch("CREATE INDEX idx_notes_body ON notes(body);")
        .unwrap();
    drop(conn);

    let att = src.join("attachments/u1/file.txt");
    fs::write(&att, "attachment-content\n").unwrap();
    let send = src.join("sends/s1/send.txt");
    fs::write(&send, b"send-bytes-\x00\x01\x02").unwrap();
    let cfg = src.join("config.json");
    fs::write(&cfg, "{\"AdminToken\":\"secret\"}").unwrap();
    let key = src.join("rsa_key.pem");
    fs::write(&key, "PRIVATE KEY DATA").unwrap();
    let pub_der = src.join("rsa_key.pub.der");
    fs::write(&pub_der, [0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
    let icon = src.join("icon_cache/a.png");
    fs::write(&icon, [0x89, b'P', b'N', b'G']).unwrap();

    src
}

/// Decompress the .tgz and map archive-entry name -> contents.
pub fn unpack(tgz: &Path) -> BTreeMap<String, Vec<u8>> {
    let bytes = fs::read(tgz).unwrap();
    let mut entries = BTreeMap::new();
    let mut decoded = Vec::new();
    GzDecoder::new(&bytes[..])
        .read_to_end(&mut decoded)
        .unwrap();
    for e in Archive::new(&decoded[..]).entries().unwrap() {
        let mut e = e.unwrap();
        let name = e.path().unwrap().to_string_lossy().to_string();
        let mut buf = Vec::new();
        e.read_to_end(&mut buf).unwrap();
        entries.insert(name, buf);
    }
    entries
}

pub fn list_dir(d: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(d)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    v.sort();
    v
}

/// Primary-key fingerprint of the single key in `GNUPGHOME`.
pub fn fingerprint_of(gnupg_home: PathBuf) -> anyhow::Result<String> {
    let out = std::process::Command::new("gpg")
        .args(["--list-keys", "--with-colons"])
        .env("GNUPGHOME", gnupg_home)
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let fpr = stdout
        .lines()
        .filter(|l| l.starts_with("fpr:"))
        // fpr: line, 0-based field 9: the 40-hex-digit fingerprint.
        .map(|l| l.split(':').nth(9).unwrap_or_default().to_string())
        .find(|f| !f.is_empty())
        .unwrap_or_else(|| panic!("no fingerprint in keygen output; stdout: {stdout:?}"));
    Ok(fpr)
}

/// Fingerprints of all keys in `GNUPGHOME`.
pub fn list_fprs(gnupg_home: &Path) -> Vec<String> {
    let out = std::process::Command::new("gpg")
        .args(["--list-keys", "--with-colons"])
        .env("GNUPGHOME", gnupg_home)
        .output()
        .unwrap();
    assert!(out.status.success());
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.starts_with("fpr:"))
        .map(|l| l.split(':').nth(9).unwrap_or_default().to_string())
        .filter(|f| !f.is_empty())
        .collect()
}

/// Path to the built binary. CARGO_BIN_EXE_<name> is set at compile time of
/// every integration-test crate, so it is read with env!, not
/// std::env::var.
pub fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_vaultwarden-backup"))
}
