//! Self-update tests: the whole flow offline against a fake GitHub on a
//! local HTTP server, plus the real-binary CLI surface, plus a gated
//! real-GitHub `--check`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use flate2::Compression;
use flate2::write::GzEncoder;
use sha2::{Digest, Sha256};

const TARGET: &str = "x86_64-unknown-linux-gnu";
const TARBALL: &str = "vwb-x86_64-unknown-linux-gnu.tar.gz";
const NEW_BIN: &[u8] = b"#!/bin/sh\necho new\n";
const OLD_BIN: &[u8] = b"old-binary";

/// A minimal HTTP/1.1 server for the fake GitHub: one thread per
/// connection, answered from a route table of request path -> (status,
/// body); unknown paths get 404. The counter counts requests, so a test
/// can assert how far the flow got.
fn start_server<F>(build: F) -> (String, Arc<AtomicUsize>, std::thread::JoinHandle<()>)
where
    F: FnOnce(&str) -> BTreeMap<String, (u16, Vec<u8>)>,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let routes = Arc::new(build(&base));
    let count = Arc::new(AtomicUsize::new(0));
    let count_for_handle = count.clone();
    let handle = std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            // One thread per connection so a slow client can never wedge
            // the accept loop.
            let routes = routes.clone();
            let count = count_for_handle.clone();
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                loop {
                    buf.clear();
                    let mut head = false;
                    while !head {
                        let mut byte = [0u8; 1];
                        match stream.read(&mut byte) {
                            Ok(0) | Err(_) => return,
                            Ok(_) => {
                                buf.push(byte[0]);
                                head = buf.len() >= 4 && buf.ends_with(b"\r\n\r\n");
                            }
                        }
                    }
                    let path = std::str::from_utf8(&buf)
                        .ok()
                        .and_then(|req| req.lines().next())
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or_default()
                        .to_string();
                    count.fetch_add(1, Ordering::SeqCst);
                    let (status, body) = routes.get(&path).cloned().unwrap_or((404, Vec::new()));
                    let text = if status == 200 { "OK" } else { "Not Found" };
                    let mut msg = format!(
                        "HTTP/1.1 {status} {text}\r\nContent-Length: {}\r\n\r\n",
                        body.len()
                    )
                    .into_bytes();
                    msg.extend_from_slice(&body);
                    if stream.write_all(&msg).is_err() {
                        return;
                    }
                }
            });
        }
    });
    (base, count, handle)
}

/// Pack `entries` as a gzip of a tar, in order. The release packs one bare
/// file at the root, but the updater must reject other shapes too.
fn make_tgz_entries(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::new(6)));
    for (name, content) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        builder.append_data(&mut header, name, *content).unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

/// Pack one entry of an arbitrary tar type (directory, symlink, ...).
fn make_tgz_entry_type(name: &str, entry_type: tar::EntryType) -> Vec<u8> {
    let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::new(6)));
    let mut header = tar::Header::new_gnu();
    header.set_size(0);
    header.set_mode(0o755);
    header.set_entry_type(entry_type);
    header.set_cksum();
    builder.append_data(&mut header, name, &[][..]).unwrap();
    builder.into_inner().unwrap().finish().unwrap()
}

/// The release tarball with the bare executable at the archive root.
fn make_tgz(entry_name: &str, content: &[u8]) -> Vec<u8> {
    make_tgz_entries(&[(entry_name, content)])
}

/// The `sha256:<hex>` digest GitHub reports for `bytes`.
fn digest_of(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("sha256:{:x}", h.finalize())
}

/// The fake GitHub's route table for a release tagged `tag`: the
/// latest-release JSON (digest as given, absent when `None`; the asset
/// URL points back at this server) plus the asset body.
fn release_routes(
    base: &str,
    tag: &str,
    tgz: &[u8],
    digest: Option<String>,
) -> BTreeMap<String, (u16, Vec<u8>)> {
    let digest_field = match digest {
        Some(digest) => format!(",\"digest\":\"{digest}\""),
        None => String::new(),
    };
    let tgz_asset = format!(
        "{{\"name\":\"{TARBALL}\",\"browser_download_url\":\"{base}/dl/pkg\"{digest_field}}}"
    );
    let json = format!("{{\"tag_name\":\"{tag}\",\"assets\":[{tgz_asset}]}}");
    let mut routes = BTreeMap::new();
    routes.insert(
        "/repos/owner/repo/releases/latest".to_string(),
        (200, json.into_bytes()),
    );
    routes.insert("/dl/pkg".to_string(), (200, tgz.to_vec()));
    routes
}

/// The `Config` every offline test shares: fake exe and cache dir under
/// `dir`, the fake repo on `api_base`, the fixed x86_64-gnu target
/// regardless of host.
fn config(dir: &Path, api_base: &str) -> vwb::update::Config {
    vwb::update::Config {
        api_base: api_base.to_string(),
        repo: "owner/repo".to_string(),
        current: "0.4.1".to_string(),
        exe: dir.join("vwb"),
        cache_dir: dir.join("cache"),
        target: TARGET.to_string(),
    }
}

#[test]
fn update_check_reports_without_installing() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("vwb"), OLD_BIN).unwrap();
    let tgz = make_tgz("vwb", NEW_BIN);
    let (base, count, _h) =
        start_server(|base| release_routes(base, "v9.9.9", &tgz, Some(digest_of(&tgz))));
    let cfg = config(dir.path(), &base);

    let report = vwb::update::run_with(true, &cfg).unwrap();
    assert_eq!(report.latest, "v9.9.9");
    assert!(report.update_available);
    assert!(!report.updated);
    // Check-only: one API call, no download, nothing on disk.
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert_eq!(fs::read(cfg.exe).unwrap(), OLD_BIN);
    assert!(!cfg.cache_dir.exists());
}

#[test]
fn update_installs_and_cleans_its_scratch() {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("vwb");
    fs::write(&exe, OLD_BIN).unwrap();
    let tgz = make_tgz("vwb", NEW_BIN);
    let (base, count, _h) =
        start_server(|base| release_routes(base, "v9.9.9", &tgz, Some(digest_of(&tgz))));
    let cfg = config(dir.path(), &base);

    let report = vwb::update::run_with(false, &cfg).unwrap();
    assert!(report.updated && report.update_available);
    assert_eq!(report.latest, "v9.9.9");
    // The path was resolved before the rename; it must not be re-resolved
    // afterwards (the running inode is unlinked by then).
    assert_eq!(report.exe, exe);
    // The executable now carries the release bytes...
    assert_eq!(fs::read(&exe).unwrap(), NEW_BIN);
    // ...and the cache directory is scratch-only: only the install-lock
    // marker rests (the `flock` is released at install end, the file
    // remains).
    assert_eq!(common::list_dir(&cfg.cache_dir), vec!["update.lock"]);
    // ...with no scratch file left next to the executable.
    assert_eq!(common::list_dir(dir.path()), vec!["cache", "vwb"]);
    // Requests: release JSON, then tarball; the digest rides on the JSON,
    // no separate hash download.
    assert_eq!(count.load(Ordering::SeqCst), 2);
}

#[test]
fn up_to_date_downloads_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("vwb");
    fs::write(&exe, OLD_BIN).unwrap();
    let tgz = make_tgz("vwb", NEW_BIN);
    let (base, count, _h) =
        start_server(|base| release_routes(base, "v0.4.1", &tgz, Some(digest_of(&tgz))));
    let cfg = config(dir.path(), &base);

    let report = vwb::update::run_with(false, &cfg).unwrap();
    assert!(!report.updated && !report.update_available);
    // "Up to date" is decided from the release tag alone: one API call.
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert_eq!(fs::read(&exe).unwrap(), OLD_BIN);
    assert!(!cfg.cache_dir.exists());
}

#[test]
fn a_prerelease_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("vwb");
    fs::write(&exe, OLD_BIN).unwrap();
    let tgz = make_tgz("vwb", NEW_BIN);
    let (base, count, _h) =
        start_server(|base| release_routes(base, "v9.9.9-rc.1", &tgz, Some(digest_of(&tgz))));
    let cfg = config(dir.path(), &base);

    let err = vwb::update::run_with(false, &cfg).unwrap_err().to_string();
    assert!(err.contains("prerelease"), "{err}");
    // Refused before the lock: one API call, nothing downloaded or written.
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert_eq!(fs::read(&exe).unwrap(), OLD_BIN);
    assert!(!cfg.cache_dir.exists());
}

#[test]
fn build_metadata_is_not_a_newer_version() {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("vwb");
    fs::write(&exe, OLD_BIN).unwrap();
    let tgz = make_tgz("vwb", NEW_BIN);
    let (base, count, _h) =
        start_server(|base| release_routes(base, "v0.4.1+build.7", &tgz, Some(digest_of(&tgz))));
    let cfg = config(dir.path(), &base);

    // The tag has the same precedence as the running 0.4.1: SemVer ignores
    // build metadata, so this is "up to date", not an update.
    let report = vwb::update::run_with(false, &cfg).unwrap();
    assert!(!report.update_available && !report.updated);
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert_eq!(fs::read(&exe).unwrap(), OLD_BIN);
    assert!(!cfg.cache_dir.exists());
}

#[test]
fn a_older_release_is_never_a_downgrade() {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("vwb");
    fs::write(&exe, OLD_BIN).unwrap();
    let tgz = make_tgz("vwb", NEW_BIN);
    let (base, count, _h) =
        start_server(|base| release_routes(base, "v0.4.0", &tgz, Some(digest_of(&tgz))));
    let cfg = config(dir.path(), &base);

    let report = vwb::update::run_with(false, &cfg).unwrap();
    assert!(!report.updated && !report.update_available);
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert_eq!(fs::read(&exe).unwrap(), OLD_BIN);
}

#[test]
fn a_corrupt_hash_fails_before_any_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("vwb");
    fs::write(&exe, OLD_BIN).unwrap();
    let tgz = make_tgz("vwb", NEW_BIN);
    // GitHub reports a digest that matches nothing.
    let corrupt = format!("sha256:{}", "0".repeat(64));
    let (base, _count, _h) =
        start_server(|base| release_routes(base, "v9.9.9", &tgz, Some(corrupt)));
    let cfg = config(dir.path(), &base);

    let err = vwb::update::run_with(false, &cfg).unwrap_err().to_string();
    assert!(err.contains("sha256 mismatch"), "{err}");
    // Nothing was replaced or cached: only the empty scratch dir and the
    // lock marker rest.
    assert_eq!(fs::read(&exe).unwrap(), OLD_BIN);
    assert_eq!(
        common::list_dir(&cfg.cache_dir),
        vec!["update", "update.lock"]
    );
}

#[test]
fn a_missing_digest_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("vwb");
    fs::write(&exe, OLD_BIN).unwrap();
    let tgz = make_tgz("vwb", NEW_BIN);
    let (base, count, _h) = start_server(|base| release_routes(base, "v9.9.9", &tgz, None));
    let cfg = config(dir.path(), &base);

    let err = vwb::update::run_with(false, &cfg).unwrap_err().to_string();
    assert!(err.contains("no digest"), "{err}");
    // No digest to verify against: nothing is downloaded, one API call
    // total.
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert_eq!(fs::read(&exe).unwrap(), OLD_BIN);
}

#[test]
fn a_foreign_tar_entry_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("vwb");
    fs::write(&exe, OLD_BIN).unwrap();
    let tgz = make_tgz("evil/sub", NEW_BIN);
    let (base, _count, _h) =
        start_server(|base| release_routes(base, "v9.9.9", &tgz, Some(digest_of(&tgz))));
    let cfg = config(dir.path(), &base);

    let err = vwb::update::run_with(false, &cfg).unwrap_err().to_string();
    assert!(err.contains("evil/sub"), "{err}");
    // The verified tarball stays in the scratch dir (a real, verified
    // artifact); the executable was never touched.
    assert_eq!(
        common::list_dir(&cfg.cache_dir),
        vec!["update", "update.lock"]
    );
    assert_eq!(
        common::list_dir(&cfg.cache_dir.join("update")),
        vec![TARBALL]
    );
    assert_eq!(fs::read(&exe).unwrap(), OLD_BIN);
}

#[test]
fn a_non_regular_tar_entry_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("vwb");
    fs::write(&exe, OLD_BIN).unwrap();
    let tgz = make_tgz_entry_type("vwb", tar::EntryType::Directory);
    let (base, _count, _h) =
        start_server(|base| release_routes(base, "v9.9.9", &tgz, Some(digest_of(&tgz))));
    let cfg = config(dir.path(), &base);

    let err = vwb::update::run_with(false, &cfg).unwrap_err().to_string();
    assert!(err.contains("not a regular file"), "{err}");
    assert_eq!(fs::read(&exe).unwrap(), OLD_BIN);
}

#[test]
fn duplicate_tar_entries_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("vwb");
    fs::write(&exe, OLD_BIN).unwrap();
    let tgz = make_tgz_entries(&[("vwb", NEW_BIN), ("vwb", NEW_BIN)]);
    let (base, _count, _h) =
        start_server(|base| release_routes(base, "v9.9.9", &tgz, Some(digest_of(&tgz))));
    let cfg = config(dir.path(), &base);

    let err = vwb::update::run_with(false, &cfg).unwrap_err().to_string();
    assert!(err.contains("more than one entry"), "{err}");
    assert_eq!(fs::read(&exe).unwrap(), OLD_BIN);
}

#[test]
fn an_empty_tarball_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("vwb");
    fs::write(&exe, OLD_BIN).unwrap();
    let tgz = make_tgz_entries(&[]);
    let (base, _count, _h) =
        start_server(|base| release_routes(base, "v9.9.9", &tgz, Some(digest_of(&tgz))));
    let cfg = config(dir.path(), &base);

    let err = vwb::update::run_with(false, &cfg).unwrap_err().to_string();
    assert!(err.contains("empty"), "{err}");
    assert_eq!(fs::read(&exe).unwrap(), OLD_BIN);
}

#[test]
fn a_missing_asset_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("vwb");
    fs::write(&exe, OLD_BIN).unwrap();
    let (base, count, _h) = start_server(|base| {
        let json = format!(
            "{{\"tag_name\":\"v9.9.9\",\"assets\":[{{\"name\":\"other.tar.gz\",\"browser_download_url\":\"{base}/dl/pkg\"}}]}}"
        );
        BTreeMap::from([(
            "/repos/owner/repo/releases/latest".to_string(),
            (200, json.into_bytes()),
        )])
    });
    let cfg = config(dir.path(), &base);

    let err = vwb::update::run_with(false, &cfg).unwrap_err().to_string();
    assert!(err.contains("is missing"), "{err}");
    assert!(err.contains("other.tar.gz"), "{err}");
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert_eq!(fs::read(&exe).unwrap(), OLD_BIN);
}

#[test]
fn the_api_rate_limit_is_reported() {
    for status in [403u16, 429u16] {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("vwb");
        fs::write(&exe, OLD_BIN).unwrap();
        let (base, count, _h) = start_server(move |_base| {
            BTreeMap::from([(
                "/repos/owner/repo/releases/latest".to_string(),
                (status, Vec::new()),
            )])
        });
        let cfg = config(dir.path(), &base);

        let err = vwb::update::run_with(false, &cfg).unwrap_err().to_string();
        assert!(err.contains("rate limit"), "HTTP {status}: {err}");
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert_eq!(fs::read(&exe).unwrap(), OLD_BIN);
        assert!(!cfg.cache_dir.exists());
    }
}

#[test]
fn no_releases_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("vwb"), OLD_BIN).unwrap();
    let (base, count, _h) = start_server(|_base: &str| {
        BTreeMap::from([(
            "/repos/owner/repo/releases/latest".to_string(),
            (404, Vec::new()),
        )])
    });
    let cfg = config(dir.path(), &base);

    let err = vwb::update::run_with(false, &cfg).unwrap_err().to_string();
    assert!(err.contains("no releases"), "{err}");
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[test]
fn concurrent_updates_converge() {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("vwb");
    fs::write(&exe, OLD_BIN).unwrap();
    let tgz = make_tgz("vwb", NEW_BIN);
    let (base, _count, _h) =
        start_server(|base| release_routes(base, "v9.9.9", &tgz, Some(digest_of(&tgz))));
    let cfg = Arc::new(config(dir.path(), &base));

    let mut handles = Vec::new();
    for _ in 0..2 {
        let cfg = Arc::clone(&cfg);
        handles.push(std::thread::spawn(move || {
            vwb::update::run_with(false, &cfg).unwrap()
        }));
    }
    for h in handles {
        assert!(h.join().unwrap().updated);
    }
    assert_eq!(fs::read(&exe).unwrap(), NEW_BIN);
    // Both runs finished: the cache dir holds only the install-lock
    // marker.
    assert_eq!(common::list_dir(&cfg.cache_dir), vec!["update.lock"]);
}

#[test]
fn a_killed_run_scratch_is_swept() {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("vwb");
    fs::write(&exe, OLD_BIN).unwrap();
    let tgz = make_tgz("vwb", NEW_BIN);
    let (base, _count, _h) =
        start_server(|base| release_routes(base, "v9.9.9", &tgz, Some(digest_of(&tgz))));
    let cfg = config(dir.path(), &base);

    // Leftovers of a killed run in the scratch dir and the executable's
    // dir: every scratch file is dead at install start and is removed.
    let scratch = cfg.cache_dir.join("update");
    let stale_cache = scratch.join("vwb.DeAdBeEf.part");
    let stale_exe = exe.parent().unwrap().join("vwb.BeEfDeAd.part");
    fs::create_dir_all(&scratch).unwrap();
    fs::write(&stale_cache, b"stale-cache").unwrap();
    fs::write(&stale_exe, b"stale-exe").unwrap();

    let report = vwb::update::run_with(false, &cfg).unwrap();
    assert!(report.updated);
    assert!(!stale_cache.exists());
    assert!(!stale_exe.exists());
}

#[test]
fn cli_update_rejects_backup_options() {
    // Backup options live on the `backup` subcommand, so a copy-pasted
    // backup flag is unknown at every level of an `update` invocation:
    // clap rejects it naming the flag, before any network work, in both
    // the `vwb update <flag>` and `vwb <flag> update` forms.
    for flags in [
        ["update", "--source-type", "local"],
        ["--source-type", "local", "update"],
    ] {
        let out = std::process::Command::new(common::bin())
            .args(flags)
            .output()
            .unwrap();
        assert!(!out.status.success(), "{flags:?}");
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        assert!(stderr.contains("--source-type"), "{stderr}");
    }
}

#[test]
fn cli_help_lists_update() {
    let out = std::process::Command::new(common::bin())
        .arg("--help")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(stdout.contains("update"), "{stdout}");
}

#[test]
fn cli_update_check_against_github() {
    // Gated like the S3 e2e: without VWB_UPDATE_TEST the test stays offline.
    if std::env::var("VWB_UPDATE_TEST").is_err() {
        return;
    }
    let out = std::process::Command::new(common::bin())
        .arg("update")
        .arg("--check")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        stdout.starts_with("update available: v") || stdout.starts_with("up to date (v"),
        "{stdout:?}"
    );
}
