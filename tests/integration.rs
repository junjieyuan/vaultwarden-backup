//! End-to-end: sample data dir -> backup -> unpack -> assert snapshot
//! semantics and byte exactness; the CLI tests run the real binary.
//!
//! The CLI is long-option-only and per-type: `--source-type local` pairs
//! with `--local-source`, `--target-type local` pairs with one or more
//! `--local-target` values (repeatable, comma-separated).

// `unwrap`/`expect` are denied for production code (Cargo.toml `[lints]`)
// but are idiomatic in tests, so this whole file opts out.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::Result;
use flate2::read::GzDecoder;
use rusqlite::Connection;
use tar::Archive;
use vaultwarden_backup::{DatabaseType, EncryptionType};

const DB: &str = "db.sqlite3";

// ---------------------------------------------------------------- sample data

fn make_sample_source(root: &Path) -> PathBuf {
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

// ------------------------------------------------------------------ tar utils

/// Decompress the .tgz and map archive-entry name -> contents.
fn unpack(tgz: &Path) -> BTreeMap<String, Vec<u8>> {
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

fn list_dir(d: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(d)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    v.sort();
    v
}

// ---------------------------------------------------------------- gpg utils

/// Primary-key fingerprint of the single key in `GNUPGHOME`.
fn fingerprint_of(gnupg_home: std::path::PathBuf) -> anyhow::Result<String> {
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
fn list_fprs(gnupg_home: &Path) -> Vec<String> {
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

// ------------------------------------------------------------------ tests

#[test]
fn happy_path_snapshot_and_files() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let src = make_sample_source(root);
    let target = root.join("backups");

    // Record the rows present at backup time; then add more rows to the
    // live source to prove the snapshot does not include later writes.
    let src_db = src.join(DB);
    {
        let conn = Connection::open(&src_db).unwrap();
        conn.execute("INSERT INTO notes(body) VALUES ('pre-backup')", ())
            .unwrap();
        drop(conn);
    }

    let delivered = vaultwarden_backup::run(
        src.clone(),
        vec![target.clone()],
        "vaultwarden-backup".into(),
        DatabaseType::Sqlite,
        EncryptionType::None,
        Vec::new(),
    )
    .unwrap();

    assert_eq!(delivered.len(), 1, "one path per local target");
    let out = &delivered[0];
    assert_eq!(out.parent().unwrap(), &target);

    let fname = out.file_name().unwrap().to_string_lossy().to_string();
    assert!(fname.starts_with("vaultwarden-backup-"), "{fname}");
    assert!(fname.ends_with(".tgz"), "{fname}");
    let ts = &fname["vaultwarden-backup-".len()..fname.len() - 4];
    assert_eq!(ts.len(), 20, "{ts}");
    assert!(ts.chars().nth(4).is_some_and(|c| c == '-'), "{ts}");
    assert!(ts.chars().nth(10).is_some_and(|c| c == 'T'), "{ts}");
    assert!(ts.ends_with('Z'), "{ts}");

    let entries = unpack(out);

    let names: Vec<String> = entries.keys().cloned().collect();
    for expected in [
        "db.sqlite3",
        "config.json",
        "rsa_key.pem",
        "rsa_key.pub.der",
        "icon_cache/a.png",
        "attachments/u1/file.txt",
        "sends/s1/send.txt",
    ] {
        assert!(
            entries.contains_key(expected),
            "missing {expected} in {names:?}"
        );
    }
    assert!(
        !entries
            .keys()
            .any(|n| n == "db.sqlite3-wal" || n == "db.sqlite3-shm")
    );

    assert_eq!(entries["config.json"], b"{\"AdminToken\":\"secret\"}");
    assert_eq!(entries["rsa_key.pem"], b"PRIVATE KEY DATA");
    assert_eq!(entries["rsa_key.pub.der"], [0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(entries["icon_cache/a.png"], [0x89, b'P', b'N', b'G']);
    assert_eq!(entries["attachments/u1/file.txt"], b"attachment-content\n");
    assert_eq!(entries["sends/s1/send.txt"], b"send-bytes-\x00\x01\x02");

    // The db.sqlite3 entry must open as a standalone snapshot: rows as of
    // backup time, no post-backup writes.
    let snap_bytes = entries["db.sqlite3"].clone();
    let snap_db = root.join("restored-snap.sqlite3");
    fs::write(&snap_db, snap_bytes).unwrap();
    let conn = Connection::open(&snap_db).unwrap();
    let rows: Vec<String> = {
        let mut s = conn
            .prepare("SELECT body FROM notes ORDER BY body")
            .unwrap();
        s.query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };
    assert_eq!(rows, vec!["one", "pre-backup"], "snapshot rows {rows:?}");

    let conn = Connection::open(&src_db).unwrap();
    conn.execute("INSERT INTO notes(body) VALUES ('post-backup')", ())
        .unwrap();
    drop(conn);

    let conn = Connection::open(&snap_db).unwrap();
    let n_post: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM notes WHERE body = 'post-backup'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n_post, 0, "post-backup row must not be in the snapshot");

    assert!(
        !list_dir(&target).iter().any(|n| n.contains(".part")),
        "part file left behind"
    );
}

#[test]
fn multiple_local_targets_all_delivered() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let src = make_sample_source(root);
    let t1 = root.join("backups-a");
    let t2 = root.join("backups-b");

    let delivered = vaultwarden_backup::run(
        src,
        vec![t1.clone(), t2.clone()],
        "multi".into(),
        DatabaseType::Sqlite,
        EncryptionType::None,
        Vec::new(),
    )
    .unwrap();

    assert_eq!(delivered.len(), 2, "one path per local target, in order");
    assert_eq!(delivered[0].parent().unwrap(), &t1);
    assert_eq!(delivered[1].parent().unwrap(), &t2);
    for p in &delivered {
        assert!(p.exists(), "{} missing", p.display());
    }
    // Independent copies of the same bytes.
    assert_eq!(
        fs::read(&delivered[0]).unwrap(),
        fs::read(&delivered[1]).unwrap()
    );
    for t in [&t1, &t2] {
        assert!(
            !list_dir(t).iter().any(|n| n.contains(".part")),
            "part file left behind in {}",
            t.display()
        );
    }
}

#[test]
fn no_targets_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let src = make_sample_source(tmp.path());
    let err = vaultwarden_backup::run(
        src,
        Vec::new(),
        "n".into(),
        DatabaseType::Sqlite,
        EncryptionType::None,
        Vec::new(),
    )
    .unwrap_err();
    assert!(err.to_string().contains("at least one target"), "{err:?}");
}

#[test]
fn custom_name_prefix_is_used() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let src = make_sample_source(root);
    let target = root.join("out");
    let delivered = vaultwarden_backup::run(
        src,
        vec![target],
        "my-prefix".into(),
        DatabaseType::Sqlite,
        EncryptionType::None,
        Vec::new(),
    )
    .unwrap();
    let fname = delivered[0]
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();
    assert!(fname.starts_with("my-prefix-"), "{fname}");
    assert!(fname.ends_with(".tgz"));
}

#[test]
fn name_with_slash_fails_before_any_work() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let src = make_sample_source(root);
    let target = root.join("out");
    let err = vaultwarden_backup::run(
        src,
        vec![target.clone()],
        "bad/name".into(),
        DatabaseType::Sqlite,
        EncryptionType::None,
        Vec::new(),
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("name"),
        "error must mention the name problem: {err:?}"
    );
    assert!(
        !target.exists(),
        "nothing may be written on preflight failure"
    );
}

#[test]
fn duplicate_target_delivered_once() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let src = make_sample_source(root);

    // The same physical directory via two spellings (one as a symlink): the
    // canonicalized path is identical, so it must be delivered exactly once.
    let target = root.join("out");
    let target_link = root.join("out-link");
    std::os::unix::fs::symlink(&target, &target_link).unwrap();

    let delivered = vaultwarden_backup::run(
        src,
        vec![target.clone(), target_link],
        "dedup".into(),
        DatabaseType::Sqlite,
        EncryptionType::None,
        Vec::new(),
    )
    .unwrap();
    assert_eq!(delivered.len(), 1, "one delivery per physical directory");
    assert_eq!(delivered[0].parent().unwrap(), &target);
    assert_eq!(list_dir(&target).len(), 1, "exactly one archive");
}

#[test]
fn missing_source_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let err = vaultwarden_backup::run(
        tmp.path().join("no-such-dir"),
        vec![tmp.path().join("out")],
        "n".into(),
        DatabaseType::Sqlite,
        EncryptionType::None,
        Vec::new(),
    )
    .unwrap_err();
    assert!(err.to_string().contains("does not exist"));
}

#[test]
fn source_is_file_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let f = tmp.path().join("not-a-dir");
    fs::write(&f, b"x").unwrap();
    let err = vaultwarden_backup::run(
        f,
        vec![tmp.path().join("out")],
        "n".into(),
        DatabaseType::Sqlite,
        EncryptionType::None,
        Vec::new(),
    )
    .unwrap_err();
    assert!(err.to_string().contains("not a directory"));
}

#[test]
fn source_without_db_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("data");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("config.json"), "{}").unwrap();
    let err = vaultwarden_backup::run(
        src,
        vec![tmp.path().join("out")],
        "n".into(),
        DatabaseType::Sqlite,
        EncryptionType::None,
        Vec::new(),
    )
    .unwrap_err();
    // The existence check now lives inside db::backup, so the message is
    // under the backup context; walk the chain instead of the top only.
    assert!(
        err.chain().any(|e| e.to_string().contains("no db.sqlite3")),
        "expected a missing-db error in the chain: {err:?}"
    );
    assert_eq!(
        list_dir(&tmp.path().join("out")),
        Vec::<String>::new(),
        "no archive may exist on failure"
    );
}

#[test]
fn source_and_target_nested_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let src = make_sample_source(tmp.path());
    let err = vaultwarden_backup::run(
        src.clone(),
        vec![src.join("backups")],
        "n".into(),
        DatabaseType::Sqlite,
        EncryptionType::None,
        Vec::new(),
    )
    .unwrap_err();
    assert!(err.to_string().contains("nested"));
}

#[test]
fn live_wal_source_still_backs_up() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let src = make_sample_source(root);
    let src_db = src.join(DB);
    let out = tmp.path().join("out");

    // An uncommitted write txn must neither block the backup nor leak into
    // the snapshot.
    let conn = Connection::open(&src_db).unwrap();
    conn.execute("BEGIN IMMEDIATE", ()).unwrap();
    conn.execute("INSERT INTO notes(body) VALUES ('uncommitted')", ())
        .unwrap();
    let delivered = vaultwarden_backup::run(
        src,
        vec![out],
        "n".into(),
        DatabaseType::Sqlite,
        EncryptionType::None,
        Vec::new(),
    )
    .unwrap();
    conn.execute("ROLLBACK", ()).unwrap();
    drop(conn);

    let entries = unpack(&delivered[0]);
    let snap_db = root.join("snap.sqlite3");
    fs::write(&snap_db, &entries["db.sqlite3"]).unwrap();
    let conn = Connection::open(&snap_db).unwrap();
    let n: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM notes WHERE body = 'uncommitted'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 0);
}

// ---------------------------------------------------------------- CLI tests

fn bin() -> PathBuf {
    // CARGO_BIN_EXE_<name> is set at compile time of the integration test
    // (runtime visibility only since cargo 1.96.1), so read it with env!,
    // not std::env::var.
    PathBuf::from(env!("CARGO_BIN_EXE_vaultwarden-backup"))
}

/// A ready `Command` for a real-binary run with the full long-flag set:
/// `--source-type local` / `--local-source` / `--target-type local` /
/// `--local-target` / `--name` / `--database-type sqlite` /
/// `--encryption-type <encryption_type>` / one `--recipient` per entry.
fn backup_cmd(
    src: &Path,
    target: &Path,
    name: &str,
    encryption_type: &str,
    recipients: &[&str],
) -> std::process::Command {
    let mut cmd = std::process::Command::new(bin());
    cmd.arg("--source-type").arg("local");
    cmd.arg("--local-source").arg(src);
    cmd.arg("--target-type").arg("local");
    cmd.arg("--local-target").arg(target);
    cmd.arg("--name").arg(name);
    cmd.arg("--database-type").arg("sqlite");
    cmd.arg("--encryption-type").arg(encryption_type);
    for r in recipients {
        cmd.arg("--recipient").arg(*r);
    }
    cmd
}

/// The clap-level required options: the type/enum selectors and `--name`.
/// (`--local-source`, `--local-target`, `--recipient` are not clap-required;
/// they are cross-checked against the declared types in preflight.)
fn assert_usage_err(err: &anyhow::Error) {
    let s = err.to_string();
    for word in [
        "--source-type",
        "--target-type",
        "--name",
        "--database-type",
        "--encryption-type",
    ] {
        assert!(s.contains(word), "usage missing {word}:\n{s}");
    }
}

#[test]
fn cli_no_args_fails_listing_required() {
    let out = std::process::Command::new(bin()).output().unwrap();
    assert!(!out.status.success(), "no-args run must fail");
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert_usage_err(&anyhow::anyhow!("{stderr}"));
    assert!(
        stderr.contains("required"),
        "should be a usage error, got: {stderr}"
    );
}

#[test]
fn cli_all_env_vars_succeed() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let src = make_sample_source(root);
    let target = root.join("out");

    let mut cmd = std::process::Command::new(bin());
    cmd.env_clear();
    cmd.env("PATH", std::env::var("PATH").unwrap());
    cmd.env("VWB_SOURCE_TYPE", "local");
    cmd.env("VWB_LOCAL_SOURCE", &src);
    cmd.env("VWB_TARGET_TYPE", "local");
    cmd.env("VWB_LOCAL_TARGET", &target);
    cmd.env("VWB_NAME", "env-run");
    cmd.env("VWB_DATABASE_TYPE", "sqlite");
    cmd.env("VWB_ENCRYPTION_TYPE", "none");
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "one stdout line per target: {stdout:?}");
    let path: PathBuf = lines[0].into();
    assert!(path.exists());
    let fname = path.file_name().unwrap().to_string_lossy().to_string();
    assert!(fname.starts_with("env-run-"), "{fname}");
}

#[test]
fn cli_cli_option_overrides_env() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let src = make_sample_source(root);
    let target = root.join("out");
    let other = root.join("other-out");

    let mut cmd = std::process::Command::new(bin());
    cmd.env_clear();
    cmd.env("PATH", std::env::var("PATH").unwrap());
    cmd.env("VWB_SOURCE_TYPE", "local");
    cmd.env("VWB_LOCAL_SOURCE", &src);
    cmd.env("VWB_TARGET_TYPE", "local");
    cmd.env("VWB_LOCAL_TARGET", &other);
    cmd.env("VWB_NAME", "x");
    cmd.env("VWB_DATABASE_TYPE", "sqlite");
    cmd.env("VWB_ENCRYPTION_TYPE", "none");
    cmd.arg("--local-target").arg(&target); // CLI wins
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let path: PathBuf = stdout.lines().next().unwrap().into();
    assert_eq!(
        path.parent().unwrap(),
        &target,
        "CLI --local-target must override env"
    );
}

#[test]
fn cli_multiple_local_targets_comma_and_repeat() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let src = make_sample_source(root);
    let a = root.join("a");
    let b = root.join("b");
    let c = root.join("c");

    // `a,b` in one comma-separated value, plus a second occurrence:
    // three targets must be delivered, one stdout line each.
    let mut cmd = std::process::Command::new(bin());
    cmd.arg("--source-type").arg("local");
    cmd.arg("--local-source").arg(&src);
    cmd.arg("--target-type").arg("local");
    cmd.arg("--local-target")
        .arg(format!("{},{}", a.display(), b.display()));
    cmd.arg("--local-target").arg(&c);
    cmd.arg("--name").arg("multi");
    cmd.arg("--database-type").arg("sqlite");
    cmd.arg("--encryption-type").arg("none");
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 3, "one stdout line per target: {stdout:?}");
    for line in &lines {
        let p = Path::new(line);
        assert!(p.exists(), "missing {}", p.display());
        assert!(
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("multi-")
        );
    }
    for t in [&a, &b, &c] {
        assert_eq!(
            list_dir(t).len(),
            1,
            "exactly one archive in {}",
            t.display()
        );
    }
}

#[test]
fn cli_local_source_flag_missing_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let target = root.join("out");

    // --source-type local declared, but --local-source is absent: the
    // type/value cross-check must fail before any work.
    let mut cmd = std::process::Command::new(bin());
    cmd.arg("--source-type").arg("local");
    cmd.arg("--target-type").arg("local");
    cmd.arg("--local-target").arg(&target);
    cmd.arg("--name").arg("n");
    cmd.arg("--database-type").arg("sqlite");
    cmd.arg("--encryption-type").arg("none");
    let out = cmd.output().unwrap();
    assert!(!out.status.success(), "missing --local-source must fail");
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        stderr.contains("--local-source"),
        "error must name the missing flag: {stderr}"
    );
    assert!(
        !target.exists(),
        "nothing may be written on preflight failure"
    );
}

#[test]
fn cli_local_target_flag_missing_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let src = make_sample_source(root);
    let target = root.join("out");

    // --target-type local declared, but no --local-target.
    let mut cmd = std::process::Command::new(bin());
    cmd.arg("--source-type").arg("local");
    cmd.arg("--local-source").arg(&src);
    cmd.arg("--target-type").arg("local");
    cmd.arg("--name").arg("n");
    cmd.arg("--database-type").arg("sqlite");
    cmd.arg("--encryption-type").arg("none");
    let out = cmd.output().unwrap();
    assert!(!out.status.success(), "missing --local-target must fail");
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        stderr.contains("--local-target"),
        "error must name the missing flag: {stderr}"
    );
    assert!(
        !target.exists(),
        "nothing may be written on preflight failure"
    );
}

#[test]
fn gpg_recipient_produces_gpg_and_no_plaintext() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let src = make_sample_source(root);
    let target = root.join("out");

    // A fresh key in a throwaway homedir. %no-protection keeps the key
    // unpassphrased so no pinentry is ever needed.
    let g1 = root.join("g1");
    fs::create_dir_all(&g1).unwrap();
    fs::write(
        g1.join("keyfile"),
        "Key-Type: RSA\nKey-Length: 2048\nName-Real: wtest\n%no-protection\n%commit\n",
    )
    .unwrap();
    let out = std::process::Command::new("gpg")
        .args([
            "--batch",
            "--no-tty",
            "--gen-key",
            g1.join("keyfile").to_str().unwrap(),
        ])
        .env("GNUPGHOME", &g1)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "keygen: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let fpr = fingerprint_of(g1.clone()).unwrap();

    let mut cmd = backup_cmd(&src, &target, "enc", "openpgp", &[&fpr]);
    cmd.env("GNUPGHOME", &g1);
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let path: PathBuf = stdout.lines().next().unwrap().into();
    assert!(path.exists(), "reported {} missing", path.display());
    assert!(
        path.file_name()
            .unwrap()
            .to_string_lossy()
            .ends_with(".tgz.gpg"),
        "expected .tgz.gpg, got {}",
        path.display()
    );
    // The plaintext archive must not linger, and no .part leftovers.
    let leftovers: Vec<String> = list_dir(&target)
        .into_iter()
        .filter(|n| n.ends_with(".tgz") || n.contains(".part"))
        .collect();
    assert!(leftovers.is_empty(), "leftovers: {leftovers:?}");

    // Decrypt back to the original archive and prove it unpacks.
    let plain = root.join("decrypted");
    let dec = std::process::Command::new("gpg")
        .args(["--batch", "--quiet", "--decrypt", "--output"])
        .arg(&plain)
        .arg(&path)
        .env("GNUPGHOME", &g1)
        .output()
        .unwrap();
    assert!(
        dec.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&dec.stderr)
    );
    let entries = unpack(&plain);
    assert!(entries.contains_key("db.sqlite3"));
    assert!(entries.contains_key("config.json"));
}

#[test]
fn gpg_uppercase_fingerprint_works() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let src = make_sample_source(root);
    let target = root.join("out");

    let g1 = root.join("g1");
    fs::create_dir_all(&g1).unwrap();
    fs::write(
        g1.join("keyfile"),
        "Key-Type: RSA\nKey-Length: 2048\nName-Real: upcase\n%no-protection\n%commit\n",
    )
    .unwrap();
    let out = std::process::Command::new("gpg")
        .args([
            "--batch",
            "--no-tty",
            "--gen-key",
            g1.join("keyfile").to_str().unwrap(),
        ])
        .env("GNUPGHOME", &g1)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "keygen: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let fpr = fingerprint_of(g1.clone()).unwrap();
    let uppercase = fpr.to_uppercase();

    // gpg keyids are hexadecimal and matched case-insensitively; an
    // upper-case fingerprint must pass preflight and encrypt.
    let mut cmd = backup_cmd(&src, &target, "enc-up", "openpgp", &[&uppercase]);
    cmd.env("GNUPGHOME", &g1);
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let path: PathBuf = stdout.lines().next().unwrap().into();
    assert!(
        path.file_name()
            .unwrap()
            .to_string_lossy()
            .ends_with(".tgz.gpg"),
        "{}",
        path.display()
    );

    // And it decrypts back to the original archive.
    let plain = root.join("decrypted-up");
    let dec = std::process::Command::new("gpg")
        .args(["--batch", "--quiet", "--decrypt", "--output"])
        .arg(&plain)
        .arg(&path)
        .env("GNUPGHOME", &g1)
        .output()
        .unwrap();
    assert!(
        dec.status.success(),
        "decrypt: {}",
        String::from_utf8_lossy(&dec.stderr)
    );
    let entries = unpack(&plain);
    assert!(entries.contains_key("db.sqlite3"));
    assert!(entries.contains_key("config.json"));
}

#[test]
fn gpg_comma_separated_recipients_work() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let src = make_sample_source(root);
    let target = root.join("out");

    // Two recipients in one throwaway homedir.
    let g1 = root.join("g1");
    fs::create_dir_all(&g1).unwrap();
    for name in ["k1", "k2"] {
        let keyfile = g1.join(format!("{name}.keyfile"));
        fs::write(
            &keyfile,
            format!(
                "Key-Type: RSA\nKey-Length: 2048\nName-Real: {name}\n%no-protection\n%commit\n"
            ),
        )
        .unwrap();
        let out = std::process::Command::new("gpg")
            .args([
                "--batch",
                "--no-tty",
                "--gen-key",
                keyfile.to_str().unwrap(),
            ])
            .env("GNUPGHOME", &g1)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "keygen {name}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let fprs = list_fprs(&g1);
    assert_eq!(fprs.len(), 2, "expected two keys in keyring");

    // One comma-separated --recipient value: the CLI must split it, and the
    // ciphertext must carry one pubkey-encr packet per recipient.
    let joined = format!("{},{}", fprs[0], fprs[1]);
    let mut cmd = backup_cmd(&src, &target, "enc2", "openpgp", &[&joined]);
    cmd.env("GNUPGHOME", &g1);
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let path: PathBuf = stdout.lines().next().unwrap().into();
    assert!(
        path.file_name()
            .unwrap()
            .to_string_lossy()
            .ends_with(".tgz.gpg")
    );

    let packets = std::process::Command::new("gpg")
        .args(["--batch", "--no-tty", "--list-packets"])
        .arg(&path)
        .env("GNUPGHOME", &g1)
        .output()
        .unwrap();
    assert!(
        packets.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&packets.stderr)
    );
    let count = String::from_utf8_lossy(&packets.stdout)
        .lines()
        .filter(|l| l.contains("pubkey enc packet"))
        .count();
    assert_eq!(count, 2, "one public-key encr packet per recipient");

    // Repeated-flag form: same effect, parsed as two separate recipients.
    let mut cmd = backup_cmd(&src, &target, "enc3", "openpgp", &[&fprs[0], &fprs[1]]);
    cmd.env("GNUPGHOME", &g1);
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let path: PathBuf = stdout.lines().next().unwrap().into();
    assert!(
        path.file_name()
            .unwrap()
            .to_string_lossy()
            .ends_with(".tgz.gpg")
    );
}

#[test]
fn gpg_recipients_via_env_var_comma_separated() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let src = make_sample_source(root);
    let target = root.join("out");

    // Two recipients in one throwaway homedir; they are supplied only
    // through the VWB_RECIPIENTS env var (comma-separated), not the CLI.
    let g1 = root.join("g1");
    fs::create_dir_all(&g1).unwrap();
    for name in ["k1", "k2"] {
        let keyfile = g1.join(format!("{name}.keyfile"));
        fs::write(
            &keyfile,
            format!(
                "Key-Type: RSA\nKey-Length: 2048\nName-Real: {name}\n%no-protection\n%commit\n"
            ),
        )
        .unwrap();
        let out = std::process::Command::new("gpg")
            .args([
                "--batch",
                "--no-tty",
                "--gen-key",
                keyfile.to_str().unwrap(),
            ])
            .env("GNUPGHOME", &g1)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "keygen {name}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let fprs = list_fprs(&g1);
    assert_eq!(fprs.len(), 2, "expected two keys in keyring");

    // No --recipient flag. Recipients arrive only via VWB_RECIPIENTS,
    // comma-separated. If clap did not split the env value on the
    // delimiter, the joined string would be an invalid recipient and
    // preflight would fail.
    let mut cmd = std::process::Command::new(bin());
    cmd.env("GNUPGHOME", &g1);
    cmd.env("VWB_RECIPIENTS", format!("{},{}", fprs[0], fprs[1]));
    cmd.env("VWB_ENCRYPTION_TYPE", "openpgp");
    cmd.arg("--source-type").arg("local");
    cmd.arg("--local-source").arg(&src);
    cmd.arg("--target-type").arg("local");
    cmd.arg("--local-target").arg(&target);
    cmd.arg("--name").arg("enc-env");
    cmd.arg("--database-type").arg("sqlite");
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let path: PathBuf = stdout.lines().next().unwrap().into();
    assert!(
        path.file_name()
            .unwrap()
            .to_string_lossy()
            .ends_with(".tgz.gpg")
    );

    let packets = std::process::Command::new("gpg")
        .args(["--batch", "--no-tty", "--list-packets"])
        .arg(&path)
        .env("GNUPGHOME", &g1)
        .output()
        .unwrap();
    assert!(packets.status.success());
    let count = String::from_utf8_lossy(&packets.stdout)
        .lines()
        .filter(|l| l.contains("pubkey enc packet"))
        .count();
    assert_eq!(count, 2, "both env var recipients must reach gpg");

    // Single-recipient env value (no comma) must still work: the common
    // cron case of exporting one fingerprint.
    let mut cmd = std::process::Command::new(bin());
    cmd.env("GNUPGHOME", &g1);
    cmd.env("VWB_RECIPIENTS", &fprs[0]);
    cmd.env("VWB_ENCRYPTION_TYPE", "openpgp");
    cmd.arg("--source-type").arg("local");
    cmd.arg("--local-source").arg(&src);
    cmd.arg("--target-type").arg("local");
    cmd.arg("--local-target").arg(&target);
    cmd.arg("--name").arg("enc-env1");
    cmd.arg("--database-type").arg("sqlite");
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let path: PathBuf = stdout.lines().next().unwrap().into();
    let packets = std::process::Command::new("gpg")
        .args(["--batch", "--no-tty", "--list-packets"])
        .arg(&path)
        .env("GNUPGHOME", &g1)
        .output()
        .unwrap();
    assert!(packets.status.success());
    let count = String::from_utf8_lossy(&packets.stdout)
        .lines()
        .filter(|l| l.contains("pubkey enc packet"))
        .count();
    assert_eq!(count, 1, "single env var recipient");

    // Command line wins over the env var: --recipient with one key must
    // produce exactly that key's packet, not the env value's two.
    let mut cmd = std::process::Command::new(bin());
    cmd.env("GNUPGHOME", &g1);
    cmd.env("VWB_RECIPIENTS", format!("{},{}", fprs[0], fprs[1]));
    cmd.env("VWB_ENCRYPTION_TYPE", "openpgp");
    cmd.arg("--source-type").arg("local");
    cmd.arg("--local-source").arg(&src);
    cmd.arg("--target-type").arg("local");
    cmd.arg("--local-target").arg(&target);
    cmd.arg("--name").arg("enc-override");
    cmd.arg("--database-type").arg("sqlite");
    cmd.arg("--recipient").arg(&fprs[0]);
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let path: PathBuf = stdout.lines().next().unwrap().into();
    let packets = std::process::Command::new("gpg")
        .args(["--batch", "--no-tty", "--list-packets"])
        .arg(&path)
        .env("GNUPGHOME", &g1)
        .output()
        .unwrap();
    assert!(packets.status.success());
    let count = String::from_utf8_lossy(&packets.stdout)
        .lines()
        .filter(|l| l.contains("pubkey enc packet"))
        .count();
    assert_eq!(count, 1, "CLI --recipient must override VWB_RECIPIENTS");
}

#[test]
fn gpg_bad_recipient_fails_before_anything() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let src = make_sample_source(root);
    let target = root.join("out");

    let mut cmd = backup_cmd(
        &src,
        &target,
        "n",
        "openpgp",
        &["0000000000000000000000000000000000000000"],
    );
    cmd.env_remove("GNUPGHOME");
    let out = cmd.output().unwrap();
    assert!(!out.status.success(), "unknown recipient must fail");
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        stderr.contains("gpg keyring"),
        "error must point at the keyring: {stderr}"
    );
    assert!(
        !target.exists(),
        "nothing may be written on preflight failure"
    );
}

#[test]
fn gpg_missing_binary_fails_at_preflight() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let src = make_sample_source(root);
    let target = root.join("out");
    // PATH holds only a fresh empty directory: gpg is not found, and the
    // preflight (before target creation) must report it.
    let empty_path = root.join("empty-bin");
    fs::create_dir_all(&empty_path).unwrap();

    let mut cmd = backup_cmd(
        &src,
        &target,
        "n",
        "openpgp",
        &["a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"],
    );
    cmd.env("PATH", &empty_path);
    let out = cmd.output().unwrap();
    assert!(!out.status.success(), "missing gpg must fail");
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(stderr.contains("gpg"), "error must mention gpg: {stderr}");
    assert!(
        !target.exists(),
        "nothing may be written on preflight failure"
    );
}

#[test]
fn cli_unsupported_database_type_fails_at_parse() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let src = make_sample_source(root);
    let target = root.join("out");

    let mut cmd = std::process::Command::new(bin());
    cmd.arg("--source-type").arg("local");
    cmd.arg("--local-source").arg(&src);
    cmd.arg("--target-type").arg("local");
    cmd.arg("--local-target").arg(&target);
    cmd.arg("--name").arg("n");
    cmd.arg("--database-type").arg("mysql");
    cmd.arg("--encryption-type").arg("none");
    let out = cmd.output().unwrap();
    assert!(!out.status.success(), "invalid db type must be rejected");
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        stderr.contains("sqlite"),
        "usage must list the possible values: {stderr}"
    );
    assert!(
        !target.exists(),
        "parse failure must not touch the target directory"
    );
}

#[test]
fn encryption_type_openpgp_requires_recipient() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let src = make_sample_source(root);
    let target = root.join("out");

    // No --recipient at all: the mode/recipients cross-check must fail
    // before any work; no gpg is involved at this stage.
    let mut cmd = backup_cmd(&src, &target, "n", "openpgp", &[]);
    let out = cmd.output().unwrap();
    assert!(
        !out.status.success(),
        "openpgp without --recipient must fail"
    );
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        stderr.contains("--recipient"),
        "error must point at the missing recipient: {stderr}"
    );
    assert!(!target.exists(), "nothing may be written");
}

#[test]
fn encryption_type_none_forbids_recipient() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let src = make_sample_source(root);
    let target = root.join("out");

    // --recipient with --encryption-type none: a plaintext run must not
    // silently take recipients; the check fires before keyring access, so
    // no gpg is needed.
    let mut cmd = backup_cmd(
        &src,
        &target,
        "n",
        "none",
        &["0000000000000000000000000000000000000000"],
    );
    let out = cmd.output().unwrap();
    assert!(!out.status.success(), "none with --recipient must fail");
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        stderr.contains("plaintext"),
        "error must name the plaintext/recipient conflict: {stderr}"
    );
    assert!(!target.exists(), "nothing may be written");
}

#[test]
fn cli_unsupported_encryption_type_fails_at_parse() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let src = make_sample_source(root);
    let target = root.join("out");

    let mut cmd = std::process::Command::new(bin());
    cmd.arg("--source-type").arg("local");
    cmd.arg("--local-source").arg(&src);
    cmd.arg("--target-type").arg("local");
    cmd.arg("--local-target").arg(&target);
    cmd.arg("--name").arg("n");
    cmd.arg("--database-type").arg("sqlite");
    cmd.arg("--encryption-type").arg("rot13");
    let out = cmd.output().unwrap();
    assert!(!out.status.success(), "invalid enc type must be rejected");
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        stderr.contains("openpgp"),
        "usage must list the possible values: {stderr}"
    );
    assert!(
        !target.exists(),
        "parse failure must not touch the target directory"
    );
}

#[test]
fn cli_long_forms_work() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let src = make_sample_source(root);
    let target = root.join("out");
    let mut cmd = backup_cmd(&src, &target, "n", "none", &[]);
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
