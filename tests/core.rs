//! Library-level end-to-end tests: call `run()` directly and assert snapshot
//! semantics, byte exactness, target dedup and preflight refusals. The
//! real-binary CLI tests live in `cli.rs`, the S3 ones in `s3.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use vwb::{DatabaseType, Delivered, EncryptionType, RetentionPeriod, Target};

use common::{DB, list_dir, make_sample_source, unpack};

/// Extract the local path from a `Delivered` value (S3 deliveries would be a
/// test bug here).
fn local_delivered(d: &Delivered) -> &Path {
    match d {
        Delivered::Local(path) => path,
        Delivered::S3 { .. } => panic!("expected a local delivery, got S3"),
    }
}

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
        let conn = rusqlite::Connection::open(&src_db).unwrap();
        conn.execute("INSERT INTO notes(body) VALUES ('pre-backup')", ())
            .unwrap();
        drop(conn);
    }

    let delivered = vwb::run(
        src.clone(),
        vec![Target::Local {
            dir: target.clone(),
        }],
        "vaultwarden-backup".into(),
        DatabaseType::Sqlite,
        EncryptionType::None,
        Vec::new(),
        RetentionPeriod::Unlimited,
    )
    .unwrap();

    assert_eq!(delivered.len(), 1, "one delivery per target");
    let out = local_delivered(&delivered[0]);
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
    let conn = rusqlite::Connection::open(&snap_db).unwrap();
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

    let conn = rusqlite::Connection::open(&src_db).unwrap();
    conn.execute("INSERT INTO notes(body) VALUES ('post-backup')", ())
        .unwrap();
    drop(conn);

    let conn = rusqlite::Connection::open(&snap_db).unwrap();
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

    let delivered = vwb::run(
        src,
        vec![
            Target::Local { dir: t1.clone() },
            Target::Local { dir: t2.clone() },
        ],
        "multi".into(),
        DatabaseType::Sqlite,
        EncryptionType::None,
        Vec::new(),
        RetentionPeriod::Unlimited,
    )
    .unwrap();

    assert_eq!(delivered.len(), 2, "one delivery per target, in order");
    let p0 = local_delivered(&delivered[0]);
    let p1 = local_delivered(&delivered[1]);
    assert_eq!(p0.parent().unwrap(), &t1);
    assert_eq!(p1.parent().unwrap(), &t2);
    for p in [p0, p1] {
        assert!(p.exists(), "{} missing", p.display());
    }
    // Independent copies of the same bytes.
    assert_eq!(fs::read(p0).unwrap(), fs::read(p1).unwrap());
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
    let err = vwb::run(
        src,
        Vec::new(),
        "n".into(),
        DatabaseType::Sqlite,
        EncryptionType::None,
        Vec::new(),
        RetentionPeriod::Unlimited,
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
    let delivered = vwb::run(
        src,
        vec![Target::Local { dir: target }],
        "my-prefix".into(),
        DatabaseType::Sqlite,
        EncryptionType::None,
        Vec::new(),
        RetentionPeriod::Unlimited,
    )
    .unwrap();
    let fname = local_delivered(&delivered[0])
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
    let err = vwb::run(
        src,
        vec![Target::Local {
            dir: target.clone(),
        }],
        "bad/name".into(),
        DatabaseType::Sqlite,
        EncryptionType::None,
        Vec::new(),
        RetentionPeriod::Unlimited,
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

    let delivered = vwb::run(
        src,
        vec![
            Target::Local {
                dir: target.clone(),
            },
            Target::Local { dir: target_link },
        ],
        "dedup".into(),
        DatabaseType::Sqlite,
        EncryptionType::None,
        Vec::new(),
        RetentionPeriod::Unlimited,
    )
    .unwrap();
    assert_eq!(delivered.len(), 1, "one delivery per physical directory");
    assert_eq!(local_delivered(&delivered[0]).parent().unwrap(), &target);
    assert_eq!(list_dir(&target).len(), 1, "exactly one archive");
}

#[test]
fn missing_source_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let err = vwb::run(
        tmp.path().join("no-such-dir"),
        vec![Target::Local {
            dir: tmp.path().join("out"),
        }],
        "n".into(),
        DatabaseType::Sqlite,
        EncryptionType::None,
        Vec::new(),
        RetentionPeriod::Unlimited,
    )
    .unwrap_err();
    assert!(err.to_string().contains("does not exist"));
}

#[test]
fn source_is_file_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let f = tmp.path().join("not-a-dir");
    fs::write(&f, b"x").unwrap();
    let err = vwb::run(
        f,
        vec![Target::Local {
            dir: tmp.path().join("out"),
        }],
        "n".into(),
        DatabaseType::Sqlite,
        EncryptionType::None,
        Vec::new(),
        RetentionPeriod::Unlimited,
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
    let err = vwb::run(
        src,
        vec![Target::Local {
            dir: tmp.path().join("out"),
        }],
        "n".into(),
        DatabaseType::Sqlite,
        EncryptionType::None,
        Vec::new(),
        RetentionPeriod::Unlimited,
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
    let err = vwb::run(
        src.clone(),
        vec![Target::Local {
            dir: src.join("backups"),
        }],
        "n".into(),
        DatabaseType::Sqlite,
        EncryptionType::None,
        Vec::new(),
        RetentionPeriod::Unlimited,
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
    let conn = rusqlite::Connection::open(&src_db).unwrap();
    conn.execute("BEGIN IMMEDIATE", ()).unwrap();
    conn.execute("INSERT INTO notes(body) VALUES ('uncommitted')", ())
        .unwrap();
    let delivered = vwb::run(
        src,
        vec![Target::Local { dir: out }],
        "n".into(),
        DatabaseType::Sqlite,
        EncryptionType::None,
        Vec::new(),
        RetentionPeriod::Unlimited,
    )
    .unwrap();
    conn.execute("ROLLBACK", ()).unwrap();
    drop(conn);

    let entries = unpack(local_delivered(&delivered[0]));
    let snap_db = root.join("snap.sqlite3");
    fs::write(&snap_db, &entries["db.sqlite3"]).unwrap();
    let conn = rusqlite::Connection::open(&snap_db).unwrap();
    let n: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM notes WHERE body = 'uncommitted'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 0);
}

// A 20-char UTC stamp well past any retention window, used to seed an
// "already expired" archive on disk.
const EXPIRED_STAMP: &str = "2020-01-02T03:04:05Z";

#[test]
fn retention_cleanup_deletes_expired_archives() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let src = make_sample_source(root);
    let target = root.join("backups");
    fs::create_dir_all(&target).unwrap();

    // Seed an expired own archive and a foreign old file that must survive.
    let expired = target.join(format!("vaultwarden-backup-{EXPIRED_STAMP}.tgz"));
    fs::write(&expired, b"old bytes").unwrap();
    let foreign = target.join("someone-else-2020-01-02T03:04:05Z.tgz");
    fs::write(&foreign, b"foreign").unwrap();

    let delivered = vwb::run(
        src,
        vec![Target::Local {
            dir: target.clone(),
        }],
        "vaultwarden-backup".into(),
        DatabaseType::Sqlite,
        EncryptionType::None,
        Vec::new(),
        RetentionPeriod::Days(7),
    )
    .unwrap();

    let fresh = local_delivered(&delivered[0]);
    assert!(fresh.exists(), "the fresh archive must be delivered");
    assert!(!expired.exists(), "expired own archive must be cleaned up");
    assert!(foreign.exists(), "foreign files must be left alone");
}

#[test]
fn failed_target_is_left_untouched_and_delivered_targets_are_cleaned() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let src = make_sample_source(root);
    let target = root.join("backups");
    fs::create_dir_all(&target).unwrap();

    // An expired own archive that cleanup *would* remove.
    let expired = target.join(format!("n-{EXPIRED_STAMP}.tgz"));
    fs::write(&expired, b"old bytes").unwrap();

    // A second target whose copy fails at delivery time (a read-only
    // directory), so the run fails — but the good target received the
    // archive and must still be cleaned, while the failed target is left
    // exactly as found.
    let broken = root.join("readonly");
    fs::create_dir_all(&broken).unwrap();
    let broken_expired = broken.join(format!("n-{EXPIRED_STAMP}.tgz"));
    fs::write(&broken_expired, b"old bytes").unwrap();
    fs::set_permissions(&broken, fs::Permissions::from_mode(0o555)).unwrap();

    let err = vwb::run(
        src,
        vec![
            Target::Local {
                dir: target.clone(),
            },
            Target::Local {
                dir: broken.clone(),
            },
        ],
        "n".into(),
        DatabaseType::Sqlite,
        EncryptionType::None,
        Vec::new(),
        RetentionPeriod::Days(7),
    )
    .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains(&format!("{}", broken.display())),
        "the failing target must be named: {msg}"
    );
    // Restore write permission so the tempdir can be removed.
    fs::set_permissions(&broken, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        broken_expired.exists(),
        "the failed target must be left untouched"
    );
    assert!(
        !expired.exists(),
        "the delivered target must still be cleaned when a sibling fails"
    );
}

/// A dead-end S3 target: `http://127.0.0.1:1` refuses the connection, so the
/// preflight head fails fast without a real server.
fn dead_s3_target() -> vwb::S3Target {
    vwb::S3Target {
        endpoint: "http://127.0.0.1:1".into(),
        region: "us-east-1".into(),
        access_key: "ak".into(),
        secret_key: "sk".into(),
        bucket: "bkt".into(),
        prefix: "/".into(),
        addressing: vwb::S3Addressing::PathStyle,
    }
}

#[test]
fn s3_preflight_failure_still_delivers_and_cleans_local() {
    // An unreachable S3 endpoint: the S3 target's preflight fails, and the
    // run must fail naming the S3 target — while the local target still
    // receives the archive and is still cleaned.
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let src = make_sample_source(root);
    let target = root.join("backups");
    fs::create_dir_all(&target).unwrap();

    let expired = target.join(format!("s3mix-{EXPIRED_STAMP}.tgz"));
    fs::write(&expired, b"old bytes").unwrap();

    let err = vwb::run(
        src,
        vec![
            Target::Local {
                dir: target.clone(),
            },
            Target::S3(dead_s3_target()),
        ],
        "s3mix".into(),
        DatabaseType::Sqlite,
        EncryptionType::None,
        Vec::new(),
        RetentionPeriod::Days(7),
    )
    .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("s3://bkt/"),
        "the failing S3 target must be named: {msg}"
    );

    // The local target still got the archive, and its expired own archive
    // was still cleaned despite the failed run.
    let fresh: Vec<String> = list_dir(&target)
        .into_iter()
        .filter(|n| n.starts_with("s3mix-") && n.ends_with(".tgz"))
        .collect();
    assert_eq!(
        fresh.len(),
        1,
        "local archive missing; dir: {}",
        list_dir(&target).join(", ")
    );
    assert!(!expired.exists(), "delivered target must still be cleaned");
}

#[test]
fn s3_only_preflight_failure_refuses_before_work() {
    let tmp = tempfile::tempdir().unwrap();
    let src = make_sample_source(tmp.path());

    // No local target: the S3 target is the only recipient, so its preflight
    // failure still refuses the whole run before any backup work.
    let err = vwb::run(
        src,
        vec![Target::S3(dead_s3_target())],
        "n".into(),
        DatabaseType::Sqlite,
        EncryptionType::None,
        Vec::new(),
        RetentionPeriod::Unlimited,
    )
    .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("no target is left"),
        "an S3-only run must refuse on preflight failure: {msg}"
    );
}

#[test]
fn bad_local_target_fails_only_itself() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let src = make_sample_source(root);
    let good = root.join("good");
    fs::create_dir_all(&good).unwrap();

    // A target whose parent is a regular file: preparation fails for it
    // alone, and the good target still receives the archive.
    let blocker = root.join("blocker");
    fs::write(&blocker, b"not a directory").unwrap();
    let bad = blocker.join("sub");

    let err = vwb::run(
        src,
        vec![
            Target::Local { dir: good.clone() },
            Target::Local { dir: bad.clone() },
        ],
        "n".into(),
        DatabaseType::Sqlite,
        EncryptionType::None,
        Vec::new(),
        RetentionPeriod::Unlimited,
    )
    .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains(&format!("{}", blocker.display())),
        "the failing target must be named: {msg}"
    );
    let fresh: Vec<String> = list_dir(&good)
        .into_iter()
        .filter(|n| n.starts_with("n-"))
        .collect();
    assert_eq!(
        fresh.len(),
        1,
        "the good target must still be delivered; dir: {}",
        list_dir(&good).join(", ")
    );
}

#[test]
fn collided_target_fails_only_itself() {
    // A same-second re-run: the target that already holds the file name
    // fails on its own, and the other target is still delivered. Retrying
    // across a few attempts makes the test immune to a second boundary
    // slipping between the occupation and the run's stamp.
    for _ in 0..5 {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let src = make_sample_source(root);
        let a = root.join("a");
        let b = root.join("b");
        fs::create_dir_all(&a).unwrap();
        fs::create_dir_all(&b).unwrap();
        // Occupy `a` with this run's would-be file name.
        let occupied = format!("x-{}.tgz", vwb::stamp(&time::OffsetDateTime::now_utc()));
        fs::write(a.join(&occupied), b"occupied").unwrap();

        let run = vwb::run(
            src.clone(),
            vec![
                Target::Local { dir: a.clone() },
                Target::Local { dir: b.clone() },
            ],
            "x".into(),
            DatabaseType::Sqlite,
            EncryptionType::None,
            Vec::new(),
            RetentionPeriod::Unlimited,
        );
        if run.is_ok() {
            // The run outlived the occupied second: no collision, retry.
            continue;
        }
        let msg = run.unwrap_err().to_string();
        assert!(
            msg.contains(&format!("{}", a.display())),
            "the collided target must be named: {msg}"
        );
        assert!(
            !msg.contains(&format!("{}", b.display())),
            "only the collided target must fail: {msg}"
        );
        // The free target still received the archive.
        let fresh: Vec<String> = list_dir(&b)
            .into_iter()
            .filter(|n| n.starts_with("x-"))
            .collect();
        assert_eq!(
            fresh.len(),
            1,
            "the free target must still be delivered; dir: {}",
            list_dir(&b).join(", ")
        );
        break;
    }
}

/// Like `dead_s3_target()`, but with a malformed endpoint URL, so the
/// failure happens at client build — no network involved, instant.
fn bad_endpoint_s3_target() -> vwb::S3Target {
    let mut s3 = dead_s3_target();
    s3.endpoint = "not-a-url".into();
    s3
}

#[test]
fn s3_bad_endpoint_fails_only_the_s3_target() {
    // A malformed endpoint URL: the S3 target fails at client build (no
    // network), and the local target still receives the archive.
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let src = make_sample_source(root);
    let target = root.join("backups");
    fs::create_dir_all(&target).unwrap();

    let err = vwb::run(
        src,
        vec![
            Target::Local {
                dir: target.clone(),
            },
            Target::S3(bad_endpoint_s3_target()),
        ],
        "n".into(),
        DatabaseType::Sqlite,
        EncryptionType::None,
        Vec::new(),
        RetentionPeriod::Unlimited,
    )
    .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("s3://bkt/"),
        "the failing S3 target must be named: {msg}"
    );
    assert!(
        msg.contains("not-a-url"),
        "the malformed endpoint must be reported: {msg}"
    );
    let fresh: Vec<String> = list_dir(&target)
        .into_iter()
        .filter(|n| n.starts_with("n-"))
        .collect();
    assert_eq!(
        fresh.len(),
        1,
        "the local target must still be delivered; dir: {}",
        list_dir(&target).join(", ")
    );
}

#[test]
fn no_target_left_refusal_names_every_failed_target() {
    // A bad local target (parent is a regular file) and a bad S3 endpoint:
    // no target is left to receive the artifact, so the run refuses before
    // any work and names every failure.
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let src = make_sample_source(root);

    let blocker = root.join("blocker");
    fs::write(&blocker, b"not a directory").unwrap();
    let bad = blocker.join("sub");

    let err = vwb::run(
        src,
        vec![
            Target::Local { dir: bad.clone() },
            Target::S3(bad_endpoint_s3_target()),
        ],
        "n".into(),
        DatabaseType::Sqlite,
        EncryptionType::None,
        Vec::new(),
        RetentionPeriod::Unlimited,
    )
    .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.starts_with("no target is left"),
        "the refusal must be before any backup work: {msg}"
    );
    assert!(
        msg.contains(&format!("{}", blocker.display())),
        "the local failure must be named: {msg}"
    );
    assert!(
        msg.contains("s3://bkt/"),
        "the S3 failure must be named: {msg}"
    );
}

#[test]
fn nested_target_fails_only_itself() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let src = make_sample_source(root);
    let good = root.join("good");
    fs::create_dir_all(&good).unwrap();
    let nested = src.join("backups");

    // A target nested in the source fails on its own, and the good target
    // still receives the archive.
    let err = vwb::run(
        src.clone(),
        vec![
            Target::Local {
                dir: nested.clone(),
            },
            Target::Local { dir: good.clone() },
        ],
        "n".into(),
        DatabaseType::Sqlite,
        EncryptionType::None,
        Vec::new(),
        RetentionPeriod::Unlimited,
    )
    .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("nested"),
        "the nested target must fail with the nesting reason: {msg}"
    );
    let fresh: Vec<String> = list_dir(&good)
        .into_iter()
        .filter(|n| n.starts_with("n-"))
        .collect();
    assert_eq!(
        fresh.len(),
        1,
        "the good target must still be delivered; dir: {}",
        list_dir(&good).join(", ")
    );
}
