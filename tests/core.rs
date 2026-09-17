//! Library-level end-to-end tests: call `run()` directly and assert snapshot
//! semantics, byte exactness, target dedup and preflight refusals. The
//! real-binary CLI tests live in `cli.rs`, the S3 ones in `s3.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::path::Path;

use vaultwarden_backup::{DatabaseType, Delivered, EncryptionType, Target};

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

    let delivered = vaultwarden_backup::run(
        src.clone(),
        vec![Target::Local {
            dir: target.clone(),
        }],
        "vaultwarden-backup".into(),
        DatabaseType::Sqlite,
        EncryptionType::None,
        Vec::new(),
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

    let delivered = vaultwarden_backup::run(
        src,
        vec![
            Target::Local { dir: t1.clone() },
            Target::Local { dir: t2.clone() },
        ],
        "multi".into(),
        DatabaseType::Sqlite,
        EncryptionType::None,
        Vec::new(),
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
        vec![Target::Local { dir: target }],
        "my-prefix".into(),
        DatabaseType::Sqlite,
        EncryptionType::None,
        Vec::new(),
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
    let err = vaultwarden_backup::run(
        src,
        vec![Target::Local {
            dir: target.clone(),
        }],
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
    )
    .unwrap();
    assert_eq!(delivered.len(), 1, "one delivery per physical directory");
    assert_eq!(local_delivered(&delivered[0]).parent().unwrap(), &target);
    assert_eq!(list_dir(&target).len(), 1, "exactly one archive");
}

#[test]
fn missing_source_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let err = vaultwarden_backup::run(
        tmp.path().join("no-such-dir"),
        vec![Target::Local {
            dir: tmp.path().join("out"),
        }],
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
        vec![Target::Local {
            dir: tmp.path().join("out"),
        }],
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
        vec![Target::Local {
            dir: tmp.path().join("out"),
        }],
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
        vec![Target::Local {
            dir: src.join("backups"),
        }],
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
    let conn = rusqlite::Connection::open(&src_db).unwrap();
    conn.execute("BEGIN IMMEDIATE", ()).unwrap();
    conn.execute("INSERT INTO notes(body) VALUES ('uncommitted')", ())
        .unwrap();
    let delivered = vaultwarden_backup::run(
        src,
        vec![Target::Local { dir: out }],
        "n".into(),
        DatabaseType::Sqlite,
        EncryptionType::None,
        Vec::new(),
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
