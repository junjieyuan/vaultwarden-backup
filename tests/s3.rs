//! S3-target tests: the CLI cross-checks run offline, the end-to-end tests
//! need a real S3-compatible server and skip when `VWB_S3_TEST_ENDPOINT` is
//! not set (a plain `cargo test` stays offline). CI provisions a RustFS
//! service container and its bucket with the `rc` CLI.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::Path;

use common::{bin, make_sample_source};

/// A ready `Command` for a run with a local source and a local target, minus
/// any target-type/flags — S3 tests add them below.
fn s3_cli_base(src: &Path, target: &Path) -> std::process::Command {
    let mut cmd = std::process::Command::new(bin());
    cmd.arg("--source-type").arg("local");
    cmd.arg("--local-source").arg(src);
    cmd.arg("--target-type").arg("local");
    cmd.arg("--local-target").arg(target);
    cmd.arg("--name").arg("s3test");
    cmd.arg("--database-type").arg("sqlite");
    cmd.arg("--encryption-type").arg("none");
    cmd
}

/// The S3 flags common to every S3 CLI test.
const S3_FLAGS: [(&str, &str); 7] = [
    ("--s3-endpoint", "http://127.0.0.1:1"),
    ("--s3-region", "us-east-1"),
    ("--s3-access-key", "ak"),
    ("--s3-secret-key", "sk"),
    ("--s3-bucket", "bkt"),
    ("--s3-prefix", "/"),
    ("--s3-addressing", "path-style"),
];

/// The S3-compatible test server configuration, read from the environment:
/// only `VWB_S3_TEST_ENDPOINT` is required to actually run; without it the
/// network-touching tests skip (a plain `cargo test` stays offline).
fn s3_test_env() -> Option<(String, String, String, String)> {
    // (endpoint, access key, secret key, bucket)
    let endpoint = std::env::var("VWB_S3_TEST_ENDPOINT").ok()?;
    let ak = std::env::var("VWB_S3_TEST_ACCESS_KEY").unwrap_or_else(|_| "minioadmin".into());
    let sk = std::env::var("VWB_S3_TEST_SECRET_KEY").unwrap_or_else(|_| "minioadmin".into());
    let bucket = std::env::var("VWB_S3_TEST_BUCKET").unwrap_or_else(|_| "backup-test".into());
    Some((endpoint, ak, sk, bucket))
}

#[test]
fn cli_s3_missing_required_flag_is_named() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let src = make_sample_source(root);
    let target = root.join("out");

    // Drop exactly one S3 flag at a time: the preflight must name the missing
    // flag and write nothing before backing up. (Declare both target types:
    // the base command already declares `local`.)
    for (skip_index, (flag, _)) in S3_FLAGS.iter().enumerate() {
        let mut cmd = s3_cli_base(&src, &target);
        cmd.arg("--target-type").arg("s3");
        for (i, (f, v)) in S3_FLAGS.iter().enumerate() {
            if i != skip_index {
                cmd.arg(*f).arg(*v);
            }
        }
        let out = cmd.output().unwrap();
        assert!(!out.status.success(), "missing {flag} must fail");
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        assert!(
            stderr.contains(*flag),
            "error must name the missing flag {flag}: {stderr}"
        );
        assert!(
            !target.exists(),
            "nothing may be written on preflight failure"
        );
    }
}

#[test]
fn cli_s3_addressing_invalid_value_fails_at_parse() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let src = make_sample_source(root);
    let target = root.join("out");

    let mut cmd = s3_cli_base(&src, &target);
    cmd.arg("--target-type").arg("s3");
    for (f, v) in S3_FLAGS {
        if f == "--s3-addressing" {
            // supplied below with the invalid value; a duplicate flag would
            // trip clap's "used multiple times" before the value check.
            continue;
        }
        cmd.arg(f).arg(v);
    }
    cmd.arg("--s3-addressing").arg("bogus");
    let out = cmd.output().unwrap();
    assert!(!out.status.success(), "invalid addressing must be rejected");
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        stderr.contains("virtual-hosted") && stderr.contains("path-style"),
        "usage must list the possible values: {stderr}"
    );
    assert!(!target.exists(), "parse failure must not touch any target");
}

#[test]
fn cli_s3_flags_without_s3_type_fail_without_writing() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let src = make_sample_source(root);
    let target = root.join("out");

    // `--s3-bucket` without `--target-type s3`: the value flag without its
    // declared type must be an error, before any work.
    let mut cmd = s3_cli_base(&src, &target);
    cmd.arg("--s3-bucket").arg("bkt");
    let out = cmd.output().unwrap();
    assert!(!out.status.success(), "s3 flag without s3 type must fail");
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        stderr.contains("--target-type s3"),
        "error must name the missing type: {stderr}"
    );
    assert!(
        !target.exists(),
        "nothing may be written on preflight failure"
    );
}

#[test]
fn cli_s3_local_mixed_success_and_stdout() {
    let Some((endpoint, ak, sk, bucket)) = s3_test_env() else {
        eprintln!("skipping S3 e2e: set VWB_S3_TEST_ENDPOINT");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let src = make_sample_source(root);
    let target = root.join("out");

    let mut cmd = s3_cli_base(&src, &target);
    cmd.arg("--target-type").arg("s3,local");
    cmd.arg("--s3-endpoint").arg(&endpoint);
    cmd.arg("--s3-region").arg("us-east-1");
    cmd.arg("--s3-access-key").arg(&ak);
    cmd.arg("--s3-secret-key").arg(&sk);
    cmd.arg("--s3-bucket").arg(&bucket);
    cmd.arg("--s3-prefix").arg("/");
    cmd.arg("--s3-addressing").arg("path-style");
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2, "one line per target: {stdout:?}");
    // Local targets are reported first, then the S3 object.
    assert!(
        Path::new(lines[0]).exists(),
        "local line missing: {stdout:?}"
    );
    assert!(lines[1].starts_with("s3://"), "s3 line missing: {stdout:?}");
    assert!(lines[1].contains(&format!("{bucket}/")), "{}", lines[1]);
}

#[test]
fn s3_target_e2e_upload_nooverwrite_and_unpack() {
    use object_store::aws::AmazonS3Builder;
    use object_store::path::Path as ObjPath;
    use object_store::{ObjectStore, ObjectStoreExt};

    let Some((endpoint, ak, sk, bucket)) = s3_test_env() else {
        eprintln!("skipping S3 e2e: set VWB_S3_TEST_ENDPOINT");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let src = make_sample_source(root);

    let s3 = vaultwarden_backup::S3Target {
        endpoint: endpoint.clone(),
        region: "us-east-1".into(),
        access_key: ak.clone(),
        secret_key: sk.clone(),
        bucket: bucket.clone(),
        prefix: "e2e".into(),
        addressing: vaultwarden_backup::S3Addressing::PathStyle,
    };
    // The bucket must already exist (CI provisions it; local runs must create
    // it first) — object_store has no bucket-creation API.
    let client = AmazonS3Builder::new()
        .with_region("us-east-1")
        .with_access_key_id(&ak)
        .with_secret_access_key(&sk)
        .with_bucket_name(&bucket)
        .with_endpoint(&endpoint)
        .with_virtual_hosted_style_request(false)
        .with_allow_http(endpoint.starts_with("http://"))
        .build()
        .unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let delivered = vaultwarden_backup::run(
        src.clone(),
        vec![vaultwarden_backup::Target::S3(s3.clone())],
        "arch".into(),
        vaultwarden_backup::DatabaseType::Sqlite,
        vaultwarden_backup::EncryptionType::None,
        Vec::new(),
    )
    .unwrap();
    assert_eq!(delivered.len(), 1, "one delivery");
    let (b, key) = match &delivered[0] {
        vaultwarden_backup::Delivered::S3 { bucket: b, key } => (b.clone(), key.clone()),
        vaultwarden_backup::Delivered::Local(_) => panic!("expected an S3 delivery"),
    };
    assert_eq!(&b, &bucket);
    assert!(key.starts_with("e2e/arch-"), "{key}");
    assert!(key.ends_with(".tgz"), "{key}");

    // Download the object and prove it unpacks to the sample source.
    let bytes = rt.block_on(async {
        client
            .get(&ObjPath::from(key.as_str()))
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap()
    });
    let plain = root.join("downloaded.tgz");
    std::fs::write(&plain, bytes).unwrap();
    let entries = common::unpack(&plain);
    assert!(entries.contains_key("db.sqlite3"));
    assert_eq!(entries["config.json"], b"{\"AdminToken\":\"secret\"}");
    assert_eq!(entries["attachments/u1/file.txt"], b"attachment-content\n");

    // A same-second re-run must refuse: occupy the would-be final name first
    // and expect the preflight head to collide (retried across second
    // boundaries, like the local variant of this test).
    let mut collided = false;
    for _ in 0..5 {
        let stamp = vaultwarden_backup::stamp(&time::OffsetDateTime::now_utc());
        let occ = format!("e2e/occ-{stamp}.tgz");
        rt.block_on(async {
            let _ = client.delete(&ObjPath::from(occ.as_str())).await;
            client
                .put(
                    &ObjPath::from(occ.as_str()),
                    format!("occupied-{stamp}").into_bytes().into(),
                )
                .await
                .unwrap();
        });
        let err = vaultwarden_backup::run(
            src.clone(),
            vec![vaultwarden_backup::Target::S3(s3.clone())],
            "occ".into(),
            vaultwarden_backup::DatabaseType::Sqlite,
            vaultwarden_backup::EncryptionType::None,
            Vec::new(),
        );
        if err.is_err() {
            collided = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1100));
    }
    assert!(collided, "a same-second re-run must collide in S3");

    // No `.part`-style leftovers: multipart state is never visible under a
    // `.part` key, and a crashed upload must not leave one behind either.
    let listing = rt
        .block_on(client.list_with_delimiter(Some(&ObjPath::from("e2e"))))
        .unwrap();
    assert!(
        listing
            .objects
            .iter()
            .all(|m| !m.location.to_string().contains(".part")),
        "no .part objects may remain"
    );
}
