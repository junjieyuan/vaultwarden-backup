//! Real-binary CLI tests: every invocation goes through the built executable
//! (`CARGO_BIN_EXE_*`), covering the long-option-only surface, the
//! type/value cross-checks, environment-variable handling, and the OpenPGP
//! path with throwaway keys in a temporary GNUPGHOME.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use common::{bin, fingerprint_of, list_dir, list_fprs, make_sample_source, unpack};

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
