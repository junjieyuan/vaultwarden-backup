//! Back up a vaultwarden `DATA_FOLDER` to a single timestamped `.tgz` and
//! deliver one copy to every local target, plus optionally one S3-compatible
//! object-store target.
//!
//! The data directory's contents sit directly at the archive root (no
//! top-level directory), so restoring is `tar -x -C <data dir>`; the
//! `db.sqlite3` entry is the online snapshot, not a copy of the file.
//!
//! Every intermediate artifact (database snapshot, `.tgz`, `.tgz.gpg`)
//! lives in a scratch directory (`tempfile::tempdir()`, honoring `TMPDIR`)
//! and is copied/uploaded to the targets only once finished, so a run never
//! touches a target until the final artifact is ready.

// `unwrap`/`expect` are denied project-wide (Cargo.toml `[lints.clippy]`);
// test builds are exempted here, production code is not.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod archive;
pub mod crypto;
pub mod db;
pub mod deliver;
pub mod files;
pub mod s3;

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::ValueEnum;
use time::OffsetDateTime;
use time::macros::format_description;

/// Database type of the source; only `sqlite` is supported.
#[derive(Debug, Clone, Copy, PartialEq, ValueEnum)]
pub enum DatabaseType {
    /// SQLite database (the only supported type)
    Sqlite,
}

/// Encryption of the produced archive; chosen explicitly so a backup can
/// never silently end up unencrypted (or unencrypted *intended* as
/// encrypted).
#[derive(Debug, Clone, Copy, PartialEq, ValueEnum)]
pub enum EncryptionType {
    /// no encryption (the archive is written in plaintext)
    None,
    /// OpenPGP-encrypt for every recipient given with `--recipient`
    Openpgp,
}

/// A single destination: a local directory or an S3-compatible object store.
/// Local targets are delivered with the `.part` + rename choreography in
/// `deliver`; the S3 target gets a multipart upload in `s3`. A run has any
/// number of local targets and at most one S3 target.
#[derive(Debug, Clone)]
pub enum Target {
    /// A local directory (created if missing).
    Local { dir: PathBuf },
    /// An S3-compatible object-store destination.
    S3(S3Target),
}

/// Addressing style for the S3 endpoint (`--s3-addressing`). Two explicit
/// values so the run never guesses: an IP/localhost or self-hosted endpoint
/// (RustFS, MinIO, Cloudflare R2, …) needs `PathStyle`; AWS and most
/// managed S3-compatible services resolve `<bucket>.<endpoint>` and can use
/// `VirtualHosted`.
#[derive(Debug, Clone, Copy, PartialEq, ValueEnum)]
pub enum S3Addressing {
    /// `https://<bucket>.<endpoint>/<key>`
    VirtualHosted,
    /// `https://<endpoint>/<bucket>/<key>`
    PathStyle,
}

/// Fully explicit configuration of an S3 destination: no field has a silent
/// default, so a run can never quietly upload to the wrong place (or to a
/// storage that was not declared).
#[derive(Debug, Clone)]
pub struct S3Target {
    /// S3-compatible endpoint URL (AWS `https://s3.<region>.amazonaws.com`,
    /// RustFS, MinIO, Wasabi, Backblaze B2, Cloudflare R2, …).
    pub endpoint: String,
    /// Region used for SigV4 signing; passed through verbatim (R2 uses
    /// `auto`), never validated.
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
    pub bucket: String,
    /// Object key prefix; `/` (or the empty string) means bucket root.
    pub prefix: String,
    pub addressing: S3Addressing,
}

/// Where a finished archive ended up, reported by `run` per target.
#[derive(Debug, Clone)]
pub enum Delivered {
    /// Local path of the delivered archive.
    Local(PathBuf),
    /// Object key in the S3 bucket (`s3://<bucket>/<key>`).
    S3 { bucket: String, key: String },
}

/// File name of the vaultwarden SQLite database inside the data directory.
pub const DB_FILENAME: &str = "db.sqlite3";

/// Run one backup into every declared target; returns one `Delivered` per
/// target — local paths first (in the order given), then the S3 object.
pub fn run(
    local_source: PathBuf,
    targets: Vec<Target>,
    name: String,
    database_type: DatabaseType,
    encryption_type: EncryptionType,
    recipients: Vec<String>,
) -> Result<Vec<Delivered>> {
    // The archive name becomes a file-name prefix; reject path separators
    // (and NUL, which every path API refuses) before anything else.
    check_archive_name(&name)?;

    // Cross-check mode and recipients before any work: the two must agree,
    // otherwise the run would silently do the wrong thing (unencrypted
    // output, or encryption nobody asked for).
    match encryption_type {
        EncryptionType::None => {
            if !recipients.is_empty() {
                bail!(
                    "--recipient is given but --encryption-type none requests \
                     plaintext; drop --recipient or use --encryption-type openpgp"
                );
            }
        }
        EncryptionType::Openpgp => {
            if recipients.is_empty() {
                bail!("--encryption-type openpgp requires at least one --recipient");
            }
        }
    }
    if targets.is_empty() {
        bail!("at least one target is required (--local-target and/or --s3-bucket)");
    }
    // Validate recipients before any other work, so a bad/unknown
    // recipient costs nothing (a typo must not cost a full archive run).
    crypto::check_recipients(&recipients)?;

    // Start time, not end time: the file name must be fixed before anything
    // is written, and must never claim content newer than what was captured.
    let stamp = stamp(&OffsetDateTime::now_utc());

    let source = local_source.canonicalize().with_context(|| {
        format!(
            "source directory '{}' does not exist or is not accessible",
            local_source.display()
        )
    })?;
    if !source.is_dir() {
        bail!("source '{}' is not a directory", source.display());
    }

    // Split the declared targets into local directories and the single S3
    // destination. The contract is "at most one S3 target per run"; a second
    // one would otherwise be silently dropped by the Option, so refuse.
    let mut local_dirs: Vec<PathBuf> = Vec::new();
    let mut s3_target: Option<S3Target> = None;
    for target in targets {
        match target {
            Target::Local { dir } => local_dirs.push(dir),
            Target::S3(_) if s3_target.is_some() => {
                bail!("at most one S3 target per run (--s3-* flags configure a single bucket)")
            }
            Target::S3(s3) => s3_target = Some(s3),
        }
    }

    // canonicalize resolves symlinks and `..`, so two spellings of one
    // physical directory collapse to a single entry and are delivered once.
    // The S3 destination has no path, so it skips the nesting checks.
    let mut targets: Vec<PathBuf> = Vec::new();
    let mut seen: HashSet<PathBuf> = HashSet::new();
    for t in &local_dirs {
        fs::create_dir_all(t)
            .with_context(|| format!("create target directory {}", t.display()))?;
        let t = t
            .canonicalize()
            .with_context(|| format!("canonicalize target directory {}", t.display()))?;
        if seen.insert(t.clone()) {
            targets.push(t);
        }
    }
    for target in &targets {
        if *target == source {
            bail!(
                "source and target must be different directories ({})",
                target.display()
            );
        }
        if target.starts_with(&source) || source.starts_with(target) {
            // Otherwise the archive lands inside its own input and gets re-read
            // on the next run.
            bail!(
                "source and target must not be nested ({})",
                target.display()
            );
        }
    }

    let archive_name = format!("{name}-{stamp}.tgz");

    // Refuse before doing any backup work when this run's artifact name
    // already exists in a target: the second-precision timestamp cannot
    // mint a distinct name within the same second, so a re-run would just
    // collide at delivery time. The final extension depends on the
    // encryption mode (.gpg appended for openpgp). `deliver()` repeats this
    // check as a race guard.
    let final_name = match encryption_type {
        EncryptionType::None => archive_name.clone(),
        EncryptionType::Openpgp => format!("{archive_name}.gpg"),
    };
    if !targets.is_empty() {
        deliver::ensure_targets_free(&targets, &final_name)?;
    }
    // Build the S3 client early (fails fast on a malformed endpoint) and
    // check the object is free before any backup work — the same
    // refuse-before-work rule as the local targets.
    let s3_client = match &s3_target {
        Some(s3) => {
            let client = s3::client(s3)?;
            s3::ensure_object_free(&client, &s3::join_prefix(&s3.prefix, &final_name))?;
            Some(client)
        }
        None => None,
    };

    // Scratch holds every intermediate; targets only ever see the finished
    // artifact, and with encryption the plaintext never leaves it.
    let work = tempfile::tempdir().context("create scratch working directory")?;
    let work_path = work.path();
    let snap = work_path.join(format!("{archive_name}.db-part"));

    db::backup(database_type, &source, &snap).with_context(|| "online database backup failed")?;

    let final_path = archive::create(work_path, &archive_name, &snap, &source)?;
    // The snapshot is scratch: its content is in the archive now.
    let _ = fs::remove_file(&snap);

    let final_path = match encryption_type {
        EncryptionType::None => final_path,
        EncryptionType::Openpgp => {
            // The plaintext archive is consumed; only the encrypted one remains.
            crypto::encrypt(&final_path, &recipients)?
        }
    };

    // Deliver to every target, collecting failures so a partial delivery
    // names all failing targets and the successes stay. Local targets keep
    // the existing `deliver` wording.
    let total = targets.len() + usize::from(s3_target.is_some());
    let mut delivered: Vec<Delivered> = Vec::new();
    let mut failures: Vec<String> = Vec::new();
    if !targets.is_empty() {
        match deliver::deliver(&final_path, &targets) {
            Ok(paths) => delivered.extend(paths.into_iter().map(Delivered::Local)),
            Err(err) => failures.push(err.to_string()),
        }
    }
    if let (Some(s3), Some(client)) = (&s3_target, &s3_client) {
        let key = s3::join_prefix(&s3.prefix, &final_name);
        match s3::upload(client, &final_path, &key) {
            Ok(()) => delivered.push(Delivered::S3 {
                bucket: s3.bucket.clone(),
                key,
            }),
            Err(err) => failures.push(format!("s3://{}/{key}: {err:#}", s3.bucket)),
        }
    }
    if failures.is_empty() {
        Ok(delivered)
    } else if failures.len() == 1 {
        // A single failure (typically the local-only case) keeps the
        // original `deliver` wording verbatim.
        bail!("{}", failures[0])
    } else {
        bail!(
            "delivery failed for {} of {} target(s): {}",
            failures.len(),
            total,
            failures.join("; ")
        )
    }
}

/// Format a UTC time stamp as `%Y-%m-%dT%H:%M:%SZ` (second precision).
pub fn stamp(dt: &OffsetDateTime) -> String {
    let fmt = format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
    // The description is a compile-time constant; formatting cannot fail.
    #[allow(clippy::expect_used)]
    dt.format(fmt).expect("format static description")
}

/// The archive name is used verbatim as a file-name prefix: forbid the path
/// separator and NUL, allow anything else (including non-ASCII), and cap the
/// byte length so even the longest artifact this run creates fits a target's
/// 255-byte NAME_MAX. 200 plus the longest suffix (`-<20-char stamp>.tgz.gpg`
/// and the transient delivery `.part.<pid>`) stays under 255 with margin.
const MAX_NAME_BYTES: usize = 200;

fn check_archive_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("--name must not be empty");
    }
    if name.contains('/') || name.contains('\0') {
        bail!("--name must not contain '/' or NUL: {name:?}");
    }
    if name.len() > MAX_NAME_BYTES {
        bail!(
            "--name is too long: {} bytes (max {MAX_NAME_BYTES}; the final file \
             is `<name>-<UTC stamp>.tgz[.gpg]`, and delivery adds a `.part`)",
            name.len()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamp_format_is_iso8601_utc() {
        let dt = OffsetDateTime::from_unix_timestamp(1_784_718_299).unwrap();
        assert_eq!(stamp(&dt), "2026-07-22T11:04:59Z");
    }

    #[test]
    fn stamp_of_now_is_well_formed() {
        let s = stamp(&OffsetDateTime::now_utc());
        assert_eq!(s.len(), 20, "expected %Y-%m-%dT%H:%M:%SZ, got {s:?}");
        assert!(s.ends_with('Z'));
        assert_eq!(&s[4..5], "-");
        assert_eq!(&s[10..11], "T");
        assert_eq!(&s[13..14], ":");
    }

    #[test]
    fn archive_name_with_slash_or_nul_is_rejected() {
        assert!(check_archive_name("a/b").is_err());
        assert!(
            check_archive_name("a\\b").is_ok(),
            "only '/' (and NUL) break file names"
        );
        assert!(check_archive_name("\0").is_err());
        assert!(check_archive_name("").is_err());
        assert!(
            check_archive_name("正常-名字 v1").is_ok(),
            "non-ASCII names are fine"
        );
    }

    #[test]
    fn archive_name_too_long_is_rejected() {
        assert!(check_archive_name(&"a".repeat(MAX_NAME_BYTES)).is_ok());
        assert!(
            check_archive_name(&"a".repeat(MAX_NAME_BYTES + 1)).is_err(),
            "one byte over the cap must fail"
        );
        // The cap counts bytes, not characters: 100 multi-byte chars are 300
        // bytes and must fail even though the char count is low.
        assert!(
            check_archive_name(&"界".repeat(100)).is_err(),
            "multi-byte names are capped in bytes"
        );
    }

    #[test]
    fn run_refuses_two_s3_targets() {
        // The bail fires while splitting targets, before any S3 client or
        // network work, so the S3Target values here are only placeholders.
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("data");
        fs::create_dir_all(&src).unwrap();
        let conn = rusqlite::Connection::open(src.join(DB_FILENAME)).unwrap();
        conn.execute_batch("CREATE TABLE t(v TEXT)").unwrap();
        drop(conn);

        let s3 = S3Target {
            endpoint: "http://127.0.0.1:1".into(),
            region: "us-east-1".into(),
            access_key: "ak".into(),
            secret_key: "sk".into(),
            bucket: "bkt".into(),
            prefix: "/".into(),
            addressing: S3Addressing::PathStyle,
        };
        let err = run(
            src,
            vec![Target::S3(s3.clone()), Target::S3(s3)],
            "x".into(),
            DatabaseType::Sqlite,
            EncryptionType::None,
            Vec::new(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("at most one S3 target"), "{err:?}");
    }

    #[test]
    fn run_aborts_when_artifact_name_already_exists() {
        use rusqlite::Connection;

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let src = root.join("data");
        fs::create_dir_all(&src).unwrap();
        let conn = Connection::open(src.join(DB_FILENAME)).unwrap();
        conn.execute_batch("CREATE TABLE t(v TEXT)").unwrap();
        drop(conn);

        let target = root.join("out");
        // Occupy this run's would-be file name (computed the same way the
        // run does, from the current second) and expect the run to refuse
        // before doing any backup work. Retrying across a few attempts makes
        // the test immune to a second boundary slipping between our stamp
        // and the run's stamp.
        let mut collided = false;
        for _ in 0..5 {
            fs::create_dir_all(&target).unwrap();
            // Wipe whatever the previous attempt delivered, if any.
            for entry in fs::read_dir(&target).unwrap() {
                fs::remove_file(entry.unwrap().path()).unwrap();
            }
            let occupied = format!("x-{}.tgz", stamp(&OffsetDateTime::now_utc()));
            fs::write(target.join(&occupied), b"occupied").unwrap();

            let delivered = run(
                src.clone(),
                vec![Target::Local {
                    dir: target.clone(),
                }],
                "x".into(),
                DatabaseType::Sqlite,
                EncryptionType::None,
                Vec::new(),
            );
            if delivered.is_err() {
                collided = true;
                break;
            }
        }
        assert!(
            collided,
            "a same-second re-run must collide within 5 attempts"
        );
    }
}
