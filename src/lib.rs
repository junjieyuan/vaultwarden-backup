//! Back up a vaultwarden `DATA_FOLDER` to a single timestamped `.tgz` and
//! deliver one copy to every local target.
//!
//! The data directory's contents sit directly at the archive root (no
//! top-level directory), so restoring is `tar -x -C <data dir>`; the
//! `db.sqlite3` entry is the online snapshot, not a copy of the file.
//!
//! Every intermediate artifact (database snapshot, `.tgz`, `.tgz.gpg`)
//! lives in a scratch directory (`tempfile::tempdir()`, honoring `TMPDIR`)
//! and is copied to the targets only once finished, so a run never touches
//! a target until the final artifact is ready.

// `unwrap`/`expect` are denied project-wide (Cargo.toml `[lints.clippy]`);
// test builds are exempted here, production code is not.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod archive;
pub mod crypto;
pub mod db;
pub mod deliver;
pub mod files;

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

/// File name of the vaultwarden SQLite database inside the data directory.
pub const DB_FILENAME: &str = "db.sqlite3";

/// Run one backup into every local target; returns one path per target, in
/// the same order as `local_targets`.
pub fn run(
    local_source: PathBuf,
    local_targets: Vec<PathBuf>,
    name: String,
    database_type: DatabaseType,
    encryption_type: EncryptionType,
    recipients: Vec<String>,
) -> Result<Vec<PathBuf>> {
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
    if local_targets.is_empty() {
        bail!("at least one target is required (--local-target)");
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

    // canonicalize resolves symlinks and `..`, so two spellings of one
    // physical directory collapse to a single entry and are delivered once.
    let mut targets: Vec<PathBuf> = Vec::new();
    let mut seen: HashSet<PathBuf> = HashSet::new();
    for t in &local_targets {
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
    deliver::ensure_targets_free(&targets, &final_name)?;

    // Everything between the snapshot and the delivered artifact lives in a
    // scratch directory: no intermediate ever touches a target, and neither
    // does the plaintext archive when encryption is on.
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

    deliver::deliver(&final_path, &targets)
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
                vec![target.clone()],
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
