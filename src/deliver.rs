//! Delivery of the finished artifact to local targets: copy to every local
//! target atomically (`.part` -> fsync -> rename), refusing to overwrite an
//! archive that already exists. S3-compatible delivery lives in `s3.rs`.

use std::fs;
use std::mem::DropGuard;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use time::OffsetDateTime;

use crate::{RetentionPeriod, archive_stamp, should_delete};

/// Copy the finished artifact to every local target, atomically per target
/// (`.part` -> rename), returning one outcome per target: `Ok(dest)` for a
/// delivered copy, `Err(reason)` for a failed one. The per-target
/// existence check is the race guard against a concurrent run; `run`
/// aggregates the outcomes.
pub(crate) fn deliver(
    final_path: &Path,
    file_name: &str,
    targets: &[PathBuf],
) -> Vec<Result<PathBuf, String>> {
    let mut outcomes: Vec<Result<PathBuf, String>> = Vec::new();
    for target in targets {
        let dest = target.join(file_name);
        // Between the pre-check in `run()` and the copy a concurrent run
        // could place the file; refuse to silently overwrite it.
        if dest.exists() {
            outcomes.push(Err(format!(
                "{}: {file_name} already exists",
                target.display()
            )));
            continue;
        }
        // A per-process part name: two concurrent runs delivering to the same
        // directory must never share a `.part` file, or one could rename
        // the other's half-written copy under the final name.
        let part = target.join(format!("{file_name}.part.{}", std::process::id()));
        match deliver_one(final_path, &part, &dest) {
            Ok(()) => outcomes.push(Ok(dest)),
            Err(err) => outcomes.push(Err(format!("{}: {err:#}", target.display()))),
        }
    }
    outcomes
}

/// One delivery: `fs::copy` over a unique `.part.<pid>` name, fsync, then
/// atomic rename (with a best-effort directory fsync), so the destination
/// never shows a partial file and a stale `.part` from a crashed run is
/// overwritten, not mixed.
fn deliver_one(final_path: &Path, part: &Path, dest: &Path) -> Result<()> {
    // The guard removes the half-written part on every exit path (including
    // `?` and panic); on success the rename already took it.
    let part = DropGuard::new(part.to_path_buf(), |part| {
        let _ = fs::remove_file(&part);
    });

    fs::copy(final_path, &*part).with_context(|| format!("copy artifact to {}", part.display()))?;
    // Make sure the copy is on disk before it becomes visible under the
    // final name; otherwise a crash right after the rename could leave
    // an empty or partial file under the target's name.
    fs::File::open(&*part)
        .and_then(|f| f.sync_all())
        .with_context(|| format!("fsync {}", part.display()))?;
    fs::rename(&*part, dest)
        .with_context(|| format!("rename {} -> {}", part.display(), dest.display()))?;
    // Persist the directory entry created by the rename. Some file
    // systems (FUSE mounts, some network/NAS file systems, tmpfs)
    // return EINVAL or ENOTSUP for a directory fsync; the archive
    // itself is already durable, so degrade to a warning instead of
    // failing the target on data that is already in place.
    if let Some(dir) = dest.parent()
        && let Err(e) = fs::File::open(dir).and_then(|d| d.sync_all())
    {
        eprintln!(
            "warning: could not fsync target directory {} ({e}); \
             the archive itself was already fsynced",
            dir.display()
        );
    }
    Ok(())
}

/// Best-effort retention cleanup for one local target: delete this run's own
/// archives (`<name>-<UTC stamp>.tgz[.gpg]`) whose stamp is older than
/// `period`. A failure here must never break a successful backup, so this
/// returns `()` and reports problems on stderr, then keeps going — a single
/// unreadable entry cannot stop the cleanup of the rest.
pub(crate) fn cleanup_retention(
    dir: &Path,
    name: &str,
    own_stamp: &str,
    now: OffsetDateTime,
    period: &RetentionPeriod,
) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) => {
            eprintln!(
                "retention: cannot read target {} for cleanup ({err}); leaving it unchanged",
                dir.display()
            );
            return;
        }
    };
    for entry in entries {
        let Ok(entry) = entry else {
            eprintln!(
                "retention: cannot read an entry in {}; skipping it",
                dir.display()
            );
            continue;
        };
        let file_name = entry.file_name().to_string_lossy().into_owned();
        // Only regular files can be archives; skip subdirectories and other
        // types (a symlink is not a file, so it is skipped too).
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_file() {
            continue;
        }
        let Some(stamp) = archive_stamp(&file_name, name) else {
            continue;
        };
        if !should_delete(own_stamp, &stamp, &now, period) {
            continue;
        }
        let path = entry.path();
        if let Err(err) = fs::remove_file(&path) {
            eprintln!(
                "retention: warning: cannot remove {} ({err}); keeping it",
                path.display()
            );
            continue;
        }
        eprintln!("retention: removed {}", path.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_delivery_failure_names_targets_and_keeps_successes() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        // `a` is a real directory; `b` is a regular file, so copying into it
        // fails at delivery time while the existence pre-checks (which only
        // stat) still pass.
        let a = root.join("a");
        fs::create_dir_all(&a).unwrap();
        let b = root.join("b");
        fs::write(&b, b"not a directory").unwrap();

        let artifact = root.join("art.tgz");
        fs::write(&artifact, b"payload").unwrap();

        let outcomes = deliver(&artifact, "art.tgz", &[a.clone(), b.clone()]);
        // The independent good target is still delivered.
        assert!(
            outcomes[0].is_ok(),
            "the independent good target is still delivered"
        );
        assert_eq!(fs::read(a.join("art.tgz")).unwrap(), b"payload");
        let err = outcomes[1].as_ref().unwrap_err();
        assert!(
            err.contains(&b.display().to_string()),
            "the failing target must be named: {err}"
        );
    }

    #[test]
    fn existing_name_fails_only_its_own_target() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let a = root.join("a");
        let b = root.join("b");
        fs::create_dir_all(&a).unwrap();
        fs::create_dir_all(&b).unwrap();

        let artifact = root.join("art.tgz");
        fs::write(&artifact, b"payload").unwrap();
        // `b` already holds this run's file name: only `b` fails, `a` is
        // still delivered.
        fs::write(b.join("art.tgz"), b"old").unwrap();

        let outcomes = deliver(&artifact, "art.tgz", &[a.clone(), b.clone()]);
        assert!(
            outcomes[0].is_ok(),
            "a same-name collision in one target must not stop the others"
        );
        assert_eq!(fs::read(a.join("art.tgz")).unwrap(), b"payload");
        let err = outcomes[1].as_ref().unwrap_err();
        assert!(
            err.contains("already exists"),
            "the collision must be named per target: {err}"
        );
    }
}
