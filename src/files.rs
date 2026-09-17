//! Everything except the database: stream every regular file under the source
//! directory into the archive.
//!
//! The database file and its `-wal`/`-shm` sidecars are skipped because the
//! online snapshot already includes any WAL contents — copying them would
//! hand the restore a WAL that does not belong to the snapshot.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use std::os::unix::fs::PermissionsExt;
use tar::Builder;

/// Stream every regular file under `src` into `builder`, with the data
/// directory's contents directly at the archive root (no top-level
/// directory).
///
/// Skips `db_name` and its `{db_name}-*` sidecars (the database path owns the
/// `db.sqlite3` entry), and skips symlinks, other special files, and empty
/// directories with a warning on stderr.
///
/// Traversal is iterative (an explicit entry stack): expanding a directory
/// pushes its children onto the stack in reverse name order so `pop()`
/// yields them ascending — the same depth-first, lexicographic entry order as
/// a recursive walk, without the call-stack depth limit.
pub fn write<W: std::io::Write>(builder: &mut Builder<W>, src: &Path, db_name: &str) -> Result<()> {
    let mut stack: Vec<(String, PathBuf)> = Vec::new();
    push_children(&mut stack, "", src, db_name)?;

    while let Some((arc_name, path)) = stack.pop() {
        let meta =
            fs::symlink_metadata(&path).with_context(|| format!("stat {}", path.display()))?;
        let file_type = meta.file_type();

        if file_type.is_symlink() {
            eprintln!("warning: skipping symlink {}", path.display());
            continue;
        }
        if file_type.is_dir() {
            // An empty directory carries no data; skipping it loses nothing.
            if fs::read_dir(&path)?.next().is_none() {
                eprintln!("warning: skipping empty directory {}", path.display());
                continue;
            }
            push_children(&mut stack, &arc_name, &path, db_name)?;
        } else if file_type.is_file() {
            let mut file =
                fs::File::open(&path).with_context(|| format!("open file {}", path.display()))?;
            // The tar record's size field must equal the bytes actually
            // streamed, or everything after this entry is unreadable.
            // vaultwarden rewrites files (icon_cache/, config.json, ...) while
            // running, so the walk's earlier stat can already be stale:
            // re-verify at open, and again after the copy.
            let opened = file
                .metadata()
                .with_context(|| format!("stat {}", path.display()))?;
            if opened.len() != meta.len() {
                bail!(
                    "file {} changed while being archived (size {} -> {}); re-run the backup",
                    path.display(),
                    meta.len(),
                    opened.len()
                );
            }
            let mut header = tar::Header::new_ustar();
            header.set_size(opened.len());
            header.set_mode(opened.permissions().mode() & 0o7777);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(mtime_of(&opened, &path)?);
            builder
                .append_data(&mut header, &arc_name, &mut file)
                .with_context(|| format!("append {}", arc_name))?;
            let after =
                fs::symlink_metadata(&path).with_context(|| format!("stat {}", path.display()))?;
            if file_changed(&opened, &after) {
                bail!(
                    "file {} changed while being archived; re-run the backup",
                    path.display()
                );
            }
        } else {
            eprintln!("warning: skipping special file {}", path.display());
        }
    }
    Ok(())
}

/// Push every entry of `dir` onto `stack` in *reverse* name order so the
/// stack pops them in ascending name order. `db_name` and its sidecars are
/// skipped here. `arc_root` is the directory's archive path; a root of ""
/// (the archive root itself) must not gain a leading slash — tar entry
/// names are relative.
fn push_children(
    stack: &mut Vec<(String, PathBuf)>,
    arc_root: &str,
    dir: &Path,
    db_name: &str,
) -> Result<()> {
    let mut entries: Vec<PathBuf> = Vec::new();
    for e in fs::read_dir(dir).with_context(|| format!("read directory {}", dir.display()))? {
        entries.push(e?.path());
    }
    entries.sort();
    for path in entries.into_iter().rev() {
        let name = path
            .file_name()
            .context("entry has no file name")?
            .to_string_lossy()
            .to_string();
        // Only the source root's own database and sidecars are skipped:
        // deeper files with the same name are ordinary files and archived.
        if arc_root.is_empty() && (name == db_name || name.starts_with(&format!("{db_name}-"))) {
            continue;
        }
        let arc_name = if arc_root.is_empty() {
            name
        } else {
            format!("{arc_root}/{name}")
        };
        stack.push((arc_name, path));
    }
    Ok(())
}

/// True when `after` looks different from `before` for the same path: a
/// different size, or a different mtime (catches a size-stable rewrite).
/// Reading the mtime is best-effort — a platform that cannot report it
/// counts as unchanged rather than failing the run.
fn file_changed(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    after.len() != before.len() || after.modified().ok() != before.modified().ok()
}

/// Modification time of `meta` as seconds since the epoch (1970-01-01 when
/// the timestamp predates it).
fn mtime_of(meta: &fs::Metadata, path: &Path) -> Result<u64> {
    let modified = meta
        .modified()
        .with_context(|| format!("read mtime of {}", path.display()))?;
    Ok(modified
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry_names(d: &Path) -> Vec<String> {
        let cursor = std::io::Cursor::new(Vec::new());
        let mut builder = tar::Builder::new(cursor);
        write(&mut builder, d, "db.sqlite3").expect("write");
        let cursor = builder.into_inner().expect("finish builder");
        let bytes = cursor.into_inner();

        let mut names = Vec::new();
        let mut archive = tar::Archive::new(&bytes[..]);
        for entry in archive.entries().unwrap() {
            let e = entry.expect("entry");
            names.push(e.path().unwrap().to_string_lossy().to_string());
        }
        names
    }

    #[test]
    fn write_streams_regular_files_and_skips_db_and_special() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        fs::write(d.join("b.txt"), b"bbb").unwrap();
        fs::write(d.join("a.txt"), b"aa").unwrap();
        // The database file and its sidecars must be skipped (not followed).
        fs::write(d.join("db.sqlite3"), b"rawdb").unwrap();
        fs::write(d.join("db.sqlite3-wal"), b"wal").unwrap();
        fs::write(d.join("db.sqlite3-shm"), b"shm").unwrap();
        let sub = d.join("sub");
        fs::create_dir(&sub).unwrap();
        fs::write(sub.join("c.txt"), b"cc").unwrap();
        // A *nested* file named like the database is not the database: the
        // db-skip applies to the source root only.
        fs::write(sub.join("db.sqlite3"), b"nested").unwrap();
        // An empty directory should be skipped with a warning, not an error.
        let empty = d.join("empty");
        fs::create_dir(&empty).unwrap();
        // A symlink should be skipped, not followed.
        std::os::unix::fs::symlink(d.join("a.txt"), d.join("link.txt")).unwrap();
        // A socket file is a special file: skipped, never read.
        let _listener = std::os::unix::net::UnixListener::bind(d.join("sock.sock")).unwrap();

        let names = entry_names(d);
        assert_eq!(
            names,
            vec!["a.txt", "b.txt", "sub/c.txt", "sub/db.sqlite3"],
            "archive root is the data directory itself (no top-level dir)"
        );
        let _ = empty; // kept on disk so the walk visits (and warns about) it
    }

    #[test]
    fn preserves_mode_and_mtime() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let f = d.join("f.txt");
        fs::write(&f, b"x").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o600)).unwrap();
        let want_mtime = fs::metadata(&f)
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let cursor = std::io::Cursor::new(Vec::new());
        let mut builder = tar::Builder::new(cursor);
        write(&mut builder, d, "db.sqlite3").unwrap();
        let cursor = builder.into_inner().unwrap();
        let bytes = cursor.into_inner();
        let mut archive = tar::Archive::new(&bytes[..]);
        let mut entries = archive.entries().unwrap();
        let entry = entries.next().unwrap().unwrap();

        assert_eq!(entry.path().unwrap().to_string_lossy(), "f.txt");
        assert_eq!(entry.header().mode().unwrap(), 0o600);
        assert_eq!(entry.header().mtime().unwrap(), want_mtime);
    }

    #[test]
    fn deep_directory_tree_does_not_overflow() {
        let dir = tempfile::tempdir().unwrap();
        // 1.2k one-character segments stay under PATH_MAX while being far
        // deeper than a recursive walk could handle.
        let mut deep = dir.path().to_path_buf();
        for _ in 0..1_200 {
            deep = deep.join("d");
        }
        fs::create_dir_all(&deep).unwrap();
        fs::write(deep.join("leaf.txt"), b"x").unwrap();

        let names = entry_names(dir.path());
        assert_eq!(names.len(), 1, "{names:?}");
        assert!(names[0].ends_with("leaf.txt"), "{names:?}");
    }

    #[test]
    fn entry_order_is_depth_first_lexicographic() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        // A subdirectory before and after an in-between file, plus two
        // subdirectories: entry order must be a depth-first, lexicographic
        // walk (a/... before b.txt before z/...), matching the original
        // recursive traversal.
        fs::create_dir(d.join("z")).unwrap();
        fs::create_dir(d.join("a")).unwrap();
        fs::write(d.join("z/m.txt"), b"z").unwrap();
        fs::write(d.join("a/m.txt"), b"a").unwrap();
        fs::write(d.join("b.txt"), b"b").unwrap();

        let names = entry_names(d);
        assert_eq!(
            names,
            vec!["a/m.txt", "b.txt", "z/m.txt"],
            "depth-first lexicographic order: {names:?}"
        );
    }

    #[test]
    fn file_changed_detects_size_and_mtime_drift() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("f");
        fs::write(&f, b"12345").unwrap();
        let before = fs::metadata(&f).unwrap();
        assert!(
            !file_changed(&before, &fs::metadata(&f).unwrap()),
            "the same file must count as unchanged"
        );

        // A size change is always detected.
        fs::write(&f, b"123456").unwrap();
        assert!(file_changed(&before, &fs::metadata(&f).unwrap()));

        // A same-size rewrite is detected via mtime (the walk->copy window
        // race this guards against is not deterministically reproducible, so
        // the comparison itself is tested here).
        fs::write(&f, b"abcde").unwrap();
        let before = fs::metadata(&f).unwrap();
        let fh = fs::OpenOptions::new().write(true).open(&f).unwrap();
        fh.set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(3600))
            .unwrap();
        drop(fh);
        assert!(file_changed(&before, &fs::metadata(&f).unwrap()));
    }
}
