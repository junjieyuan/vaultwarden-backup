//! Packaging and compression: turn the database snapshot and the rest of the
//! source directory into the final `.tgz`.
//!
//! `tar::Builder<W>` only requires `W: Write` (headers are written in order
//! and sizes are known up front, so no seeking is needed), which lets the tar
//! stream straight into a gzip writer: one pass, no uncompressed scratch
//! file. All artifacts (`.part`, final `.tgz`) live in the working directory
//! passed in — the caller runs this in a scratch directory and copies the
//! finished archive to the targets itself.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use flate2::Compression;
use flate2::write::GzEncoder;
use tar::Builder;

use crate::DB_FILENAME;
use crate::files;

/// Produce `<archive_name>` in the working directory `workdir`: tar
/// (snapshot entry + `source` contents) gzipped to `.part` -> atomic rename.
pub fn create(
    workdir: &Path,
    archive_name: &str,
    snapshot: &Path,
    source: &Path,
) -> Result<PathBuf> {
    let part = workdir.join(format!("{archive_name}.part"));
    let final_path = workdir.join(archive_name);

    let result = (|| {
        // The snapshot's metadata is needed twice (size for the header, mtime
        // so the restored db.sqlite3 carries its backup time), so stat once.
        let snap_meta = fs::metadata(snapshot)
            .with_context(|| format!("stat snapshot {}", snapshot.display()))?;
        let snap_len = snap_meta.len();

        let part_file =
            fs::File::create(&part).with_context(|| format!("create {}", part.display()))?;
        let encoder = GzEncoder::new(part_file, Compression::new(6));
        let mut builder = Builder::new(encoder);

        // The `db.sqlite3` entry is the snapshot, so the archive is consistent
        // on its own; the data directory's contents sit directly at the archive
        // root.
        {
            let mut snap_file = fs::File::open(snapshot)
                .with_context(|| format!("open snapshot {}", snapshot.display()))?;
            let mut header = tar::Header::new_ustar();
            header.set_size(snap_len);
            header.set_mode(0o644);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(files::mtime_of(&snap_meta, snapshot)?);
            builder
                .append_data(&mut header, DB_FILENAME, &mut snap_file)
                .with_context(|| format!("append {DB_FILENAME} to archive"))?;
        }

        files::write(&mut builder, source, DB_FILENAME)?;

        // Close the tar stream first (writes the end-of-archive block), then the
        // gzip trailer.
        let encoder = builder
            .into_inner()
            .with_context(|| "finalize tar stream")?;
        encoder
            .finish()
            .with_context(|| format!("write gzip trailer to {}", part.display()))?;

        // Atomic publish: the final name appears only once fully written.
        fs::rename(&part, &final_path)
            .with_context(|| format!("rename {} -> {}", part.display(), final_path.display()))?;

        Ok(final_path)
    })();
    if result.is_err() {
        // Never leave a half-written artifact under the final name's parent.
        let _ = fs::remove_file(&part);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn snapshot_entry_preserves_snapshot_mtime() {
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path();
        let snap = work.join("snap.db");
        fs::write(&snap, b"snapshot payload").unwrap();
        // Pin a recognizable mtime: far from the epoch and from "now", so the
        // header value can only come from the snapshot, not from happenstance.
        let want = 1_700_000_000u64;
        let fh = fs::OpenOptions::new().write(true).open(&snap).unwrap();
        fh.set_modified(UNIX_EPOCH + Duration::from_secs(want))
            .unwrap();
        drop(fh);

        let src = work.join("src");
        fs::create_dir(&src).unwrap();
        let final_path = create(work, "vault.tgz", &snap, &src).unwrap();

        let bytes = fs::read(&final_path).unwrap();
        let mut decoded = Vec::new();
        flate2::read::GzDecoder::new(&bytes[..])
            .read_to_end(&mut decoded)
            .unwrap();
        let mut archive = tar::Archive::new(&decoded[..]);
        let mut entries = archive.entries().unwrap();
        let mut entry = entries.next().unwrap().unwrap();
        assert_eq!(entry.path().unwrap().to_string_lossy(), "db.sqlite3");
        assert_eq!(entry.header().mtime().unwrap(), want);
        // The payload is intact under the preserved header.
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"snapshot payload");
    }
}
