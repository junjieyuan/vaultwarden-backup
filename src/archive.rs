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
        let snap_len = fs::metadata(snapshot)
            .with_context(|| format!("stat snapshot {}", snapshot.display()))?
            .len();

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
            header.set_mtime(0);
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
