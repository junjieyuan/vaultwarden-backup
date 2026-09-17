//! The database path: a standalone snapshot of `db.sqlite3` via the SQLite
//! Online Backup API, safe to run while the instance is live.

use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, DatabaseName, OpenFlags};

use crate::{DB_FILENAME, DatabaseType};

/// Back up the database in the data directory `source` to a standalone
/// snapshot at `dst`, dispatching on `database_type`.
pub fn backup(database_type: DatabaseType, source: &Path, dst: &Path) -> Result<()> {
    match database_type {
        DatabaseType::Sqlite => {
            let src_db = source.join(DB_FILENAME);
            if !src_db.is_file() {
                bail!(
                    "no {} in source directory {} (is this a vaultwarden data directory?)",
                    DB_FILENAME,
                    source.display()
                );
            }
            backup_sqlite(&src_db, dst)
        }
    }
}

/// Write a standalone snapshot of `src_db` to `dst`.
///
/// Opened read-only so a live vaultwarden is never blocked and no `-shm`
/// side file appears next to the source database.
fn backup_sqlite(src_db: &Path, dst: &Path) -> Result<()> {
    let src = Connection::open_with_flags(src_db, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("open database {}", src_db.display()))?;
    // Retry inside SQLite for a short while instead of failing on the first
    // transient `SQLITE_BUSY` (e.g. a write txn being committed right now).
    src.busy_timeout(Duration::from_secs(10))
        .context("set busy timeout")?;

    // The Online Backup API writes a fresh file; a leftover from a crashed
    // run would otherwise poison the result.
    if dst.exists() {
        fs::remove_file(dst).with_context(|| format!("remove stale {}", dst.display()))?;
    }

    match src.backup(DatabaseName::Main, dst, None) {
        Ok(()) => Ok(()),
        Err(e) => {
            let msg = e.to_string();
            // SQLITE_BUSY / SQLITE_LOCKED surface when the source is holding
            // a long write transaction; give an actionable message.
            let lower = msg.to_lowercase();
            if lower.contains("busy") || lower.contains("locked") {
                bail!(
                    "database is busy while backing up (the source may be holding a long \
                     write transaction). Try again shortly, or stop the vaultwarden \
                     instance first ({msg})"
                );
            }
            Err(anyhow::Error::new(e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_produces_standalone_snapshot() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("db.sqlite3");
        let conn = Connection::open(&src).unwrap();
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE t(v TEXT);
             INSERT INTO t(v) VALUES ('x');",
        )
        .unwrap();

        let dst = tmp.path().join("snap.sqlite3");
        backup_sqlite(&src, &dst).unwrap();

        // The snapshot is a standalone DB with the row, even though the source
        // is still open (WAL active).
        let conn2 = Connection::open(&dst).unwrap();
        let n: i64 = conn2
            .query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
    }
}
