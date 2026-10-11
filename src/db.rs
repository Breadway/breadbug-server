//! SQLite storage. One connection behind a mutex, used from blocking tasks.

use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};

use crate::crypto::ct_eq;

/// A report ready to store. `raw` is the already-scrubbed JSON.
pub struct NewReport<'a> {
    pub receipt: &'a str,
    pub token_hash: &'a str,
    pub install_hash: &'a str,
    pub payload_sha: &'a str,
    pub received_at: u64,
    pub app: &'a str,
    pub app_version: Option<&'a str>,
    pub report_type: &'a str,
    pub quarantined: bool,
    pub rescrub_hits: &'a str,
    pub raw: &'a str,
}

pub struct Db {
    conn: Mutex<Connection>,
}

const MIGRATIONS: &[&str] = &[
    // 1: reports
    "CREATE TABLE reports (
        id            INTEGER PRIMARY KEY,
        receipt       TEXT NOT NULL UNIQUE,
        token_hash    TEXT NOT NULL,
        install_hash  TEXT NOT NULL,
        payload_sha   TEXT NOT NULL,
        received_at   INTEGER NOT NULL,
        app           TEXT NOT NULL,
        app_version   TEXT,
        report_type   TEXT NOT NULL,
        status        TEXT NOT NULL DEFAULT 'received',
        quarantined   INTEGER NOT NULL DEFAULT 0,
        rescrub_hits  TEXT NOT NULL DEFAULT '{}',
        raw           TEXT NOT NULL
    );
    CREATE INDEX reports_received ON reports(received_at);
    CREATE UNIQUE INDEX reports_dedupe ON reports(install_hash, payload_sha);
    CREATE INDEX reports_app ON reports(app, received_at);",
];

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).with_context(|| format!("open {}", path.display()))?;
        Self::init(conn)
    }

    /// An in-memory database (tests and tools).
    pub fn open_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = ON;
             PRAGMA secure_delete = ON;",
        )?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        for (i, sql) in MIGRATIONS.iter().enumerate().skip(version as usize) {
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(sql)?;
            tx.pragma_update(None, "user_version", (i + 1) as i64)?;
            tx.commit()?;
        }
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The receipt of an identical earlier report from the same install.
    pub fn find_duplicate(&self, install_hash: &str, payload_sha: &str) -> Result<Option<String>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT receipt FROM reports WHERE install_hash = ?1 AND payload_sha = ?2",
                params![install_hash, payload_sha],
                |r| r.get(0),
            )
            .optional()?)
    }

    pub fn insert_report(&self, r: &NewReport<'_>) -> Result<i64> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO reports (receipt, token_hash, install_hash, payload_sha, received_at,
                                  app, app_version, report_type, quarantined, rescrub_hits, raw)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                r.receipt,
                r.token_hash,
                r.install_hash,
                r.payload_sha,
                r.received_at as i64,
                r.app,
                r.app_version,
                r.report_type,
                r.quarantined as i64,
                r.rescrub_hits,
                r.raw
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Delete a report if `token_hash` matches. Returns whether it existed
    /// and matched; a wrong token and an unknown receipt look the same.
    pub fn delete_report(&self, receipt: &str, token_hash: &str) -> Result<bool> {
        let conn = self.conn();
        let stored: Option<String> = conn
            .query_row(
                "SELECT token_hash FROM reports WHERE receipt = ?1",
                params![receipt],
                |r| r.get(0),
            )
            .optional()?;
        match stored {
            Some(h) if ct_eq(&h, token_hash) => {
                conn.execute("DELETE FROM reports WHERE receipt = ?1", params![receipt])?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Delete raw reports received before `cutoff_unix`. Returns the count.
    pub fn purge_before(&self, cutoff_unix: u64) -> Result<usize> {
        Ok(self.conn().execute(
            "DELETE FROM reports WHERE received_at < ?1",
            params![cutoff_unix as i64],
        )?)
    }

    /// Delete the oldest reports until at most `keep` remain.
    pub fn trim_to(&self, keep: usize) -> Result<usize> {
        Ok(self.conn().execute(
            "DELETE FROM reports WHERE id IN (
                SELECT id FROM reports ORDER BY received_at ASC, id ASC
                LIMIT max(0, (SELECT count(*) FROM reports) - ?1))",
            params![keep as i64],
        )?)
    }

    /// Evict one oldest raw report. Retention/quota eviction preserves any
    /// historical cluster aggregates supplied by the clustering layer.
    pub fn evict_oldest(&self) -> Result<bool> {
        Ok(self.conn().execute(
            "DELETE FROM reports WHERE id = (SELECT id FROM reports ORDER BY received_at, id LIMIT 1)",
            [],
        )? > 0)
    }

    pub fn report_count(&self) -> Result<usize> {
        Ok(self
            .conn()
            .query_row("SELECT count(*) FROM reports", [], |r| r.get::<_, i64>(0))?
            as usize)
    }

    /// Whether a stored report was quarantined by the server-side scrub.
    pub fn is_quarantined(&self, receipt: &str) -> Result<Option<bool>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT quarantined FROM reports WHERE receipt = ?1",
                params![receipt],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
            .map(|q| q != 0))
    }

    pub fn status_of(&self, receipt: &str) -> Result<Option<String>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT status FROM reports WHERE receipt = ?1",
                params![receipt],
                |r| r.get(0),
            )
            .optional()?)
    }

    pub fn raw_of(&self, receipt: &str) -> Result<Option<String>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT raw FROM reports WHERE receipt = ?1",
                params![receipt],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Fold the WAL back and reclaim freed pages so deleted data really
    /// leaves the disk.
    pub fn compact(&self) -> Result<()> {
        let conn = self.conn();
        conn.execute_batch(
            "PRAGMA wal_checkpoint(TRUNCATE); VACUUM; PRAGMA wal_checkpoint(TRUNCATE);",
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
