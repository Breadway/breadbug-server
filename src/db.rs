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

/// `(id, token_hash, install_hash, cluster_id, app_version, raw)`.
type DeleteRow = (i64, String, String, Option<i64>, Option<String>, String);

/// `(build_id, app, app_version, count)` of symbols we were asked for but lack.
pub type MissingSymbols = (String, String, Option<String>, u64);

/// A report shown as evidence in the triage view.
#[derive(Debug, Clone)]
pub struct SampleRow {
    pub id: i64,
    pub receipt: String,
    pub received_at: u64,
    pub app_version: Option<String>,
    pub raw: String,
}

/// A quarantined report awaiting review.
#[derive(Debug, Clone)]
pub struct QuarantineRow {
    pub id: i64,
    pub receipt: String,
    pub received_at: u64,
    pub app: String,
    pub hits: String,
    pub raw: String,
}

/// Statuses a human can put a cluster in.
pub const STATUSES: &[&str] = &[
    "new",
    "investigating",
    "dismissed",
    "promoted",
    "fixed",
    "regressed",
];

/// `(cluster id, centroid, reports folded into it)`.
pub type FuzzyCandidate = (i64, Vec<f32>, u64);

/// A stored report, for maintenance jobs.
pub struct StoredReport {
    pub id: i64,
    pub install_hash: String,
    pub app_version: Option<String>,
    pub cluster_id: Option<i64>,
    pub raw: String,
}

/// What a report contributes to a cluster.
pub struct Contribution<'a> {
    pub report_id: i64,
    pub install_hash: &'a str,
    pub version: Option<&'a str>,
    pub os_build: Option<&'a str>,
    pub at: u64,
}

/// A cluster as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterRow {
    pub id: i64,
    pub app: String,
    pub kind: String,
    pub fingerprint: Option<String>,
    pub title: String,
    pub status: String,
    pub first_seen: u64,
    pub last_seen: u64,
    pub count: u64,
    pub installs: u64,
    pub versions: std::collections::BTreeMap<String, u64>,
    pub os_builds: std::collections::BTreeMap<String, u64>,
    pub fixed_in: Option<String>,
    pub issue_key: Option<String>,
    pub merged_into: Option<i64>,
}

pub struct Db {
    conn: Mutex<Connection>,
}

fn bump(map_json: &str, key: Option<&str>) -> String {
    let mut m: std::collections::BTreeMap<String, u64> =
        serde_json::from_str(map_json).unwrap_or_default();
    if let Some(k) = key {
        *m.entry(k.chars().take(64).collect()).or_default() += 1;
    }
    serde_json::to_string(&m).unwrap_or_else(|_| "{}".into())
}

fn unbump(map_json: &str, key: Option<&str>) -> String {
    let mut m: std::collections::BTreeMap<String, u64> =
        serde_json::from_str(map_json).unwrap_or_default();
    if let Some(k) = key {
        let k: String = k.chars().take(64).collect();
        if let Some(n) = m.get_mut(&k) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                m.remove(&k);
            }
        }
    }
    serde_json::to_string(&m).unwrap_or_else(|_| "{}".into())
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
    // 2: clusters
    "ALTER TABLE reports ADD COLUMN cluster_id INTEGER;
    CREATE TABLE clusters (
        id          INTEGER PRIMARY KEY,
        app         TEXT NOT NULL,
        kind        TEXT NOT NULL,
        fingerprint TEXT,
        title       TEXT NOT NULL,
        status      TEXT NOT NULL DEFAULT 'new',
        first_seen  INTEGER NOT NULL,
        last_seen   INTEGER NOT NULL,
        count       INTEGER NOT NULL DEFAULT 0,
        versions    TEXT NOT NULL DEFAULT '{}',
        os_builds   TEXT NOT NULL DEFAULT '{}',
        fixed_in    TEXT,
        issue_key   TEXT,
        merged_into INTEGER
    );
    CREATE UNIQUE INDEX clusters_fp ON clusters(app, fingerprint) WHERE fingerprint IS NOT NULL;
    CREATE TABLE cluster_installs (
        cluster_id   INTEGER NOT NULL,
        install_hash TEXT NOT NULL,
        PRIMARY KEY (cluster_id, install_hash)
    );
    CREATE INDEX reports_cluster ON reports(cluster_id);",
    // 3: build-ids we were asked to symbolicate but have no symbols for
    "CREATE TABLE missing_symbols (
        build_id    TEXT PRIMARY KEY,
        app         TEXT NOT NULL,
        app_version TEXT,
        first_seen  INTEGER NOT NULL,
        last_seen   INTEGER NOT NULL,
        count       INTEGER NOT NULL DEFAULT 1
    );",
    // 4: fuzzy-cluster centroids
    "ALTER TABLE clusters ADD COLUMN embedding BLOB;
    ALTER TABLE clusters ADD COLUMN emb_n INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE clusters ADD COLUMN emb_model TEXT;",
    // 5: banned installs
    "CREATE TABLE bans (
        install_hash TEXT PRIMARY KEY,
        reason       TEXT NOT NULL,
        banned_at    INTEGER NOT NULL
    );",
    // 6: promotion bookkeeping
    "ALTER TABLE clusters ADD COLUMN notified_count INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE clusters ADD COLUMN issue_priority TEXT;",
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
    /// and matched; a wrong token and an unknown receipt look the same. The
    /// report's cluster count (and per-version counts) go down with it.
    pub fn delete_report(&self, receipt: &str, token_hash: &str) -> Result<bool> {
        let conn = self.conn();
        let row: Option<DeleteRow> = conn
            .query_row(
                "SELECT id, token_hash, install_hash, cluster_id, app_version, raw
                 FROM reports WHERE receipt = ?1",
                params![receipt],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((id, stored, install, cluster, version, raw)) = row else {
            return Ok(false);
        };
        if !ct_eq(&stored, token_hash) {
            return Ok(false);
        }
        let tx = conn.unchecked_transaction()?;
        Self::detach(&tx, id, cluster, &install, version.as_deref(), &raw)?;
        tx.execute("DELETE FROM reports WHERE id = ?1", params![id])?;
        tx.commit()?;
        Ok(true)
    }

    /// Take a report out of its cluster's counters (the report row itself is
    /// left to the caller).
    fn detach(
        tx: &Connection,
        report_id: i64,
        cluster: Option<i64>,
        install: &str,
        version: Option<&str>,
        raw: &str,
    ) -> Result<()> {
        let Some(cid) = cluster else {
            return Ok(());
        };
        let os_build = serde_json::from_str::<serde_json::Value>(raw)
            .ok()
            .and_then(|v| v["system"]["os_build"].as_str().map(String::from));
        let (versions, os_builds): (String, String) = tx.query_row(
            "SELECT versions, os_builds FROM clusters WHERE id = ?1",
            params![cid],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        tx.execute(
            "UPDATE clusters SET count = max(0, count - 1), versions = ?2, os_builds = ?3
             WHERE id = ?1",
            params![
                cid,
                unbump(&versions, version),
                unbump(&os_builds, os_build.as_deref())
            ],
        )?;
        let others: i64 = tx.query_row(
            "SELECT count(*) FROM reports WHERE cluster_id = ?1 AND install_hash = ?2 AND id != ?3",
            params![cid, install, report_id],
            |r| r.get(0),
        )?;
        if others == 0 {
            tx.execute(
                "DELETE FROM cluster_installs WHERE cluster_id = ?1 AND install_hash = ?2",
                params![cid, install],
            )?;
        }
        Ok(())
    }

    /// Every clean (non-quarantined) report, for re-fingerprinting.
    pub fn clusterable_reports(&self) -> Result<Vec<StoredReport>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id, install_hash, app_version, cluster_id, raw FROM reports
             WHERE quarantined = 0 ORDER BY id",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(StoredReport {
                    id: r.get(0)?,
                    install_hash: r.get(1)?,
                    app_version: r.get(2)?,
                    cluster_id: r.get(3)?,
                    raw: r.get(4)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Move a report out of its current cluster; the caller re-assigns it.
    pub fn detach_report(&self, r: &StoredReport) -> Result<()> {
        let conn = self.conn();
        let tx = conn.unchecked_transaction()?;
        Self::detach(
            &tx,
            r.id,
            r.cluster_id,
            &r.install_hash,
            r.app_version.as_deref(),
            &r.raw,
        )?;
        tx.execute(
            "UPDATE reports SET cluster_id = NULL WHERE id = ?1",
            params![r.id],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Drop clusters nothing points at, unless someone has acted on them.
    pub fn prune_empty_clusters(&self) -> Result<usize> {
        let conn = self.conn();
        let n = conn.execute(
            "DELETE FROM clusters WHERE count = 0 AND status = 'new' AND issue_key IS NULL
               AND NOT EXISTS (SELECT 1 FROM clusters m WHERE m.merged_into = clusters.id)",
            [],
        )?;
        conn.execute(
            "DELETE FROM cluster_installs WHERE cluster_id NOT IN (SELECT id FROM clusters)",
            [],
        )?;
        Ok(n)
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

    /// Remember build-ids that could not be symbolicated for lack of symbols.
    pub fn note_missing_symbols(
        &self,
        build_ids: &[String],
        app: &str,
        version: Option<&str>,
        at: u64,
    ) -> Result<()> {
        let conn = self.conn();
        for id in build_ids {
            conn.execute(
                "INSERT INTO missing_symbols (build_id, app, app_version, first_seen, last_seen)
                 VALUES (?1, ?2, ?3, ?4, ?4)
                 ON CONFLICT(build_id) DO UPDATE SET last_seen = ?4, count = count + 1",
                params![id, app, version, at as i64],
            )?;
        }
        Ok(())
    }

    /// `(build_id, app, app_version, count)`, most requested first.
    pub fn missing_symbols(&self) -> Result<Vec<MissingSymbols>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT build_id, app, app_version, count FROM missing_symbols ORDER BY count DESC, build_id",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get::<_, i64>(3)? as u64))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Centroids of live fuzzy clusters for `(app, kind)` made with `model`:
    /// `(cluster id, centroid, reports folded in)`.
    pub fn fuzzy_candidates(
        &self,
        app: &str,
        kind: &str,
        model: &str,
    ) -> Result<Vec<FuzzyCandidate>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id, embedding, emb_n FROM clusters
             WHERE fingerprint IS NULL AND merged_into IS NULL AND app = ?1 AND kind = ?2
               AND emb_model = ?3 AND embedding IS NOT NULL",
        )?;
        let rows = stmt
            .query_map(params![app, kind, model], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    crate::embed::from_bytes(&r.get::<_, Vec<u8>>(1)?),
                    r.get::<_, i64>(2)? as u64,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn set_embedding(&self, id: i64, v: &[f32], n: u64, model: &str) -> Result<()> {
        self.conn().execute(
            "UPDATE clusters SET embedding = ?2, emb_n = ?3, emb_model = ?4 WHERE id = ?1",
            params![id, crate::embed::to_bytes(v), n as i64, model],
        )?;
        Ok(())
    }

    /// Ids of live fuzzy (unfingerprinted) clusters.
    pub fn fuzzy_cluster_ids(&self) -> Result<Vec<i64>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id FROM clusters WHERE fingerprint IS NULL AND merged_into IS NULL ORDER BY id",
        )?;
        let ids = stmt
            .query_map([], |r| r.get(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(ids)
    }

    /// The stored (scrubbed) JSON of every clean report in a cluster.
    pub fn cluster_report_raws(&self, id: i64) -> Result<Vec<String>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT raw FROM reports WHERE cluster_id = ?1 AND quarantined = 0 ORDER BY id",
        )?;
        let raws = stmt
            .query_map(params![id], |r| r.get(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(raws)
    }

    /// Set a cluster's status. Returns false for an unknown cluster or status.
    pub fn set_status(&self, id: i64, status: &str) -> Result<bool> {
        if !STATUSES.contains(&status) {
            return Ok(false);
        }
        Ok(self.conn().execute(
            "UPDATE clusters SET status = ?2 WHERE id = ?1 AND merged_into IS NULL",
            params![id, status],
        )? > 0)
    }

    /// Mark a cluster fixed in `version`.
    /// Atomically claim the right to promote a cluster. False if it already
    /// has an issue (or another promotion is running).
    pub fn begin_promotion(&self, id: i64) -> Result<bool> {
        Ok(self.conn().execute(
            "UPDATE clusters SET issue_key = 'pending'
             WHERE id = ?1 AND issue_key IS NULL AND merged_into IS NULL",
            params![id],
        )? > 0)
    }

    /// Give up a claimed promotion after a failure.
    pub fn abort_promotion(&self, id: i64) -> Result<()> {
        self.conn().execute(
            "UPDATE clusters SET issue_key = NULL WHERE id = ?1 AND issue_key = 'pending'",
            params![id],
        )?;
        Ok(())
    }

    /// Record the created issue; the count at promotion is the baseline for
    /// "N more reports" comments.
    pub fn finish_promotion(&self, id: i64, key: &str, priority: &str) -> Result<()> {
        self.conn().execute(
            "UPDATE clusters SET status = 'promoted', issue_key = ?2, issue_priority = ?3,
                                 notified_count = count
             WHERE id = ?1 AND issue_key = 'pending'",
            params![id, key, priority],
        )?;
        Ok(())
    }

    pub fn set_notified(&self, id: i64, count: u64, priority: Option<&str>) -> Result<()> {
        self.conn().execute(
            "UPDATE clusters SET notified_count = ?2, issue_priority = coalesce(?3, issue_priority)
             WHERE id = ?1",
            params![id, count as i64, priority],
        )?;
        Ok(())
    }

    /// `(cluster id, issue key)` for every cluster tracking an issue.
    pub fn tracked_issues(&self) -> Result<Vec<(i64, String)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id, issue_key FROM clusters
             WHERE issue_key IS NOT NULL AND issue_key != 'pending' AND merged_into IS NULL
               AND status IN ('promoted', 'regressed', 'investigating', 'new')",
        )?;
        let rows = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn issue_priority(&self, id: i64) -> Result<(Option<String>, u64)> {
        Ok(self.conn().query_row(
            "SELECT issue_priority, notified_count FROM clusters WHERE id = ?1",
            params![id],
            |r| Ok((r.get(0)?, r.get::<_, i64>(1)? as u64)),
        )?)
    }

    pub fn mark_fixed(&self, id: i64, version: &str) -> Result<bool> {
        Ok(self.conn().execute(
            "UPDATE clusters SET status = 'fixed', fixed_in = ?2 WHERE id = ?1 AND merged_into IS NULL",
            params![id, version],
        )? > 0)
    }

    /// Record the breadboard issue a cluster was promoted to.
    pub fn set_issue(&self, id: i64, key: &str) -> Result<bool> {
        Ok(self.conn().execute(
            "UPDATE clusters SET status = 'promoted', issue_key = ?2 WHERE id = ?1 AND merged_into IS NULL",
            params![id, key],
        )? > 0)
    }

    /// Fold cluster `from` into `into`: reports, counts, versions, installs.
    pub fn merge_clusters(&self, from: i64, into: i64) -> Result<bool> {
        let conn = self.conn();
        let into = Self::resolve(&conn, into)?;
        if from == into {
            return Ok(false);
        }
        let (Some(a), Some(b)) = (
            Self::cluster_from(&conn, from)?,
            Self::cluster_from(&conn, into)?,
        ) else {
            return Ok(false);
        };
        if a.merged_into.is_some() || a.app != b.app {
            return Ok(false);
        }
        let tx = conn.unchecked_transaction()?;
        let mut versions = b.versions.clone();
        for (k, n) in &a.versions {
            *versions.entry(k.clone()).or_default() += n;
        }
        let mut os_builds = b.os_builds.clone();
        for (k, n) in &a.os_builds {
            *os_builds.entry(k.clone()).or_default() += n;
        }
        tx.execute(
            "UPDATE clusters SET count = count + ?2, first_seen = min(first_seen, ?3),
                                 last_seen = max(last_seen, ?4), versions = ?5, os_builds = ?6
             WHERE id = ?1",
            params![
                into,
                a.count as i64,
                a.first_seen as i64,
                a.last_seen as i64,
                serde_json::to_string(&versions)?,
                serde_json::to_string(&os_builds)?
            ],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO cluster_installs (cluster_id, install_hash)
             SELECT ?2, install_hash FROM cluster_installs WHERE cluster_id = ?1",
            params![from, into],
        )?;
        tx.execute(
            "UPDATE reports SET cluster_id = ?2 WHERE cluster_id = ?1",
            params![from, into],
        )?;
        tx.execute(
            "UPDATE clusters SET merged_into = ?2, count = 0 WHERE id = ?1",
            params![from, into],
        )?;
        tx.execute(
            "UPDATE clusters SET merged_into = ?2 WHERE merged_into = ?1",
            params![from, into],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// The newest reports in a cluster, for the triage view.
    pub fn cluster_samples(&self, id: i64, limit: usize) -> Result<Vec<SampleRow>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id, receipt, received_at, app_version, raw FROM reports
             WHERE cluster_id = ?1 ORDER BY id DESC LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![id, limit as i64], |r| {
                Ok(SampleRow {
                    id: r.get(0)?,
                    receipt: r.get(1)?,
                    received_at: r.get::<_, i64>(2)? as u64,
                    app_version: r.get(3)?,
                    raw: r.get(4)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn quarantined(&self, limit: usize) -> Result<Vec<QuarantineRow>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id, receipt, received_at, app, rescrub_hits, raw FROM reports
             WHERE quarantined = 1 ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![limit as i64], |r| {
                Ok(QuarantineRow {
                    id: r.get(0)?,
                    receipt: r.get(1)?,
                    received_at: r.get::<_, i64>(2)? as u64,
                    app: r.get(3)?,
                    hits: r.get(4)?,
                    raw: r.get(5)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Take a report out of quarantine and return it for clustering.
    pub fn release_quarantine(&self, id: i64) -> Result<Option<StoredReport>> {
        let conn = self.conn();
        let changed = conn.execute(
            "UPDATE reports SET quarantined = 0 WHERE id = ?1 AND quarantined = 1",
            params![id],
        )?;
        if changed == 0 {
            return Ok(None);
        }
        Ok(conn
            .query_row(
                "SELECT id, install_hash, app_version, cluster_id, raw FROM reports WHERE id = ?1",
                params![id],
                |r| {
                    Ok(StoredReport {
                        id: r.get(0)?,
                        install_hash: r.get(1)?,
                        app_version: r.get(2)?,
                        cluster_id: r.get(3)?,
                        raw: r.get(4)?,
                    })
                },
            )
            .optional()?)
    }

    /// Delete a report by id (admin action), keeping cluster counters right.
    pub fn delete_report_by_id(&self, id: i64) -> Result<bool> {
        let conn = self.conn();
        let row: Option<(String, Option<i64>, Option<String>, String)> = conn
            .query_row(
                "SELECT install_hash, cluster_id, app_version, raw FROM reports WHERE id = ?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        let Some((install, cluster, version, raw)) = row else {
            return Ok(false);
        };
        let tx = conn.unchecked_transaction()?;
        Self::detach(&tx, id, cluster, &install, version.as_deref(), &raw)?;
        tx.execute("DELETE FROM reports WHERE id = ?1", params![id])?;
        tx.commit()?;
        Ok(true)
    }

    /// Ban the install that sent report `id`; returns false if unknown.
    pub fn ban_install_of_report(&self, id: i64, reason: &str, at: u64) -> Result<bool> {
        let conn = self.conn();
        let hash: Option<String> = conn
            .query_row(
                "SELECT install_hash FROM reports WHERE id = ?1",
                params![id],
                |r| r.get(0),
            )
            .optional()?;
        let Some(hash) = hash else {
            return Ok(false);
        };
        conn.execute(
            "INSERT OR REPLACE INTO bans (install_hash, reason, banned_at) VALUES (?1, ?2, ?3)",
            params![
                hash,
                reason.chars().take(200).collect::<String>(),
                at as i64
            ],
        )?;
        Ok(true)
    }

    pub fn is_banned(&self, install_hash: &str) -> Result<bool> {
        Ok(self
            .conn()
            .query_row(
                "SELECT 1 FROM bans WHERE install_hash = ?1",
                params![install_hash],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    pub fn ban_count(&self) -> Result<usize> {
        Ok(self
            .conn()
            .query_row("SELECT count(*) FROM bans", [], |r| r.get::<_, i64>(0))?
            as usize)
    }

    /// Test hook: overwrite a cluster's fingerprint to simulate older rules.
    #[doc(hidden)]
    pub fn corrupt_fingerprint_for_test(&self, id: i64, fp: &str) -> Result<()> {
        self.conn().execute(
            "UPDATE clusters SET fingerprint = ?2 WHERE id = ?1",
            params![id, fp],
        )?;
        Ok(())
    }

    /// Follow `merged_into` to the live cluster.
    fn resolve(conn: &Connection, mut id: i64) -> Result<i64> {
        for _ in 0..8 {
            let next: Option<i64> = conn
                .query_row(
                    "SELECT merged_into FROM clusters WHERE id = ?1",
                    params![id],
                    |r| r.get(0),
                )
                .optional()?
                .flatten();
            match next {
                Some(n) => id = n,
                None => break,
            }
        }
        Ok(id)
    }

    fn attach(conn: &Connection, cluster_id: i64, c: &Contribution<'_>) -> Result<i64> {
        let cluster_id = Self::resolve(conn, cluster_id)?;
        let (versions, os_builds): (String, String) = conn.query_row(
            "SELECT versions, os_builds FROM clusters WHERE id = ?1",
            params![cluster_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        conn.execute(
            "UPDATE clusters SET count = count + 1, last_seen = max(last_seen, ?2),
                                 first_seen = min(first_seen, ?2), versions = ?3, os_builds = ?4
             WHERE id = ?1",
            params![
                cluster_id,
                c.at as i64,
                bump(&versions, c.version),
                bump(&os_builds, c.os_build)
            ],
        )?;
        conn.execute(
            "INSERT OR IGNORE INTO cluster_installs (cluster_id, install_hash) VALUES (?1, ?2)",
            params![cluster_id, c.install_hash],
        )?;
        conn.execute(
            "UPDATE reports SET cluster_id = ?2 WHERE id = ?1",
            params![c.report_id, cluster_id],
        )?;
        Ok(cluster_id)
    }

    /// Put a report in the cluster for `fingerprint`, creating it if new.
    pub fn assign_fingerprint(
        &self,
        app: &str,
        kind: &str,
        fingerprint: &str,
        title: &str,
        c: &Contribution<'_>,
    ) -> Result<i64> {
        let conn = self.conn();
        let tx = conn.unchecked_transaction()?;
        let existing: Option<i64> = tx
            .query_row(
                "SELECT id FROM clusters WHERE app = ?1 AND fingerprint = ?2",
                params![app, fingerprint],
                |r| r.get(0),
            )
            .optional()?;
        let id = match existing {
            Some(id) => id,
            None => {
                tx.execute(
                    "INSERT INTO clusters (app, kind, fingerprint, title, first_seen, last_seen)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
                    params![app, kind, fingerprint, title, c.at as i64],
                )?;
                tx.last_insert_rowid()
            }
        };
        let id = Self::attach(&tx, id, c)?;
        tx.commit()?;
        Ok(id)
    }

    /// Put a report in an existing cluster (fuzzy matching).
    pub fn assign_to(&self, cluster_id: i64, c: &Contribution<'_>) -> Result<i64> {
        let conn = self.conn();
        let tx = conn.unchecked_transaction()?;
        let id = Self::attach(&tx, cluster_id, c)?;
        tx.commit()?;
        Ok(id)
    }

    /// Start a cluster with no fingerprint (fuzzy matching creates these).
    pub fn new_cluster(
        &self,
        app: &str,
        kind: &str,
        title: &str,
        c: &Contribution<'_>,
    ) -> Result<i64> {
        let conn = self.conn();
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO clusters (app, kind, fingerprint, title, first_seen, last_seen)
             VALUES (?1, ?2, NULL, ?3, ?4, ?4)",
            params![app, kind, title, c.at as i64],
        )?;
        let id = tx.last_insert_rowid();
        let id = Self::attach(&tx, id, c)?;
        tx.commit()?;
        Ok(id)
    }

    fn cluster_from(conn: &Connection, id: i64) -> Result<Option<ClusterRow>> {
        Ok(conn
            .query_row(
                "SELECT c.id, c.app, c.kind, c.fingerprint, c.title, c.status, c.first_seen,
                        c.last_seen, c.count, c.versions, c.os_builds, c.fixed_in, c.issue_key,
                        c.merged_into,
                        (SELECT count(*) FROM cluster_installs i WHERE i.cluster_id = c.id)
                 FROM clusters c WHERE c.id = ?1",
                params![id],
                |r| {
                    let versions: String = r.get(9)?;
                    let os_builds: String = r.get(10)?;
                    Ok(ClusterRow {
                        id: r.get(0)?,
                        app: r.get(1)?,
                        kind: r.get(2)?,
                        fingerprint: r.get(3)?,
                        title: r.get(4)?,
                        status: r.get(5)?,
                        first_seen: r.get::<_, i64>(6)? as u64,
                        last_seen: r.get::<_, i64>(7)? as u64,
                        count: r.get::<_, i64>(8)? as u64,
                        versions: serde_json::from_str(&versions).unwrap_or_default(),
                        os_builds: serde_json::from_str(&os_builds).unwrap_or_default(),
                        fixed_in: r.get(11)?,
                        issue_key: r.get(12)?,
                        merged_into: r.get(13)?,
                        installs: r.get::<_, i64>(14)? as u64,
                    })
                },
            )
            .optional()?)
    }

    pub fn cluster(&self, id: i64) -> Result<Option<ClusterRow>> {
        Self::cluster_from(&self.conn(), id)
    }

    /// Clusters that are not merged away, newest activity first.
    pub fn clusters(&self) -> Result<Vec<ClusterRow>> {
        let conn = self.conn();
        let ids: Vec<i64> = conn
            .prepare("SELECT id FROM clusters WHERE merged_into IS NULL ORDER BY last_seen DESC, id DESC")?
            .query_map([], |r| r.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        let mut out = Vec::new();
        for id in ids {
            if let Some(c) = Self::cluster_from(&conn, id)? {
                out.push(c);
            }
        }
        Ok(out)
    }

    pub fn cluster_of(&self, receipt: &str) -> Result<Option<i64>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT cluster_id FROM reports WHERE receipt = ?1",
                params![receipt],
                |r| r.get::<_, Option<i64>>(0),
            )
            .optional()?
            .flatten())
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
