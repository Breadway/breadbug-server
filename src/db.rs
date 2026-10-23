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

/// What anyone holding a receipt may learn about their report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicStatus {
    pub status: &'static str,
    pub fixed_in: Option<String>,
    /// Development progress from the linked breadboard issue, if any. This
    /// is a coarse stage name only; no board internals ever leave the server.
    ///
    /// Mapping (breadboard is authoritative, this is a cached view):
    ///
    /// | cluster / board state | progress |
    /// |---|---|
    /// | cluster `dismissed` | `declined` |
    /// | cluster `deferred` | `deferred` |
    /// | issue `done` | `completed` |
    /// | issue `review` | `fixed` |
    /// | cluster `fixed` with a recorded version | `targeting_release` |
    /// | cluster `fixed` without a version | `fixed` |
    /// | issue `backlog` or `todo` | `accepted` |
    /// | issue `doing` | `in_development` |
    pub progress: Option<String>,
    /// Planned vs confirmed beta and stable application releases, if any.
    pub releases: Option<ReleaseTrack>,
}

/// Development progress for a cluster row. See [`PublicStatus::progress`]
/// for the mapping table. Cluster verdicts take precedence, then a completed
/// board issue, then the cluster's own fixed state, then the remaining board
/// stages.
pub fn progress_of(c: &ClusterRow) -> Option<&'static str> {
    match c.status.as_str() {
        "dismissed" => return Some("declined"),
        "deferred" => return Some("deferred"),
        _ => {}
    }
    let linked = c.issue_key.as_deref().filter(|k| *k != "pending");
    if linked.is_some() {
        match c.issue_status.as_deref() {
            Some("done") => return Some("completed"),
            Some("review") => return Some("fixed"),
            _ => {}
        }
    }
    if c.status == "fixed" {
        // A recorded fix version names the release the fix targets; with no
        // version the fix is implemented but not yet aimed at a release.
        return Some(if c.fixed_in.is_some() {
            "targeting_release"
        } else {
            "fixed"
        });
    }
    if linked.is_some() {
        match c.issue_status.as_deref() {
            Some("backlog") | Some("todo") => return Some("accepted"),
            Some("doing") => return Some("in_development"),
            _ => {}
        }
    }
    None
}

/// One release channel (beta or stable): what release is planned and whether
/// it has actually shipped. Per application release, never per BOS
/// distribution release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelRelease {
    pub planned: Option<String>,
    pub shipped: bool,
    pub shipped_in: Option<String>,
}

/// A pending notification for one follow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    pub id: i64,
    pub event: String,
    pub text: String,
    pub created_at: u64,
}

/// Planned vs confirmed availability for both channels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseTrack {
    pub beta: ChannelRelease,
    pub stable: ChannelRelease,
}

/// Release tracking for a cluster row, or `None` when nothing is planned
/// or confirmed yet.
pub fn releases_of(c: &ClusterRow) -> Option<ReleaseTrack> {
    if c.target_beta.is_none()
        && c.confirmed_beta.is_none()
        && c.target_stable.is_none()
        && c.confirmed_stable.is_none()
    {
        return None;
    }
    let channel = |planned: &Option<String>, confirmed: &Option<String>| ChannelRelease {
        planned: planned.clone(),
        shipped: confirmed.is_some(),
        shipped_in: confirmed.clone(),
    };
    Some(ReleaseTrack {
        beta: channel(&c.target_beta, &c.confirmed_beta),
        stable: channel(&c.target_stable, &c.confirmed_stable),
    })
}

/// Longest version string the release columns accept.
pub const MAX_VERSION: usize = 128;

/// The stored release columns for one cluster, used to validate an update
/// against the effective (confirmed or planned) version on the other channel.
struct ReleaseState {
    target_beta: Option<String>,
    target_stable: Option<String>,
    confirmed_beta: Option<String>,
    confirmed_stable: Option<String>,
}

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
    "deferred",
];

/// Board statuses we cache per promoted cluster. Anything else is ignored.
pub const KNOWN_ISSUE_STATUSES: &[&str] = &["backlog", "todo", "doing", "review", "done"];

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
    pub issue_status: Option<String>,
    /// Whether the fixed state came from the board reaching `done` (so a
    /// board reopen should re-derive it), as opposed to an admin mark-fixed.
    pub board_fixed: bool,
    pub target_beta: Option<String>,
    pub confirmed_beta: Option<String>,
    pub target_stable: Option<String>,
    pub confirmed_stable: Option<String>,
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
    // 7: anonymous follows: one row per (cluster, install), token stored hashed
    "CREATE TABLE follows (
        id           INTEGER PRIMARY KEY,
        cluster_id   INTEGER NOT NULL,
        token_hash   TEXT NOT NULL UNIQUE,
        install_hash TEXT NOT NULL,
        created_at   INTEGER NOT NULL
    );
    CREATE INDEX follows_cluster ON follows(cluster_id);
    CREATE UNIQUE INDEX follows_one_per_install ON follows(cluster_id, install_hash);",
    // 8: follow capability aliases: a merge can fold two follows into one
    // cluster and both tokens must keep working, so more than one live token
    // per install is allowed. Idempotency is handled by rotating in `follow`.
    "DROP INDEX IF EXISTS follows_one_per_install;",
    // 9: remember that a cluster's fixed state came from the board, so a
    // board reopen re-derives it while an admin "mark fixed" is left alone.
    "ALTER TABLE clusters ADD COLUMN board_fixed INTEGER NOT NULL DEFAULT 0;",
    // 10: cached breadboard issue status for the public progress stage
    "ALTER TABLE clusters ADD COLUMN issue_status TEXT;",
    // 11: per-app beta/stable release tracking: planned vs confirmed
    "ALTER TABLE clusters ADD COLUMN target_beta TEXT;
    ALTER TABLE clusters ADD COLUMN confirmed_beta TEXT;
    ALTER TABLE clusters ADD COLUMN target_stable TEXT;
    ALTER TABLE clusters ADD COLUMN confirmed_stable TEXT;",
    // 10: notification outbox: one row per follow per transition version.
    // Repeating a transition never duplicates (the first text wins); a new
    // version is new information and notifies again. Delivered rows stay so
    // the dedup survives reads.
    "CREATE TABLE notices (
        id           INTEGER PRIMARY KEY,
        cluster_id   INTEGER NOT NULL,
        token_hash   TEXT NOT NULL,
        event        TEXT NOT NULL,
        text         TEXT NOT NULL,
        created_at   INTEGER NOT NULL,
        delivered    INTEGER NOT NULL DEFAULT 0,
        UNIQUE(token_hash, event, text)
    );
    CREATE INDEX notices_token ON notices(token_hash);",
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
        conn.execute(
            "DELETE FROM follows WHERE cluster_id NOT IN (SELECT id FROM clusters)",
            [],
        )?;
        conn.execute(
            "DELETE FROM notices WHERE cluster_id NOT IN (SELECT id FROM clusters)",
            [],
        )?;
        conn.execute(
            "DELETE FROM notices WHERE token_hash NOT IN (SELECT token_hash FROM follows)",
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

    /// The coarse, public status of a report, derived from its cluster. Never
    /// reveals other users' data: only a state word and, once fixed, the
    /// version the fix shipped in.
    pub fn public_status(&self, receipt: &str) -> Result<Option<PublicStatus>> {
        let conn = self.conn();
        let row: Option<(Option<i64>, i64)> = conn
            .query_row(
                "SELECT cluster_id, quarantined FROM reports WHERE receipt = ?1",
                params![receipt],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((cluster, quarantined)) = row else {
            return Ok(None);
        };
        let received = PublicStatus {
            status: "received",
            fixed_in: None,
            progress: None,
            releases: None,
        };
        let (Some(cid), 0) = (cluster, quarantined) else {
            return Ok(Some(received));
        };
        let cid = Self::resolve(&conn, cid)?;
        let Some(c) = Self::cluster_from(&conn, cid)? else {
            return Ok(Some(received));
        };
        let progress = progress_of(&c).map(str::to_string);
        let releases = releases_of(&c);
        Ok(Some(match c.status.as_str() {
            "promoted" | "investigating" | "regressed" => PublicStatus {
                status: "investigating",
                fixed_in: None,
                progress,
                releases,
            },
            "fixed" => PublicStatus {
                status: "fixed",
                fixed_in: c.fixed_in,
                progress,
                releases,
            },
            "dismissed" => PublicStatus {
                status: "closed",
                fixed_in: None,
                progress,
                releases,
            },
            "deferred" => PublicStatus {
                status: "investigating",
                fixed_in: None,
                progress,
                releases,
            },
            // A known problem others have already reported.
            _ if c.count > 1 => PublicStatus {
                status: "duplicate",
                fixed_in: None,
                progress,
                releases,
            },
            // A single fresh report: still surface any planned releases.
            _ => PublicStatus {
                status: "received",
                fixed_in: None,
                progress,
                releases,
            },
        }))
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

    /// Forget the vector but remember which model looked at the cluster, so a
    /// cluster with nothing left to match on is not retried every hour.
    pub fn clear_embedding(&self, id: i64, model: &str) -> Result<()> {
        self.conn().execute(
            "UPDATE clusters SET embedding = NULL, emb_n = 0, emb_model = ?2 WHERE id = ?1",
            params![id, model],
        )?;
        Ok(())
    }

    /// Follow `merged_into` to the live cluster.
    pub fn resolve_cluster_id(&self, id: i64) -> Result<i64> {
        Self::resolve(&self.conn(), id)
    }

    /// Fuzzy clusters whose vectors came from another model (or none).
    pub fn stale_fuzzy_cluster_ids(&self, model: &str) -> Result<Vec<i64>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id FROM clusters
             WHERE fingerprint IS NULL AND merged_into IS NULL
               AND (emb_model IS NULL OR emb_model != ?1)
             ORDER BY id",
        )?;
        let ids = stmt
            .query_map(params![model], |r| r.get(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(ids)
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

    /// `(cluster id, issue key)` for every cluster tracking an issue. This
    /// includes fixed, dismissed and deferred groups: their board issue can
    /// still move, and a fixed cluster whose issue reopens must be re-derived
    /// rather than frozen.
    pub fn tracked_issues(&self) -> Result<Vec<(i64, String)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id, issue_key FROM clusters
             WHERE issue_key IS NOT NULL AND issue_key != 'pending' AND merged_into IS NULL
AND status IN ('promoted', 'regressed', 'investigating', 'new', 'fixed', 'dismissed', 'deferred')",
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

    /// Cache the linked breadboard issue's workflow status for the public
    /// progress stage. Unknown values are ignored; returns false then.
    pub fn set_issue_status(&self, id: i64, status: &str) -> Result<bool> {
        if !KNOWN_ISSUE_STATUSES.contains(&status) {
            return Ok(false);
        }
        Ok(self.conn().execute(
            "UPDATE clusters SET issue_status = ?2 WHERE id = ?1 AND merged_into IS NULL",
            params![id, status],
        )? > 0)
    }

    /// Planned targets and confirmed releases for both channels, if the
    /// cluster exists and is not merged away.
    fn release_state(conn: &Connection, id: i64) -> Result<Option<ReleaseState>> {
        Ok(conn
            .query_row(
                "SELECT target_beta, target_stable, confirmed_beta, confirmed_stable
                 FROM clusters WHERE id = ?1 AND merged_into IS NULL",
                params![id],
                |r| {
                    Ok(ReleaseState {
                        target_beta: r.get(0)?,
                        target_stable: r.get(1)?,
                        confirmed_beta: r.get(2)?,
                        confirmed_stable: r.get(3)?,
                    })
                },
            )
            .optional()?)
    }

    /// beta must never be newer than stable once each channel's effective
    /// version (the confirmed release if shipped, otherwise the planned
    /// target) is known.
    fn ordering_ok(beta: &Option<String>, stable: &Option<String>) -> bool {
        match (beta, stable) {
            (Some(b), Some(s)) => {
                crate::lifecycle::version_cmp(b, s) != std::cmp::Ordering::Greater
            }
            _ => true,
        }
    }

    fn valid_release_version(version: &str) -> bool {
        crate::lifecycle::valid_version(version) && version.len() <= MAX_VERSION
    }

    /// Plan the fix or feature for a beta or stable application release.
    /// The beta target must not be newer than the stable target, malformed
    /// versions are refused, and the read plus write happen in one
    /// transaction so concurrent updates cannot interleave into an inverted
    /// plan. Returns false for a bad channel or version, bad ordering, or no
    /// cluster.
    pub fn set_release_target(&self, id: i64, channel: &str, version: &str) -> Result<bool> {
        if !matches!(channel, "beta" | "stable") || !Self::valid_release_version(version) {
            return Ok(false);
        }
        let conn = self.conn();
        let tx = conn.unchecked_transaction()?;
        let Some(state) = Self::release_state(&conn, id)? else {
            return Ok(false);
        };
        // A confirmed release dominates a later plan for the same channel.
        let (eff_beta, eff_stable) = if channel == "beta" {
            (
                state.confirmed_beta.clone().or(Some(version.to_string())),
                state
                    .confirmed_stable
                    .clone()
                    .or(state.target_stable.clone()),
            )
        } else {
            (
                state.confirmed_beta.clone().or(state.target_beta.clone()),
                state.confirmed_stable.clone().or(Some(version.to_string())),
            )
        };
        if !Self::ordering_ok(&eff_beta, &eff_stable) {
            return Ok(false);
        }
        let column = if channel == "beta" {
            "target_beta"
        } else {
            "target_stable"
        };
        let changed = tx.execute(
            &format!("UPDATE clusters SET {column} = ?2 WHERE id = ?1 AND merged_into IS NULL"),
            params![id, version],
        )? > 0;
        tx.commit()?;
        Ok(changed)
    }

    /// Confirm the fix or feature actually shipped in a channel release.
    /// The channel must have a planned target first. The confirmed version
    /// must be well formed and must keep beta no newer than stable. Returns
    /// false otherwise, or for a bad channel or cluster.
    pub fn mark_release_confirmed(&self, id: i64, channel: &str, version: &str) -> Result<bool> {
        if !matches!(channel, "beta" | "stable") || !Self::valid_release_version(version) {
            return Ok(false);
        }
        let conn = self.conn();
        let tx = conn.unchecked_transaction()?;
        let Some(state) = Self::release_state(&conn, id)? else {
            return Ok(false);
        };
        let planned = if channel == "beta" {
            &state.target_beta
        } else {
            &state.target_stable
        };
        if planned.is_none() {
            return Ok(false);
        }
        let (eff_beta, eff_stable) = if channel == "beta" {
            (
                Some(version.to_string()),
                state
                    .confirmed_stable
                    .clone()
                    .or(state.target_stable.clone()),
            )
        } else {
            (
                state.confirmed_beta.clone().or(state.target_beta.clone()),
                Some(version.to_string()),
            )
        };
        if !Self::ordering_ok(&eff_beta, &eff_stable) {
            return Ok(false);
        }
        let column = if channel == "beta" {
            "confirmed_beta"
        } else {
            "confirmed_stable"
        };
        let changed = tx.execute(
            &format!("UPDATE clusters SET {column} = ?2 WHERE id = ?1 AND merged_into IS NULL"),
            params![id, version],
        )? > 0;
        tx.commit()?;
        Ok(changed)
    }

    pub fn mark_fixed(&self, id: i64, version: &str) -> Result<bool> {
        Ok(self.conn().execute(
            "UPDATE clusters SET status = 'fixed', fixed_in = ?2 WHERE id = ?1 AND merged_into IS NULL",
            params![id, version],
        )? > 0)
    }

    /// Mark a cluster fixed because its board issue reached `done`. Records
    /// the shipped version when the board provides one and flags the state as
    /// board-driven, so a later board reopen re-derives it.
    pub fn mark_fixed_from_board(&self, id: i64, version: Option<&str>) -> Result<bool> {
        Ok(self.conn().execute(
            "UPDATE clusters SET status = 'fixed', fixed_in = coalesce(?2, fixed_in), board_fixed = 1
             WHERE id = ?1 AND merged_into IS NULL",
            params![id, version],
        )? > 0)
    }

    /// Return a board-fixed cluster to the promoted state after the board
    /// moved its issue back out of `done`.
    pub fn reopen_from_board(&self, id: i64) -> Result<bool> {
        Ok(self.conn().execute(
            "UPDATE clusters SET status = 'promoted', board_fixed = 0
             WHERE id = ?1 AND merged_into IS NULL",
            params![id],
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
        // Follows move with the reports. An install following both clusters
        // keeps both capability tokens (aliases): each one still reads and
        // unsubscribes the folded follow instead of the source token being
        // silently invalidated.
        tx.execute(
            "UPDATE follows SET cluster_id = ?2 WHERE cluster_id = ?1",
            params![from, into],
        )?;
        // Pending notices move with their follows. A follow that already has
        // the same event on the target keeps the target's copy.
        tx.execute(
            "DELETE FROM notices WHERE cluster_id = ?1 AND (token_hash, event) IN
             (SELECT token_hash, event FROM notices WHERE cluster_id = ?2)",
            params![from, into],
        )?;
        tx.execute(
            "UPDATE notices SET cluster_id = ?2 WHERE cluster_id = ?1",
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

    /// Test hook: a report's row id for its receipt.
    #[doc(hidden)]
    pub fn report_id_for_test(&self, receipt: &str) -> Result<Option<i64>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT id FROM reports WHERE receipt = ?1",
                params![receipt],
                |r| r.get(0),
            )
            .optional()?)
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
c.issue_status, c.board_fixed, c.target_beta, c.confirmed_beta,
                        c.target_stable, c.confirmed_stable, c.merged_into,
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
                        issue_status: r.get(13)?,
                        board_fixed: r.get(14)?,
                        target_beta: r.get(15)?,
                        confirmed_beta: r.get(16)?,
                        target_stable: r.get(17)?,
                        confirmed_stable: r.get(18)?,
                        merged_into: r.get(19)?,
                        installs: r.get::<_, i64>(20)? as u64,
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

    /// Follow a cluster. A fresh token replaces any earlier one for the same
    /// install on this cluster, so a lost first response can be recovered by
    /// retrying (the retry returns a usable token). Returns whether an
    /// earlier follow was replaced.
    pub fn follow(
        &self,
        cluster_id: i64,
        token_hash: &str,
        install_hash: &str,
        at: u64,
    ) -> Result<bool> {
        let conn = self.conn();
        let tx = conn.unchecked_transaction()?;
        let replaced = tx.execute(
            "DELETE FROM follows WHERE cluster_id = ?1 AND install_hash = ?2",
            params![cluster_id, install_hash],
        )? > 0;
        tx.execute(
            "INSERT INTO follows (cluster_id, token_hash, install_hash, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![cluster_id, token_hash, install_hash, at as i64],
        )?;
        tx.commit()?;
        Ok(replaced)
    }

    /// Stop following. Returns false for an unknown token.
    pub fn unfollow(&self, token_hash: &str) -> Result<bool> {
        let conn = self.conn();
        let tx = conn.unchecked_transaction()?;
        let n = tx.execute(
            "DELETE FROM follows WHERE token_hash = ?1",
            params![token_hash],
        )?;
        // Pending notices for a dead follow go away with it.
        tx.execute(
            "UPDATE notices SET delivered = 1 WHERE token_hash = ?1 AND delivered = 0",
            params![token_hash],
        )?;
        tx.commit()?;
        Ok(n > 0)
    }

    /// How many installs follow a cluster (a merge can leave an install with
    /// more than one live token, so count distinct installs).
    pub fn follow_count(&self, cluster_id: i64) -> Result<usize> {
        Ok(self.conn().query_row(
            "SELECT count(DISTINCT install_hash) FROM follows WHERE cluster_id = ?1",
            params![cluster_id],
            |r| r.get::<_, i64>(0),
        )? as usize)
    }

    /// Whether `token_hash` is the deletion token of the report with this
    /// receipt. Used to authenticate the reporter for follow.
    pub fn deletion_token_matches(&self, receipt: &str, token_hash: &str) -> Result<bool> {
        let stored: Option<String> = self
            .conn()
            .query_row(
                "SELECT token_hash FROM reports WHERE receipt = ?1",
                params![receipt],
                |r| r.get(0),
            )
            .optional()?;
        Ok(stored.is_some_and(|s| ct_eq(&s, token_hash)))
    }

    /// Whether a follow token is live.
    pub fn has_follow(&self, token_hash: &str) -> Result<bool> {
        Ok(self
            .conn()
            .query_row(
                "SELECT 1 FROM follows WHERE token_hash = ?1",
                params![token_hash],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Peek at a follow's undelivered notifications without consuming them.
    pub fn notices_for(&self, token_hash: &str) -> Result<Vec<Notice>> {
        Ok(self
            .conn()
            .prepare(
                "SELECT id, event, text, created_at FROM notices
                 WHERE token_hash = ?1 AND delivered = 0 ORDER BY id",
            )?
            .query_map(params![token_hash], |r| {
                Ok(Notice {
                    id: r.get(0)?,
                    event: r.get(1)?,
                    text: r.get(2)?,
                    created_at: r.get::<_, i64>(3)? as u64,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Read pending notifications and mark them delivered. A retry after a
    /// successful read finds nothing, so nothing is ever sent twice, and the
    /// delivered rows keep deduplicating future repeats of a transition.
    pub fn take_notices(&self, token_hash: &str) -> Result<Vec<Notice>> {
        let conn = self.conn();
        let tx = conn.unchecked_transaction()?;
        let out = tx
            .prepare(
                "SELECT id, event, text, created_at FROM notices
                 WHERE token_hash = ?1 AND delivered = 0 ORDER BY id",
            )?
            .query_map(params![token_hash], |r| {
                Ok(Notice {
                    id: r.get(0)?,
                    event: r.get(1)?,
                    text: r.get(2)?,
                    created_at: r.get::<_, i64>(3)? as u64,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        tx.execute(
            "UPDATE notices SET delivered = 1 WHERE token_hash = ?1 AND delivered = 0",
            params![token_hash],
        )?;
        tx.commit()?;
        Ok(out)
    }

    /// Queue one notice per follow of a cluster. Retries are safe: a follow
    /// keeps its first notice per event text, so re-running a transition never
    /// duplicates. Returns how many follows were notified.
    pub fn notify_follows(
        &self,
        cluster_id: i64,
        event: &str,
        text: &str,
        at: u64,
    ) -> Result<usize> {
        Ok(self.conn().execute(
            "INSERT OR IGNORE INTO notices (cluster_id, token_hash, event, text, created_at)
                 SELECT ?1, token_hash, ?2, ?3, ?4 FROM follows WHERE cluster_id = ?1",
            params![cluster_id, event, text, at as i64],
        )?)
    }

    /// Acknowledge specific pending notices (durable ack). Only the ids given
    /// are marked delivered, so a client that read but crashed before acking
    /// sees them again on the next read.
    pub fn ack_notices(&self, token_hash: &str, ids: &[i64]) -> Result<usize> {
        let conn = self.conn();
        let tx = conn.unchecked_transaction()?;
        let mut n = 0;
        for id in ids {
            n += tx.execute(
                "UPDATE notices SET delivered = 1
                 WHERE token_hash = ?1 AND id = ?2 AND delivered = 0",
                params![token_hash, id],
            )?;
        }
        tx.commit()?;
        Ok(n)
    }

    /// Mark a cluster fixed (recording a version when given) and queue its
    /// notices in one transaction, so a crash between the two cannot leave a
    /// fixed cluster with no notice queued. Returns whether it was updated.
    pub fn mark_fixed_and_notify(
        &self,
        id: i64,
        version: Option<&str>,
        event: &str,
        text: &str,
        at: u64,
    ) -> Result<bool> {
        let conn = self.conn();
        let tx = conn.unchecked_transaction()?;
        let changed = tx.execute(
            "UPDATE clusters SET status = 'fixed', fixed_in = coalesce(?2, fixed_in)
             WHERE id = ?1 AND merged_into IS NULL",
            params![id, version],
        )? > 0;
        tx.execute(
            "INSERT OR IGNORE INTO notices (cluster_id, token_hash, event, text, created_at)
                 SELECT ?1, token_hash, ?2, ?3, ?4 FROM follows WHERE cluster_id = ?1",
            params![id, event, text, at as i64],
        )?;
        tx.commit()?;
        Ok(changed)
    }

    /// Like `mark_fixed_and_notify`, but for a fix that came from the board
    /// reaching `done`: also flags the state as board-driven so a later board
    /// reopen re-derives it, while an admin mark-fixed is left alone.
    pub fn mark_fixed_from_board_and_notify(
        &self,
        id: i64,
        version: Option<&str>,
        event: &str,
        text: &str,
        at: u64,
    ) -> Result<bool> {
        let conn = self.conn();
        let tx = conn.unchecked_transaction()?;
        let changed = tx.execute(
            "UPDATE clusters SET status = 'fixed', fixed_in = coalesce(?2, fixed_in),
             board_fixed = 1
             WHERE id = ?1 AND merged_into IS NULL",
            params![id, version],
        )? > 0;
        tx.execute(
            "INSERT OR IGNORE INTO notices (cluster_id, token_hash, event, text, created_at)
                 SELECT ?1, token_hash, ?2, ?3, ?4 FROM follows WHERE cluster_id = ?1",
            params![id, event, text, at as i64],
        )?;
        tx.commit()?;
        Ok(changed)
    }

    /// Confirm a beta or stable release and queue its notices in one
    /// transaction (same ordering and planning checks as
    /// `mark_release_confirmed`).
    pub fn confirm_and_notify(
        &self,
        id: i64,
        channel: &str,
        version: &str,
        event: &str,
        text: &str,
        at: u64,
    ) -> Result<bool> {
        if !matches!(channel, "beta" | "stable") || !Self::valid_release_version(version) {
            return Ok(false);
        }
        let conn = self.conn();
        let tx = conn.unchecked_transaction()?;
        let Some(state) = Self::release_state(&conn, id)? else {
            return Ok(false);
        };
        let planned = if channel == "beta" {
            &state.target_beta
        } else {
            &state.target_stable
        };
        if planned.is_none() {
            return Ok(false);
        }
        let (eff_beta, eff_stable) = if channel == "beta" {
            (
                Some(version.to_string()),
                state
                    .confirmed_stable
                    .clone()
                    .or(state.target_stable.clone()),
            )
        } else {
            (
                state.confirmed_beta.clone().or(state.target_beta.clone()),
                Some(version.to_string()),
            )
        };
        if !Self::ordering_ok(&eff_beta, &eff_stable) {
            return Ok(false);
        }
        let column = if channel == "beta" {
            "confirmed_beta"
        } else {
            "confirmed_stable"
        };
        let changed = tx.execute(
            &format!("UPDATE clusters SET {column} = ?2 WHERE id = ?1 AND merged_into IS NULL"),
            params![id, version],
        )? > 0;
        tx.execute(
            "INSERT OR IGNORE INTO notices (cluster_id, token_hash, event, text, created_at)
                 SELECT ?1, token_hash, ?2, ?3, ?4 FROM follows WHERE cluster_id = ?1",
            params![id, event, text, at as i64],
        )?;
        tx.commit()?;
        Ok(changed)
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
