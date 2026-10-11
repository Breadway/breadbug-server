//! Cluster assignment: deterministic fingerprints first.
//!
//! A report with a stable fingerprint joins (or creates) the cluster for
//! `(app, fingerprint)`, whatever version or machine it came from. Reports
//! with nothing stable to hash fall through to fuzzy matching (a later step).

use anyhow::Result;

use crate::db::{Contribution, Db};
use crate::fingerprint::fingerprint;
use crate::schema::Report;

/// What kind of problem a report describes, for the cluster row.
pub fn kind_of(report: &Report) -> &'static str {
    report.report_type.as_str()
}

/// Assign a stored report to a cluster. Returns the cluster id, or `None`
/// when the report has no fingerprint.
pub fn assign(db: &Db, report_id: i64, report: &Report, install_hash: &str) -> Result<Option<i64>> {
    let Some(fp) = fingerprint(report) else {
        return Ok(None);
    };
    let c = Contribution {
        report_id,
        install_hash,
        version: report.app.version.as_deref(),
        os_build: report.system.os_build.as_deref(),
        at: crate::app::now_unix(),
    };
    Ok(Some(db.assign_fingerprint(
        &report.app.id,
        kind_of(report),
        &fp.key,
        &fp.title,
        &c,
    )?))
}

/// Re-run fingerprinting over every stored clean report, for when the
/// normalization rules (`RULES_VERSION`) change. Reports whose fingerprint
/// is unchanged stay put; others move to the right cluster. Returns how many
/// moved. Clusters a human has acted on are never deleted.
pub fn refingerprint_all(db: &Db) -> Result<usize> {
    let mut moved = 0;
    for stored in db.clusterable_reports()? {
        let Ok(report) = serde_json::from_str::<Report>(&stored.raw) else {
            continue;
        };
        let Some(fp) = fingerprint(&report) else {
            continue;
        };
        let current = match stored.cluster_id {
            Some(id) => db.cluster(id)?.and_then(|c| c.fingerprint),
            None => None,
        };
        if current.as_deref() == Some(fp.key.as_str()) {
            continue;
        }
        db.detach_report(&stored)?;
        let c = Contribution {
            report_id: stored.id,
            install_hash: &stored.install_hash,
            version: stored.app_version.as_deref(),
            os_build: report.system.os_build.as_deref(),
            at: crate::app::now_unix(),
        };
        db.assign_fingerprint(&report.app.id, kind_of(&report), &fp.key, &fp.title, &c)?;
        moved += 1;
    }
    db.prune_empty_clusters()?;
    Ok(moved)
}
