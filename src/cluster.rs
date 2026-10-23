//! Cluster assignment: deterministic fingerprints first.
//!
//! A report with a stable fingerprint joins (or creates) the cluster for
//! `(app, fingerprint)`, whatever version or machine it came from. Reports
//! with nothing stable to hash fall through to fuzzy matching (a later step).

use anyhow::Result;

use crate::db::{Contribution, Db};
use crate::embed::{centroid, cosine, report_text, title_for, tokens, Embedder};
use crate::fingerprint::fingerprint;
use crate::schema::Report;

/// What kind of problem a report describes, for the cluster row.
pub fn kind_of(report: &Report) -> &'static str {
    report.report_type.as_str()
}

/// How fuzzy matching is done for reports with no fingerprint.
pub struct Fuzzy<'a> {
    pub embedder: &'a dyn Embedder,
    pub threshold: f32,
}

/// Fewer distinct meaningful words than this and there is nothing to match on.
const MIN_TOKENS: usize = 3;

/// Distinct words, ignoring the report-type label that every text carries.
fn meaningful(text: &str) -> usize {
    tokens(text)
        .into_iter()
        .filter(|t| {
            !matches!(
                t.as_str(),
                "crash" | "freeze" | "behavior" | "manual" | "request"
            )
        })
        .collect::<std::collections::BTreeSet<_>>()
        .len()
}

/// Assign a stored report to a cluster: by fingerprint when it has one,
/// otherwise by similarity. Returns the cluster id, or `None` when there is
/// nothing to cluster on.
pub fn assign(
    db: &Db,
    report_id: i64,
    report: &Report,
    install_hash: &str,
    fuzzy: Option<&Fuzzy<'_>>,
) -> Result<Option<i64>> {
    let c = Contribution {
        report_id,
        install_hash,
        version: report.app.version.as_deref(),
        os_build: report.system.os_build.as_deref(),
        at: crate::app::now_unix(),
    };
    if let Some(fp) = fingerprint(report) {
        return Ok(Some(db.assign_fingerprint(
            &report.app.id,
            kind_of(report),
            &fp.key,
            &fp.title,
            &c,
        )?));
    }
    match fuzzy {
        Some(f) => assign_fuzzy(db, f, report, &c),
        None => Ok(None),
    }
}

fn assign_fuzzy(
    db: &Db,
    f: &Fuzzy<'_>,
    report: &Report,
    c: &Contribution<'_>,
) -> Result<Option<i64>> {
    let text = report_text(report);
    if meaningful(&text) < MIN_TOKENS {
        return Ok(None);
    }
    let v = f.embedder.embed(&text)?;
    let model = f.embedder.model();
    let best = db
        .fuzzy_candidates(&report.app.id, kind_of(report), model)?
        .into_iter()
        .map(|(id, cen, n)| (cosine(&v, &cen), id, cen, n))
        .max_by(|a, b| a.0.total_cmp(&b.0));
    match best {
        Some((score, id, cen, n)) if score >= f.threshold => {
            let id = db.assign_to(id, c)?;
            // Fold this report into the running centroid.
            let scaled: Vec<f32> = cen.iter().map(|x| x * n as f32).collect();
            if let Some(new) = centroid(&[scaled, v]).filter(|_| n > 0) {
                db.set_embedding(id, &new, n + 1, model)?;
            }
            Ok(Some(id))
        }
        _ => {
            let id = db.new_cluster(&report.app.id, kind_of(report), &title_for(report), c)?;
            db.set_embedding(id, &v, 1, model)?;
            Ok(Some(id))
        }
    }
}

/// Recompute one fuzzy cluster's centroid from its stored reports. Used when
/// the embedding model changes and after a manual merge, so the survivor can
/// match the wording that was just folded into it. Fingerprint clusters have
/// no fuzzy space and are left alone.
pub fn reembed_cluster(db: &Db, embedder: &dyn Embedder, id: i64) -> Result<bool> {
    let id = db.resolve_cluster_id(id)?;
    let Some(row) = db.cluster(id)? else {
        return Ok(false);
    };
    if row.fingerprint.is_some() {
        return Ok(false);
    }
    let mut vectors = Vec::new();
    for raw in db.cluster_report_raws(id)? {
        let Ok(report) = serde_json::from_str::<Report>(&raw) else {
            continue;
        };
        let text = report_text(&report);
        if meaningful(&text) >= MIN_TOKENS {
            vectors.push(embedder.embed(&text)?);
        }
    }
    match centroid(&vectors) {
        Some(c) => db.set_embedding(id, &c, vectors.len() as u64, embedder.model())?,
        // Nothing left to match on (deleted or purged reports). Record the
        // current model so the hourly pass does not retry it forever.
        None => db.clear_embedding(id, embedder.model())?,
    }
    Ok(true)
}

/// Recompute every fuzzy cluster's centroid from its member reports, for
/// when the embedding model changes. Returns how many were updated.
pub fn reembed_all(db: &Db, embedder: &dyn Embedder) -> Result<usize> {
    let mut updated = 0;
    for id in db.fuzzy_cluster_ids()? {
        if reembed_cluster(db, embedder, id)? {
            updated += 1;
        }
    }
    Ok(updated)
}

/// Rebuild only clusters whose vectors came from a different model. This is
/// what switching from the built-in hashing embedder to a local model needs;
/// without it, old clusters keep vectors the new model never compares
/// against and silently stop matching.
pub fn reembed_stale(db: &Db, embedder: &dyn Embedder) -> Result<usize> {
    let mut updated = 0;
    for id in db.stale_fuzzy_cluster_ids(embedder.model())? {
        if reembed_cluster(db, embedder, id)? {
            updated += 1;
        }
    }
    Ok(updated)
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
