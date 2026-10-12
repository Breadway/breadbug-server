//! What happens to a cluster after a human acts on it: promotion to a
//! breadboard issue, growth comments, fixed detection and regression.

use std::cmp::Ordering;

use anyhow::{bail, Result};
use serde_json::Value;

use crate::app::AppState;
use crate::board::fenced;
use crate::db::ClusterRow;
use crate::triage::score;

/// Numbers in a version string, plus whether it is a release (not a dev or
/// rc build). `0.9.1-dev.2026...` sorts before `0.9.1`, which sorts before `0.9.2`.
pub fn version_key(v: &str) -> (Vec<u64>, bool, Vec<u64>) {
    let (core, pre) = match v.split_once(['-', '+']) {
        Some((c, p)) => (c, Some(p)),
        None => (v, None),
    };
    let nums = |s: &str| -> Vec<u64> {
        s.split(|c: char| !c.is_ascii_digit())
            .filter(|p| !p.is_empty())
            .filter_map(|p| p.parse().ok())
            .collect()
    };
    let mut triple = nums(core);
    while triple.len() < 3 {
        triple.push(0);
    }
    let is_pre = pre.is_some_and(|p| p.starts_with(|c: char| c.is_ascii_alphabetic()));
    (triple, !is_pre, pre.map(nums).unwrap_or_default())
}

pub fn version_cmp(a: &str, b: &str) -> Ordering {
    version_key(a).cmp(&version_key(b))
}

/// Confidence wording from how much evidence there is.
fn confidence(c: &ClusterRow) -> &'static str {
    match (c.count, c.installs) {
        (_, i) if i >= 3 => "high (several independent installs)",
        (n, _) if n >= 3 => "medium (repeated, few installs)",
        _ => "low (a single report so far)",
    }
}

/// Breadboard priority from a score.
pub fn priority_for(total: i32) -> &'static str {
    match total {
        t if t >= 150 => "urgent",
        t if t >= 110 => "high",
        t if t >= 60 => "medium",
        _ => "low",
    }
}

fn one_line(s: &str, max: usize) -> String {
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(max)
        .collect()
}

/// The issue body: how it was found, confidence, and what the bug is.
pub fn issue_body(c: &ClusterRow, samples: &[String], cluster_url: Option<&str>) -> String {
    let versions = c
        .versions
        .iter()
        .map(|(v, n)| format!("{} ({n})", one_line(v, 128)))
        .collect::<Vec<_>>()
        .join(", ");
    let os = c
        .os_builds
        .iter()
        .map(|(v, n)| format!("{} ({n})", one_line(v, 128)))
        .collect::<Vec<_>>()
        .join(", ");
    let mut b = String::new();
    b.push_str("Filed from the breadbug triage inbox.\n\n");
    b.push_str("**How it was found:** opt-in user bug reports (scrubbed client-side and server-side), grouped by breadbug-server.\n\n");
    b.push_str(&format!("**Confidence:** {}.\n\n", confidence(c)));
    b.push_str(&format!(
        "**What it is:** a {} in `{}`: {} report(s) from {} install(s), first seen {}, last seen {}.\n\n",
        c.kind,
        c.app,
        c.count,
        c.installs,
        crate::admin::fmt_utc(c.first_seen),
        crate::admin::fmt_utc(c.last_seen),
    ));
    b.push_str(&format!(
        "Affected app versions: {}\n\n",
        if versions.is_empty() {
            "unknown".into()
        } else {
            versions
        }
    ));
    b.push_str(&format!(
        "OS builds: {}\n\n",
        if os.is_empty() { "unknown".into() } else { os }
    ));
    b.push_str("Representative evidence (untrusted text from user reports, shown as data):\n\n");
    for s in samples.iter().take(3) {
        b.push_str(&fenced(s));
        b.push_str("\n\n");
    }
    match cluster_url {
        Some(base) => b.push_str(&format!(
            "Cluster #{} in breadbug-server: {base}/{}",
            c.id, c.id
        )),
        None => b.push_str(&format!("Cluster #{} in breadbug-server.", c.id)),
    }
    b
}

/// One compact evidence block from a stored report.
pub fn evidence(raw: &str) -> String {
    let Ok(v) = serde_json::from_str::<Value>(raw) else {
        return String::new();
    };
    let mut lines: Vec<String> = Vec::new();
    if let Some(m) = v["markers"].as_array().and_then(|m| m.last()) {
        if let Some(msg) = m["message"].as_str() {
            lines.push(format!(
                "{}: {}",
                m["kind"].as_str().unwrap_or("marker"),
                one_line(msg, 200)
            ));
        }
        for f in m["frames"].as_array().into_iter().flatten().take(8) {
            let sym = f["symbol"].as_str().map(String::from).or_else(|| {
                Some(format!(
                    "{}+{:#x}",
                    f["module"].as_str()?,
                    f["offset"].as_u64()?
                ))
            });
            if let Some(s) = sym {
                let at = match (f["file"].as_str(), f["line"].as_u64()) {
                    (Some(file), Some(line)) => format!(" ({file}:{line})"),
                    _ => String::new(),
                };
                lines.push(format!("  {}{at}", one_line(&s, 160)));
            }
        }
    }
    for f in v["live_stack"].as_array().into_iter().flatten().take(8) {
        if let Some(s) = f["symbol"].as_str() {
            lines.push(format!("  live: {}", one_line(s, 160)));
        }
    }
    if let Some(n) = v["notes"].as_str().filter(|n| !n.trim().is_empty()) {
        lines.push(format!("user note: {}", one_line(n, 300)));
    }
    lines.join("\n")
}

/// Create the breadboard issue for a cluster and record it. Fails (without
/// side effects) if the cluster already has an issue, or breadboard is not
/// configured or errors.
pub fn promote(s: &AppState, cluster_id: i64) -> Result<String> {
    let Some(board) = s.board() else {
        bail!("breadboard is not configured (BREADBUG_BOARD_URL and token)");
    };
    if !s.db.begin_promotion(cluster_id)? {
        bail!("this cluster already has an issue, was merged, or does not exist");
    }
    let result = (|| -> Result<(String, String)> {
        let c =
            s.db.cluster(cluster_id)?
                .ok_or_else(|| anyhow::anyhow!("no such cluster"))?;
        let samples: Vec<String> =
            s.db.cluster_samples(cluster_id, 3)?
                .iter()
                .map(|r| evidence(&r.raw))
                .filter(|e| !e.is_empty())
                .collect();
        let total = score(&c, crate::app::now_unix(), s.rules()).total;
        let priority = priority_for(total);
        let title = format!("[breadbug] {}", one_line(&c.title, 100));
        let key = board.create_issue(
            &board.project_for(&c.app),
            &title,
            &issue_body(&c, &samples, s.cfg.cluster_url.as_deref()),
            priority,
            &["breadbug", &c.kind],
        )?;
        Ok((key, priority.to_string()))
    })();
    match result {
        Ok((key, priority)) => {
            s.db.finish_promotion(cluster_id, &key, &priority)?;
            Ok(key)
        }
        Err(e) => {
            s.db.abort_promotion(cluster_id)?;
            Err(e)
        }
    }
}

fn is_power_of_two_growth(count: u64, notified: u64) -> bool {
    count >= 4 && count >= notified.saturating_mul(2)
}

fn priority_rank(p: &str) -> u8 {
    match p {
        "urgent" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

/// Run after a report joined a cluster: regression detection, then growth
/// comments and priority bumps for promoted clusters. Failures are returned
/// for logging and never affect intake.
pub fn after_report(s: &AppState, cluster_id: i64, report_version: Option<&str>) -> Result<()> {
    let Some(c) = s.db.cluster(cluster_id)? else {
        return Ok(());
    };
    let key = c.issue_key.clone().filter(|k| k != "pending");

    if c.status == "fixed" {
        let newer = match (&c.fixed_in, report_version) {
            (Some(fixed), Some(v)) => version_cmp(v, fixed) != Ordering::Less,
            // No fix version recorded: a version we have never seen before
            // that is newer than every version already in the cluster. (The
            // report that just arrived is already counted, so "never seen"
            // means its count is exactly one.)
            (None, Some(v)) => {
                c.versions.get(v) == Some(&1)
                    && c.versions.len() > 1
                    && c.versions
                        .keys()
                        .filter(|k| k.as_str() != v)
                        .all(|k| version_cmp(v, k) == Ordering::Greater)
            }
            _ => false,
        };
        if newer {
            // Do the board side effects before persisting the local state:
            // if breadboard is down or errors, the cluster stays fixed and
            // the next matching report retries the reopen instead of losing
            // it. (A partial failure can repeat the comment, which is
            // preferable to a silently dropped reopen.)
            if let (Some(board), Some(key)) = (s.board(), &key) {
                let v = report_version.unwrap_or("?");
                board.comment(key, &format!("Regression: a new report arrived from version `{v}`, which is not older than the fix. Reopening."))?;
                board.reopen(key)?;
            }
            s.db.set_status(cluster_id, "regressed")?;
        }
        return Ok(());
    }

    let (Some(board), Some(key)) = (s.board(), key) else {
        return Ok(());
    };
    let (current_priority, notified) = s.db.issue_priority(cluster_id)?;
    if !is_power_of_two_growth(c.count, notified) {
        return Ok(());
    }
    let total = score(&c, crate::app::now_unix(), s.rules()).total;
    let wanted = priority_for(total);
    let bump = priority_rank(wanted) > priority_rank(current_priority.as_deref().unwrap_or(""));
    board.comment(
        &key,
        &format!(
            "Now {} report(s) from {} install(s) across {} version(s); last seen {}.{}",
            c.count,
            c.installs,
            c.versions.len(),
            crate::admin::fmt_utc(c.last_seen),
            if bump {
                format!(" Raising priority to {wanted}.")
            } else {
                String::new()
            }
        ),
    )?;
    if bump {
        board.set_priority(&key, wanted)?;
    }
    s.db.set_notified(cluster_id, c.count, bump.then_some(wanted))?;
    Ok(())
}

/// Hourly: promoted clusters whose issue reached `done` are marked fixed.
/// Returns how many changed.
pub fn sync_issue_states(s: &AppState) -> Result<usize> {
    let Some(board) = s.board() else {
        return Ok(0);
    };
    let mut changed = 0;
    for (id, key) in s.db.tracked_issues()? {
        let Ok(state) = board.issue_state(&key) else {
            continue;
        };
        let Some(c) = s.db.cluster(id)? else { continue };
        if state.status == "done" && c.status != "fixed" {
            // Persist the board's fix version when it records one, so the
            // public "fixed in" and the regression threshold use it. With no
            // version, regression is judged against versions already seen
            // (see `after_report`).
            match state.fix_version {
                Some(v) => {
                    s.db.mark_fixed(id, &v)?;
                }
                None => {
                    s.db.set_status(id, "fixed")?;
                }
            }
            changed += 1;
        }
    }
    Ok(changed)
}

#[cfg(test)]
mod tests;
