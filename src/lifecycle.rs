//! What happens to a cluster after a human acts on it: promotion to a
//! breadboard issue, growth comments, fixed detection and regression.

use std::cmp::Ordering;

use anyhow::{bail, Result};
use serde_json::Value;

use crate::app::AppState;
use crate::board::fenced;
use crate::db::ClusterRow;
use crate::triage::score;

/// Sort key for a version string: numeric components, release stage, then the
/// numeric prerelease identifiers. Build metadata (`+...`) never affects
/// precedence. Stages order `dev < beta < rc < release`, so
/// `1.4-dev.20260101` sorts before `1.4-rc.1`, which sorts before `1.4`.
pub fn version_key(v: &str) -> (Vec<u64>, u8, Vec<u64>) {
    let v = v.split('+').next().unwrap_or(v);
    let (core, pre) = match v.split_once('-') {
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
    // 0 dev, 1 beta (and any other named prerelease), 2 rc, 3 release.
    let stage = match pre {
        None => 3,
        Some(p) => {
            let name: String = p
                .chars()
                .take_while(|c| c.is_ascii_alphabetic())
                .collect::<String>()
                .to_ascii_lowercase();
            match name.as_str() {
                "dev" => 0,
                "rc" => 2,
                _ => 1,
            }
        }
    };
    (triple, stage, pre.map(nums).unwrap_or_default())
}

pub fn version_cmp(a: &str, b: &str) -> Ordering {
    version_key(a).cmp(&version_key(b))
}

/// A version string must start with a digit and contain only version
/// characters (`[0-9A-Za-z.+-]`). This keeps empty, whitespace, markdown and
/// other malformed values out of stored release plans.
pub fn valid_version(v: &str) -> bool {
    !v.is_empty()
        && v.starts_with(|c: char| c.is_ascii_digit())
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
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

/// Display name for a cluster kind in filed issues.
fn kind_name(kind: &str) -> &'static str {
    match kind {
        "manual" => "manual bug report",
        "request" => "feature request",
        _ => match kind {
            "crash" => "crash",
            "freeze" => "freeze",
            _ => "behavior",
        },
    }
}

/// How a kind was found, for the issue body.
fn found_by(kind: &str) -> &'static str {
    match kind {
        "manual" => {
            "a user-filed manual bug report (written by the user, scrubbed client-side and server-side)"
        }
        "request" => {
            "a user-filed feature request (written by the user, scrubbed client-side and server-side)"
        }
        _ => "opt-in user bug reports (scrubbed client-side and server-side)",
    }
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
    b.push_str(&format!(
        "**How it was found:** {}, grouped by breadbug-server.\n\n",
        found_by(&c.kind)
    ));
    b.push_str(&format!("**Confidence:** {}.\n\n", confidence(c)));
    b.push_str(&format!(
        "**What it is:** a {} in `{}`: {} report(s) from {} install(s), first seen {}, last seen {}.\n\n",
        kind_name(&c.kind),
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
    if let Some(t) = v["title"].as_str().filter(|t| !t.trim().is_empty()) {
        lines.push(format!("title: {}", one_line(t, 200)));
    }
    if let Some(w) = v["want"].as_str().filter(|w| !w.trim().is_empty()) {
        lines.push(format!("wants: {}", one_line(w, 300)));
    }
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

/// Hourly: clusters whose board issue reached `done` are marked fixed, and a
/// cluster whose issue the board has reopened is returned to the promoted
/// state. The issue's workflow status is cached on every pass so the public
/// progress stage stays current. Returns how many changed.
/// User-facing notice text for a cluster transition. Names the application
/// and version, and says which stage was reached: fixed in development, out
/// in beta, or available in stable.
pub fn notice_text(c: &ClusterRow, event: &str, version: Option<&str>) -> String {
    let (thing, done) = match c.kind.as_str() {
        "request" => ("A feature you follow", "has been implemented"),
        _ => ("A bug you follow", "has been fixed"),
    };
    // Always name the app and the stage, even when no version is known yet.
    match (event, version) {
        ("beta", Some(v)) => format!("{thing} in {} is available in the {v} beta.", c.app),
        ("beta", None) => format!("{thing} in {} is available in the beta channel.", c.app),
        ("stable", Some(v)) => format!("{thing} in {} is available in {v} stable.", c.app),
        ("stable", None) => format!("{thing} in {} is available in the stable channel.", c.app),
        (_, Some(v)) => format!(
            "{thing} in {} {done} in {v}. Thanks for helping us improve it!",
            c.app
        ),
        (_, None) => format!(
            "{thing} in {} {done}. Thanks for helping us improve it!",
            c.app
        ),
    }
}

/// Queue notices for every follow of a cluster. Failures are returned for
/// logging and never affect the admin action or intake.
pub fn notify(
    c: &ClusterRow,
    db: &crate::db::Db,
    event: &str,
    version: Option<&str>,
) -> Result<usize> {
    db.notify_follows(
        c.id,
        event,
        &notice_text(c, event, version),
        crate::app::now_unix(),
    )
}

/// Hourly: clusters whose board issue reached `done` are marked fixed, and a
/// cluster whose issue the board has reopened is returned to the promoted
/// state. The issue's workflow status is cached on every pass so the public
/// progress stage stays current. Returns how many changed.
pub fn sync_issue_states(s: &AppState) -> Result<usize> {
    let Some(board) = s.board() else {
        return Ok(0);
    };
    let mut changed = 0;
    for (id, key) in s.db.tracked_issues()? {
        let Ok(state) = board.issue_state(&key) else {
            continue;
        };
        let _ = s.db.set_issue_status(id, &state.status);
        let Some(c) = s.db.cluster(id)? else { continue };
        let live = matches!(
            c.status.as_str(),
            "promoted" | "regressed" | "investigating" | "new"
        );
        if state.status == "done" {
            if live {
                // Persist the board's fix version when it records one, flag
                // the state as board-driven so a later reopen re-derives it,
                // and queue the notices in the same transaction so a crash
                // cannot lose them.
                let text = notice_text(&c, "fixed", state.fix_version.as_deref());
                s.db.mark_fixed_from_board_and_notify(
                    id,
                    state.fix_version.as_deref(),
                    "fixed",
                    &text,
                    crate::app::now_unix(),
                )?;
                let _ = s.notice_wake().send(());
                changed += 1;
            }
        } else if c.status == "fixed" && c.board_fixed {
            // The board moved a done issue back out of done, so re-derive the
            // public state.
            s.db.reopen_from_board(id)?;
            changed += 1;
        }
    }
    Ok(changed)
}

#[cfg(test)]
mod tests;
