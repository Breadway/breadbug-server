//! Explainable severity scoring for clusters.
//!
//! Severity is rules, not a model: crash beats freeze beats behavior, then
//! volume, spread across installs and versions, and recency adjust it. Every
//! point is attributed to a rule so the inbox can show why a cluster ranks
//! where it does. Rules can be tuned with a TOML file (`BREADBUG_TRIAGE_RULES`).

use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::db::ClusterRow;

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default)]
pub struct ScoreRules {
    pub crash: i32,
    pub freeze: i32,
    pub behavior: i32,
    /// Points per doubling of the report count, up to `volume_max`.
    pub volume_per_doubling: i32,
    pub volume_max: i32,
    /// Points per distinct install beyond the first, up to `installs_max`.
    pub per_extra_install: i32,
    pub installs_max: i32,
    pub seen_last_day: i32,
    pub seen_last_week: i32,
    /// Added when three or more app versions are affected.
    pub version_spread: i32,
    /// Added to a cluster that was marked fixed and then reported again.
    pub regression: i32,
}

impl Default for ScoreRules {
    fn default() -> Self {
        Self {
            crash: 100,
            freeze: 60,
            behavior: 20,
            volume_per_doubling: 10,
            volume_max: 30,
            per_extra_install: 4,
            installs_max: 20,
            seen_last_day: 10,
            seen_last_week: 5,
            version_spread: 5,
            regression: 20,
        }
    }
}

impl ScoreRules {
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parse {}", path.display()))
    }
}

/// A score and the rules that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Score {
    pub total: i32,
    pub parts: Vec<(&'static str, i32)>,
}

pub const DAY: u64 = 24 * 3600;

pub fn score(c: &ClusterRow, now: u64, rules: &ScoreRules) -> Score {
    let mut parts: Vec<(&'static str, i32)> = Vec::new();
    let base = match c.kind.as_str() {
        "crash" => rules.crash,
        "freeze" => rules.freeze,
        _ => rules.behavior,
    };
    parts.push(("kind", base));
    if c.count > 1 {
        let doublings = (c.count as f64).log2().floor() as i32;
        let pts = (doublings * rules.volume_per_doubling).min(rules.volume_max);
        if pts > 0 {
            parts.push(("volume", pts));
        }
    }
    if c.installs > 1 {
        let pts = ((c.installs as i32 - 1) * rules.per_extra_install).min(rules.installs_max);
        parts.push(("distinct installs", pts));
    }
    let age = now.saturating_sub(c.last_seen);
    if age <= DAY {
        parts.push(("seen in the last day", rules.seen_last_day));
    } else if age <= 7 * DAY {
        parts.push(("seen in the last week", rules.seen_last_week));
    }
    if c.versions.len() >= 3 {
        parts.push(("spread across versions", rules.version_spread));
    }
    if c.status == "regressed" {
        parts.push(("regression", rules.regression));
    }
    let total = parts.iter().map(|(_, p)| *p).sum();
    Score { total, parts }
}

#[cfg(test)]
mod tests;
