//! The report wire format (schema 1) and its validation.
//!
//! This mirrors `bread-bug`'s report, deliberately re-declared here so the
//! server never trusts the client's types: unknown fields are rejected at
//! every level, every string and list has a hard size limit, and free-form
//! JSON (event data) is bounded in depth and width.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const SCHEMA_VERSION: u32 = 1;

const MAX_STR: usize = 8 * 1024;
const MAX_MSG: usize = 4 * 1024 + 256;
const MAX_TITLE: usize = 256;
const MAX_MARKERS: usize = 8;
const MAX_FRAMES: usize = 128;
const MAX_LOGS: usize = 1000;
const MAX_EVENTS: usize = 500;
const MAX_JOURNAL: usize = 500;
const MAX_APPS: usize = 100;
const MAX_MAP: usize = 64;
const MAX_JSON_DEPTH: usize = 6;
const MAX_JSON_KEYS: usize = 64;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ReportType {
    Crash,
    Freeze,
    Behavior,
    Manual,
    Request,
}

impl ReportType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Crash => "crash",
            Self::Freeze => "freeze",
            Self::Behavior => "behavior",
            Self::Manual => "manual",
            Self::Request => "request",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MarkerKind {
    Panic,
    Crash,
    Freeze,
    Recovered,
    /// A frozen app exited. `breadd` records this for its own bookkeeping and
    /// older clients included it in the report they queued. It is accepted and
    /// stored so those reports are not rejected and lost, but it is not a
    /// panic, crash or freeze signal and never builds or joins a cluster.
    #[serde(rename = "stopped")]
    Stopped,
}

impl MarkerKind {
    /// Whether this marker is the evidence a crash cluster is built from. Only
    /// a panic or crash carries the frames, location and message a fingerprint
    /// hashes. Freeze, recovered and stopped markers are bookkeeping.
    pub fn is_problem(self) -> bool {
        match self {
            Self::Panic | Self::Crash => true,
            Self::Freeze | Self::Recovered | Self::Stopped => false,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppInfo {
    pub id: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub build_id: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemInfo {
    #[serde(default)]
    pub os_id: Option<String>,
    #[serde(default)]
    pub os_version: Option<String>,
    #[serde(default)]
    pub os_build: Option<String>,
    #[serde(default)]
    pub kernel: Option<String>,
    #[serde(default)]
    pub arch: String,
    #[serde(default)]
    pub gpu_drivers: Vec<String>,
    #[serde(default)]
    pub compositor: Option<String>,
    #[serde(default)]
    pub bakery_track: Option<String>,
    #[serde(default)]
    pub breadd_version: Option<String>,
    #[serde(default)]
    pub api_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledApp {
    pub id: String,
    pub version: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSummary {
    #[serde(default)]
    pub daemon_running: bool,
    #[serde(default)]
    pub uptime_s: Option<u64>,
    #[serde(default)]
    pub adapters: BTreeMap<String, String>,
    #[serde(default)]
    pub modules_total: Option<u32>,
    #[serde(default)]
    pub modules_with_errors: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Frame {
    #[serde(default)]
    pub module: Option<String>,
    #[serde(default)]
    pub offset: Option<u64>,
    #[serde(default)]
    pub build_id: Option<String>,
    #[serde(default)]
    pub symbol: Option<String>,
    /// Source file and line, filled in by the server's symbolication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Marker {
    pub t: u64,
    pub kind: MarkerKind,
    #[serde(default)]
    pub app_version: Option<String>,
    #[serde(default)]
    pub build_id: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub location: Option<String>,
    #[serde(default)]
    pub signal: Option<String>,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub frames: Vec<Frame>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogRecord {
    pub t: u64,
    pub level: String,
    pub msg: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventRecord {
    pub t: u64,
    pub name: String,
    #[serde(default)]
    pub data: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub schema: u32,
    pub report_type: ReportType,
    pub created_unix: u64,
    pub app: AppInfo,
    #[serde(default)]
    pub system: SystemInfo,
    #[serde(default)]
    pub installed_apps: Vec<InstalledApp>,
    #[serde(default)]
    pub runtime: RuntimeSummary,
    #[serde(default)]
    pub markers: Vec<Marker>,
    #[serde(default)]
    pub logs: Vec<LogRecord>,
    #[serde(default)]
    pub daemon_logs: Vec<LogRecord>,
    #[serde(default)]
    pub events: Vec<EventRecord>,
    #[serde(default)]
    pub journal: Vec<String>,
    #[serde(default)]
    pub live_stack: Vec<Frame>,
    /// Short user-written title. Only manual reports and feature requests may
    /// set this; automatic reports keep their derived titles so clients
    /// cannot spoof clustering.
    #[serde(default)]
    pub title: Option<String>,
    /// What the requester wants. Only feature requests may set this.
    #[serde(default)]
    pub want: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    /// Optional reference (a path or opaque id, never the bytes) to a
    /// diagnostics bundle the user chose to attach. Requires `consent`.
    #[serde(default)]
    pub diagnostics_reference: Option<String>,
    /// Optional reference to a screenshot the user chose to attach.
    /// Requires `consent`.
    #[serde(default)]
    pub screenshot_reference: Option<String>,
    /// The user's explicit consent to attach the optional diagnostics above.
    #[serde(default)]
    pub consent: bool,
    #[serde(default)]
    pub redactions: BTreeMap<String, usize>,
}

/// `^[a-z][a-z0-9_-]{0,31}$`
pub fn valid_app_id(id: &str) -> bool {
    let mut chars = id.chars();
    id.len() <= 32
        && chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

fn opt(s: &Option<String>, max: usize, what: &str) -> Result<(), String> {
    match s {
        Some(v) if v.len() > max => Err(format!("{what} is too long")),
        _ => Ok(()),
    }
}

fn list<T>(v: &[T], max: usize, what: &str) -> Result<(), String> {
    if v.len() > max {
        Err(format!("{what} has too many entries"))
    } else {
        Ok(())
    }
}

fn json_bounded(v: &Value, depth: usize) -> Result<(), String> {
    if depth > MAX_JSON_DEPTH {
        return Err("event data is nested too deeply".into());
    }
    match v {
        Value::String(s) if s.len() > MAX_STR => Err("event data string is too long".into()),
        Value::Array(a) => {
            if a.len() > MAX_JSON_KEYS {
                return Err("event data array is too long".into());
            }
            a.iter().try_for_each(|x| json_bounded(x, depth + 1))
        }
        Value::Object(m) => {
            if m.len() > MAX_JSON_KEYS {
                return Err("event data has too many keys".into());
            }
            for (k, x) in m {
                if k.len() > 128 {
                    return Err("event data key is too long".into());
                }
                json_bounded(x, depth + 1)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn frames(fs: &[Frame], what: &str) -> Result<(), String> {
    list(fs, MAX_FRAMES, what)?;
    for f in fs {
        opt(&f.module, 1024, "frame module")?;
        opt(&f.build_id, 128, "frame build id")?;
        opt(&f.symbol, 1024, "frame symbol")?;
        opt(&f.file, 1024, "frame file")?;
    }
    Ok(())
}

impl Report {
    /// Parse and validate a request body. Errors are safe to show a client.
    pub fn parse(bytes: &[u8], now_unix: u64) -> Result<Self, String> {
        let report: Report =
            serde_json::from_slice(bytes).map_err(|e| format!("invalid report: {e}"))?;
        report.validate(now_unix)?;
        Ok(report)
    }

    pub fn validate(&self, now_unix: u64) -> Result<(), String> {
        if self.schema != SCHEMA_VERSION {
            return Err(format!("unsupported schema {}", self.schema));
        }
        if !valid_app_id(&self.app.id) {
            return Err("invalid app id".into());
        }
        if self.created_unix > now_unix + 24 * 3600 {
            return Err("created_unix is in the future".into());
        }
        opt(&self.app.version, 128, "app version")?;
        opt(&self.app.build_id, 128, "app build id")?;
        let s = &self.system;
        for (v, w) in [
            (&s.os_id, "os_id"),
            (&s.os_version, "os_version"),
            (&s.os_build, "os_build"),
            (&s.kernel, "kernel"),
            (&s.compositor, "compositor"),
            (&s.bakery_track, "bakery_track"),
            (&s.breadd_version, "breadd_version"),
            (&s.api_version, "api_version"),
        ] {
            opt(v, 256, w)?;
        }
        if s.arch.len() > 64 {
            return Err("arch is too long".into());
        }
        list(&s.gpu_drivers, 8, "gpu_drivers")?;
        if s.gpu_drivers.iter().any(|g| g.len() > 256) {
            return Err("gpu driver is too long".into());
        }
        list(&self.installed_apps, MAX_APPS, "installed_apps")?;
        for a in &self.installed_apps {
            if !valid_app_id(&a.id) || a.version.len() > 128 {
                return Err("invalid installed app".into());
            }
        }
        list(
            &self.runtime.adapters.keys().collect::<Vec<_>>(),
            MAX_MAP,
            "adapters",
        )?;
        if self
            .runtime
            .adapters
            .iter()
            .any(|(k, v)| k.len() > 64 || v.len() > 128)
        {
            return Err("adapter entry is too long".into());
        }
        list(&self.markers, MAX_MARKERS, "markers")?;
        for m in &self.markers {
            opt(&m.app_version, 128, "marker app version")?;
            opt(&m.build_id, 128, "marker build id")?;
            opt(&m.message, MAX_MSG, "marker message")?;
            opt(&m.location, 1024, "marker location")?;
            opt(&m.signal, 64, "marker signal")?;
            frames(&m.frames, "marker frames")?;
        }
        frames(&self.live_stack, "live_stack")?;
        list(&self.logs, MAX_LOGS, "logs")?;
        list(&self.daemon_logs, MAX_LOGS, "daemon_logs")?;
        for l in self.logs.iter().chain(&self.daemon_logs) {
            if l.msg.len() > MAX_MSG || l.level.len() > 16 {
                return Err("log line is too long".into());
            }
        }
        list(&self.events, MAX_EVENTS, "events")?;
        for e in &self.events {
            if e.name.len() > 256 {
                return Err("event name is too long".into());
            }
            json_bounded(&e.data, 0)?;
        }
        list(&self.journal, MAX_JOURNAL, "journal")?;
        if self.journal.iter().any(|l| l.len() > MAX_MSG) {
            return Err("journal line is too long".into());
        }
        opt(&self.notes, MAX_STR, "notes")?;
        opt(
            &self.diagnostics_reference,
            MAX_STR,
            "diagnostics_reference",
        )?;
        opt(&self.screenshot_reference, MAX_STR, "screenshot_reference")?;
        let attaching = self.diagnostics_reference.is_some() || self.screenshot_reference.is_some();
        if attaching && !self.consent {
            return Err("consent is required to attach diagnostics or a screenshot".into());
        }
        if self.report_type == ReportType::Manual {
            match &self.title {
                Some(t) if !t.trim().is_empty() && t.len() <= MAX_TITLE => {}
                _ => return Err("manual reports need a short title".into()),
            }
            match &self.notes {
                Some(n) if !n.trim().is_empty() => {}
                _ => return Err("manual reports need a description in notes".into()),
            }
            if self.want.is_some() {
                return Err("want is only for feature requests".into());
            }
        } else if self.report_type == ReportType::Request {
            match &self.title {
                Some(t) if !t.trim().is_empty() && t.len() <= MAX_TITLE => {}
                _ => return Err("feature requests need a short title".into()),
            }
            match &self.want {
                Some(w) if !w.trim().is_empty() && w.len() <= MAX_STR => {}
                _ => return Err("feature requests need what is wanted in want".into()),
            }
            match &self.notes {
                Some(n) if !n.trim().is_empty() => {}
                _ => return Err("feature requests need why it matters in notes".into()),
            }
        } else if self.title.is_some() || self.want.is_some() {
            return Err("title and want are only for manual reports and requests".into());
        }
        list(
            &self.redactions.keys().collect::<Vec<_>>(),
            MAX_MAP,
            "redactions",
        )?;
        if self.redactions.keys().any(|k| k.len() > 32) {
            return Err("redaction key is too long".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
