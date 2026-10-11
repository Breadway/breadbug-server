//! Deterministic crash fingerprints.
//!
//! The same bug should hash the same across releases, so the fingerprint is
//! built from things that survive a rebuild: normalized function names (not
//! addresses), the normalized source location, and the panic message with
//! numbers removed. Runtime and panic-machinery frames are noise and are
//! skipped. Frames with no symbol fall back to `build-id/module+offset`, which only
//! groups within one build; that is still correct, just narrower.
//!
//! Normalization rules are versioned (`RULES_VERSION`) so stored reports can
//! be re-fingerprinted when they change.

use sha2::{Digest, Sha256};

use crate::schema::{Frame, Marker, MarkerKind, Report};

/// Bump when normalization changes; fingerprints include it.
pub const RULES_VERSION: u32 = 2;
/// How many useful frames go into the fingerprint.
pub const TOP_FRAMES: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    /// Hex digest, 32 chars.
    pub key: String,
    /// Short human title for the cluster.
    pub title: String,
}

/// Drop the `::h0123456789abcdef` hash Rust appends to legacy symbols.
fn strip_hash(s: &str) -> &str {
    match s.rfind("::h") {
        Some(i) => {
            let tail = &s[i + 3..];
            if tail.len() == 16 && tail.bytes().all(|b| b.is_ascii_hexdigit()) {
                &s[..i]
            } else {
                s
            }
        }
        None => s,
    }
}

/// Remove every balanced `<...>` group (generic arguments, trait casts).
fn strip_generics(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut depth = 0usize;
    for c in s.chars() {
        match c {
            '<' => depth += 1,
            '>' if depth > 0 => depth -= 1,
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

/// `{{closure}}` / `{closure#3}` -> `{closure}`.
fn normalize_closures(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('{') {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        let end = tail.find('}').map_or(tail.len(), |e| e + 1);
        let group = tail[..end].trim_matches(|c| c == '{' || c == '}');
        let word: String = group.chars().take_while(|c| c.is_alphabetic()).collect();
        out.push_str(&format!("{{{word}}}"));
        rest = &tail[end..];
        // a doubled brace group `{{closure}}` leaves a trailing `}`
        rest = rest.strip_prefix('}').unwrap_or(rest);
    }
    out.push_str(rest);
    out
}

/// A symbol with the parts that vary between builds removed.
pub fn normalize_symbol(sym: &str) -> String {
    let s = strip_hash(sym.trim());
    let s = strip_generics(s);
    let s = normalize_closures(&s);
    s.trim_matches(':').to_string()
}

const NOISE_PREFIXES: &[&str] = &[
    "core::panicking",
    "core::result::unwrap_failed",
    "core::option::unwrap_failed",
    "core::option::expect_failed",
    "core::option::Option::unwrap",
    "core::option::Option::expect",
    "core::result::Result::unwrap",
    "core::result::Result::expect",
    "core::ops::function",
    "std::panicking",
    "std::rt::",
    "std::sys",
    "std::thread::local",
    "std::panic::",
    "rust_begin_unwind",
    "rust_panic",
    "__rust_",
    "_start",
    "__libc_start",
    "start_thread",
    "clone3",
    "clone",
    "poll",
    "__poll",
    "g_main_context_iterate",
    "g_main_context_dispatch",
    "g_main_loop_run",
    "g_main_context_",
];

/// Frames that appear in almost every stack and say nothing about the bug.
pub fn is_noise(normalized: &str) -> bool {
    normalized.is_empty() || NOISE_PREFIXES.iter().any(|p| normalized.starts_with(p))
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn frame_token(f: &Frame) -> Option<String> {
    if let Some(sym) = f.symbol.as_deref() {
        let n = normalize_symbol(sym);
        return (!is_noise(&n)).then_some(n);
    }
    match (f.build_id.as_deref(), f.module.as_deref(), f.offset) {
        (Some(build), Some(m), Some(off)) if !build.is_empty() => {
            Some(format!("{build}/{}+{off:x}", basename(m)))
        }
        _ => None,
    }
}

/// Normalize paths but preserve line/column to avoid conflating panic sites.
/// Source movement across releases can split a cluster; human merging is
/// safer than automatically grouping two failures in the same function.
pub fn normalize_location(loc: &str) -> String {
    let (path, position) = loc.split_once(':').unwrap_or((loc, ""));
    let comps: Vec<&str> = path
        .split('/')
        .filter(|c| !c.is_empty() && *c != "<HOME>")
        .collect();
    let cleaned: Vec<String> = comps
        .iter()
        .map(|c| {
            // `name-1.2.3` -> `name`
            match c.rfind('-') {
                Some(i)
                    if c[i + 1..]
                        .chars()
                        .next()
                        .is_some_and(|d| d.is_ascii_digit())
                        && c[i + 1..].chars().all(|d| d.is_ascii_digit() || d == '.') =>
                {
                    c[..i].to_string()
                }
                _ => (*c).to_string(),
            }
        })
        .collect();
    let keep = cleaned.len().saturating_sub(3);
    let path = cleaned[keep..].join("/");
    if position.is_empty() {
        path
    } else {
        format!("{path}:{position}")
    }
}

/// Panic text with numbers, markers and quoting noise removed.
pub fn normalize_message(msg: &str) -> String {
    let mut out = String::new();
    let mut in_marker = false;
    let mut prev_digit = false;
    for c in msg.chars() {
        match c {
            '<' => in_marker = true,
            '>' if in_marker => in_marker = false,
            _ if in_marker => {}
            d if d.is_ascii_digit() => {
                if !prev_digit {
                    out.push('#');
                }
                prev_digit = true;
                continue;
            }
            c => out.push(c),
        }
        prev_digit = false;
    }
    let collapsed = out.split_whitespace().collect::<Vec<_>>().join(" ");
    collapsed.chars().take(120).collect()
}

/// The marker a crash cluster is built from: the newest panic or crash with
/// frames or a message.
fn problem_marker(report: &Report) -> Option<&Marker> {
    report
        .markers
        .iter()
        .rev()
        .find(|m| matches!(m.kind, MarkerKind::Panic | MarkerKind::Crash))
}

/// Fingerprint a report, or `None` when there is nothing stable to hash
/// (a behavior report, or a freeze with no stack). Those go to the fuzzy
/// clustering step instead.
pub fn fingerprint(report: &Report) -> Option<Fingerprint> {
    let marker = problem_marker(report);
    let frames: &[Frame] = match marker {
        Some(m) if !m.frames.is_empty() => &m.frames,
        _ => &report.live_stack,
    };
    let tokens: Vec<String> = frames
        .iter()
        .filter_map(frame_token)
        .take(TOP_FRAMES)
        .collect();
    let location = marker
        .and_then(|m| m.location.as_deref())
        .map(normalize_location)
        .unwrap_or_default();
    let message = marker
        .and_then(|m| m.message.as_deref())
        .map(normalize_message)
        .unwrap_or_default();

    if tokens.is_empty() && location.is_empty() {
        return None;
    }
    let kind = match marker.map(|m| m.kind) {
        Some(_) => "crash",
        None => "freeze",
    };
    let material = format!(
        "v{RULES_VERSION}|{}|{kind}|{}|{location}|{message}",
        report.app.id,
        tokens.join(">")
    );
    let key = hex::encode(&Sha256::digest(material.as_bytes())[..16]);
    let title = if !message.is_empty() {
        message
    } else if let Some(t) = tokens.first() {
        format!("{kind} in {t}")
    } else {
        format!("{kind} at {location}")
    };
    Some(Fingerprint { key, title })
}

#[cfg(test)]
mod tests;
