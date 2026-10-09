//! Fuzzy matching for reports with no stable fingerprint (freezes without a
//! stack, behavior reports, log-only problems).
//!
//! Report text is turned into a fixed-size vector and compared by cosine
//! similarity against the centroids of existing fuzzy clusters for the same
//! app and kind. Embedding happens locally: the default [`HashEmbedder`] is
//! a feature-hashing bag of words and bigrams with no model to download, and
//! [`HttpEmbedder`] can call a local sentence-embedding service
//! (text-embeddings-inference style) when better paraphrase handling is
//! wanted. Report text never goes to a third party.

use std::io::Read;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};

use crate::schema::Report;

pub const HASH_DIM: usize = 256;
const STOPWORDS: &[&str] = &[
    "the", "and", "for", "with", "that", "this", "when", "then", "was", "are", "has", "have",
    "had", "not", "but", "from", "into", "out", "its", "it", "is", "in", "on", "of", "to", "a",
    "an", "at", "as", "by", "be", "or", "my", "me", "i", "after", "while", "again", "just", "now",
];

pub trait Embedder: Send + Sync {
    /// A short identifier stored with each embedding, so vectors from a
    /// different model are never compared.
    fn model(&self) -> &str;
    fn embed(&self, text: &str) -> Result<Vec<f32>>;
}

/// Lowercase word tokens, numbers collapsed, redaction markers and
/// stopwords dropped.
pub fn tokens(text: &str) -> Vec<String> {
    let mut cleaned = String::with_capacity(text.len());
    let mut in_marker = false;
    for c in text.chars() {
        match c {
            '<' => in_marker = true,
            '>' if in_marker => in_marker = false,
            _ if in_marker => {}
            c => cleaned.push(c),
        }
    }
    cleaned
        .to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(|t| {
            if t.chars().all(|c| c.is_ascii_digit()) {
                "#".to_string()
            } else {
                t.to_string()
            }
        })
        .filter(|t| t != "#" && t.chars().count() >= 2 && !STOPWORDS.contains(&t.as_str()))
        .collect()
}

fn fnv(s: &str) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for b in s.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn l2_normalize(v: &mut [f32]) {
    let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 0.0 {
        v.iter_mut().for_each(|x| *x /= norm);
    }
}

/// Feature hashing over unigrams (weight 1) and bigrams (weight 0.5), with a
/// sign bit so collisions cancel rather than pile up.
pub struct HashEmbedder;

impl Embedder for HashEmbedder {
    fn model(&self) -> &str {
        "hash-v1-256"
    }

    fn embed(&self, text: &str) -> Result<Vec<f32>> {
        let toks = tokens(text);
        let mut v = vec![0f32; HASH_DIM];
        let mut add = |feature: &str, weight: f32| {
            let h = fnv(feature);
            let idx = (h % HASH_DIM as u64) as usize;
            let sign = if (h >> 63) & 1 == 0 { 1.0 } else { -1.0 };
            v[idx] += sign * weight;
        };
        for t in &toks {
            add(t, 1.0);
        }
        for w in toks.windows(2) {
            add(&format!("{} {}", w[0], w[1]), 0.5);
        }
        l2_normalize(&mut v);
        Ok(v)
    }
}

/// Calls a local embedding service: `POST {url}` with `{"inputs": [text]}`,
/// expecting `[[f32, ...]]`. Only loopback and private-range hosts are
/// accepted; report text must not leave the machine.
pub struct HttpEmbedder {
    url: String,
    model: String,
    agent: ureq::Agent,
}

fn local_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let host = rest.split(['/', ':']).next().unwrap_or("");
    host == "localhost"
        || host == "127.0.0.1"
        || host.starts_with("10.")
        || host.starts_with("192.168.")
        || host.starts_with("172.16.")
        || host == "host.docker.internal"
}

impl HttpEmbedder {
    pub fn new(url: &str, model: &str) -> Result<Self> {
        if !local_url(url) {
            bail!("embedding service must be a local http:// address (got {url})");
        }
        Ok(Self {
            url: url.to_string(),
            model: format!("http:{model}"),
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(10))
                .redirects(0)
                .build(),
        })
    }
}

impl Embedder for HttpEmbedder {
    fn model(&self) -> &str {
        &self.model
    }

    fn embed(&self, text: &str) -> Result<Vec<f32>> {
        let resp = self
            .agent
            .post(&self.url)
            .send_json(json!({ "inputs": [text] }))
            .map_err(|e| anyhow!("embedding service: {e}"))?;
        let mut body = String::new();
        resp.into_reader()
            .take(4 * 1024 * 1024)
            .read_to_string(&mut body)?;
        let v: Value = serde_json::from_str(&body)?;
        let row = v
            .get(0)
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("unexpected embedding reply"))?;
        let mut out: Vec<f32> = row
            .iter()
            .filter_map(|x| x.as_f64().map(|f| f as f32))
            .collect();
        if out.is_empty() || out.len() != row.len() {
            bail!("embedding reply had non-numeric entries");
        }
        l2_normalize(&mut out);
        Ok(out)
    }
}

pub fn cosine(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

/// A mean of unit vectors, renormalised.
pub fn centroid(vectors: &[Vec<f32>]) -> Option<Vec<f32>> {
    let dim = vectors.first()?.len();
    let mut acc = vec![0f32; dim];
    for v in vectors.iter().filter(|v| v.len() == dim) {
        acc.iter_mut().zip(v).for_each(|(a, x)| *a += x);
    }
    l2_normalize(&mut acc);
    Some(acc)
}

pub fn to_bytes(v: &[f32]) -> Vec<u8> {
    v.iter().flat_map(|x| x.to_le_bytes()).collect()
}

pub fn from_bytes(b: &[u8]) -> Vec<f32> {
    b.chunks_exact(4)
        .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

/// The text a report is matched on: what the user said and what went wrong,
/// not machine facts (those are the same for everyone).
pub fn report_text(r: &Report) -> String {
    let mut parts: Vec<String> = Vec::new();
    parts.push(r.report_type.as_str().to_string());
    if let Some(n) = &r.notes {
        // The user's own words are the strongest signal: count them twice.
        parts.push(n.clone());
        parts.push(n.clone());
    }
    for m in &r.markers {
        if let Some(msg) = &m.message {
            parts.push(msg.clone());
        }
        if let Some(loc) = &m.location {
            parts.push(loc.clone());
        }
    }
    for l in r
        .logs
        .iter()
        .chain(&r.daemon_logs)
        .filter(|l| l.level == "WARN" || l.level == "ERROR")
    {
        parts.push(l.msg.clone());
    }
    for f in &r.live_stack {
        if let Some(s) = &f.symbol {
            parts.push(s.clone());
        }
    }
    for e in r.events.iter().rev().take(10) {
        parts.push(e.name.clone());
    }
    parts.join("\n")
}

/// A short title for a new fuzzy cluster.
pub fn title_for(r: &Report) -> String {
    let basis = r
        .notes
        .as_deref()
        .filter(|n| !n.trim().is_empty())
        .or_else(|| r.markers.iter().find_map(|m| m.message.as_deref()))
        .or_else(|| {
            r.logs
                .iter()
                .rev()
                .find(|l| l.level == "ERROR" || l.level == "WARN")
                .map(|l| l.msg.as_str())
        })
        .unwrap_or("");
    let line = basis.lines().next().unwrap_or("").trim();
    let t: String = line.chars().take(100).collect();
    if t.is_empty() {
        format!("{} report for {}", r.report_type.as_str(), r.app.id)
    } else {
        t
    }
}

#[cfg(test)]
mod tests;
