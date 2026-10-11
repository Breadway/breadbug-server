//! Server-side scrubbing. The client scrubs, but the server never takes that
//! on trust: every report is run through the same rules again. A clean
//! report comes back unchanged; any change means the client let something
//! through, so the report is stored scrubbed and quarantined for review.

use std::collections::BTreeMap;

use bread_scrub::{ScrubContext, Scrubber};
use serde_json::Value;

pub struct Outcome {
    /// The scrubbed value; this is the only form that is ever stored.
    pub value: Value,
    /// New redactions by category. Empty for a clean report.
    pub hits: BTreeMap<String, usize>,
}

impl Outcome {
    pub fn clean(&self) -> bool {
        self.hits.is_empty()
    }
}

/// Build-ids found in a parsed report value, so the hex rule leaves them.
fn build_ids(v: &Value) -> Vec<String> {
    let mut out = Vec::new();
    fn walk(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::Object(m) => {
                for (k, x) in m {
                    if k == "build_id" {
                        if let Some(s) = x.as_str() {
                            out.push(s.to_string());
                        }
                    } else {
                        walk(x, out);
                    }
                }
            }
            Value::Array(a) => a.iter().for_each(|x| walk(x, out)),
            _ => {}
        }
    }
    walk(v, &mut out);
    out
}

pub fn rescrub(report: &Value) -> Outcome {
    let mut scrubber = Scrubber::new(ScrubContext::default());
    for id in build_ids(report) {
        scrubber.keep_build_id(&id);
    }
    let value = scrubber.scrub_value(report);
    let hits = scrubber
        .stats()
        .iter()
        .map(|(k, v)| ((*k).to_string(), *v))
        .collect();
    Outcome { value, hits }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn clean_report_is_unchanged() {
        let v = json!({
            "app": {"id": "clip", "build_id": "3f2a9c1de4b5a6978081726354453423a1b2c3d4"},
            "logs": [{"t": 1, "level": "INFO", "msg": "failed for <USER> at <HOME>/x from <IP:1>"}],
            "redactions": {"IP": 1, "HOME": 1}
        });
        let out = rescrub(&v);
        assert!(out.clean(), "{:?}", out.hits);
        assert_eq!(out.value, v);
    }

    #[test]
    fn leaked_values_are_scrubbed_and_counted() {
        let v = json!({
            "logs": [{"t": 1, "level": "INFO", "msg": "mail me@example.org from 203.0.113.42"}],
            "notes": "token=abc123"
        });
        let out = rescrub(&v);
        let text = out.value.to_string();
        assert!(!text.contains("me@example.org") && !text.contains("203.0.113.42"));
        assert!(!text.contains("abc123"));
        assert_eq!(out.hits.get("EMAIL"), Some(&1));
        assert_eq!(out.hits.get("IP"), Some(&1));
        assert!(!out.clean());
    }
}
