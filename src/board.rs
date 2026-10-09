//! A small breadboard API client, used to turn triaged clusters into issues.
//!
//! The token is a dedicated, minimum-scope breadboard API token read from the
//! environment or a file; it never appears in the repo or in logs. Report
//! text that ends up in an issue is placed inside fenced code blocks so it is
//! inert markdown.

use std::collections::HashMap;
use std::io::Read;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};

/// Project key for each app id; apps not listed go to `ECO`.
pub fn default_projects() -> HashMap<String, String> {
    [
        ("clip", "CLIP"),
        ("pad", "PAD"),
        ("bar", "BAR"),
        ("box", "BOX"),
        ("lock", "LOCK"),
        ("mon", "MON"),
        ("paper", "PAPER"),
        ("search", "SEARCH"),
        ("shot", "SHOT"),
        ("arr", "ARR"),
        ("crumbs", "CRUMB"),
        ("help", "HELP"),
        ("cast", "CAST"),
        ("bakery", "ECO"),
        ("breadd", "BREAD"),
        ("settings", "BSET"),
    ]
    .into_iter()
    .map(|(a, p)| (a.to_string(), p.to_string()))
    .collect()
}

/// Parse `app=PROJECT,app=PROJECT` overrides onto the defaults.
pub fn parse_projects(spec: &str) -> HashMap<String, String> {
    let mut m = default_projects();
    for pair in spec.split(',').filter(|p| !p.trim().is_empty()) {
        if let Some((app, proj)) = pair.split_once('=') {
            let (app, proj) = (app.trim(), proj.trim());
            if crate::schema::valid_app_id(app)
                && !proj.is_empty()
                && proj.bytes().all(|b| b.is_ascii_alphanumeric())
            {
                m.insert(app.to_string(), proj.to_ascii_uppercase());
            }
        }
    }
    m
}

pub struct BoardClient {
    base: String,
    token: String,
    agent: ureq::Agent,
    projects: HashMap<String, String>,
}

fn base_ok(url: &str) -> bool {
    url.starts_with("https://")
        || url.starts_with("http://127.0.0.1")
        || url.starts_with("http://localhost")
}

impl BoardClient {
    pub fn new(base: &str, token: &str, projects: HashMap<String, String>) -> Result<Self> {
        let base = base.trim_end_matches('/').to_string();
        if !base_ok(&base) {
            bail!("breadboard URL must be https (got {base})");
        }
        if token.trim().is_empty() {
            bail!("breadboard token is empty");
        }
        Ok(Self {
            base,
            token: token.trim().to_string(),
            agent: ureq::AgentBuilder::new()
                .redirects(0)
                .timeout_connect(Duration::from_secs(5))
                .timeout(Duration::from_secs(15))
                .user_agent("breadbug-server")
                .build(),
            projects,
        })
    }

    pub fn project_for(&self, app: &str) -> String {
        self.projects
            .get(app)
            .cloned()
            .unwrap_or_else(|| "ECO".into())
    }

    fn call(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value> {
        let req = self
            .agent
            .request(method, &format!("{}/api{path}", self.base))
            .set("Authorization", &format!("Bearer {}", self.token));
        let resp = match body {
            Some(b) => req.send_json(b),
            None => req.call(),
        };
        let resp = match resp {
            Ok(r) => r,
            // Never echo the token or request: just the status.
            Err(ureq::Error::Status(code, _)) => bail!("breadboard answered HTTP {code}"),
            Err(ureq::Error::Transport(t)) => bail!("breadboard unreachable: {}", t.kind()),
        };
        if !(200..300).contains(&resp.status()) {
            bail!("breadboard answered HTTP {}", resp.status());
        }
        let mut text = String::new();
        resp.into_reader()
            .take(2 * 1024 * 1024)
            .read_to_string(&mut text)?;
        Ok(serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    /// Create an issue; returns its key.
    pub fn create_issue(
        &self,
        project: &str,
        title: &str,
        body: &str,
        priority: &str,
        labels: &[&str],
    ) -> Result<String> {
        let v = self.call(
            "POST",
            "/issues",
            Some(json!({
                "title": title,
                "body": body,
                "project": project,
                "status": "backlog",
                "priority": priority,
                "labels": labels,
            })),
        )?;
        v["key"]
            .as_str()
            .filter(|k| k.len() <= 32 && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
            .map(String::from)
            .ok_or_else(|| anyhow!("breadboard reply had no issue key"))
    }

    pub fn comment(&self, key: &str, body: &str) -> Result<()> {
        self.call(
            "POST",
            &format!("/issues/{}/comments", safe_key(key)?),
            Some(json!({ "body": body })),
        )?;
        Ok(())
    }

    pub fn set_priority(&self, key: &str, priority: &str) -> Result<()> {
        self.call(
            "PATCH",
            &format!("/issues/{}", safe_key(key)?),
            Some(json!({ "priority": priority })),
        )?;
        Ok(())
    }

    pub fn reopen(&self, key: &str) -> Result<()> {
        self.call(
            "PATCH",
            &format!("/issues/{}", safe_key(key)?),
            Some(json!({ "status": "todo" })),
        )?;
        Ok(())
    }

    /// The issue's workflow status (`done`, `review`, ...).
    pub fn status(&self, key: &str) -> Result<String> {
        let v = self.call("GET", &format!("/issues/{}", safe_key(key)?), None)?;
        v["status"]
            .as_str()
            .or_else(|| v["issue"]["status"].as_str())
            .map(String::from)
            .ok_or_else(|| anyhow!("breadboard reply had no status"))
    }
}

fn safe_key(key: &str) -> Result<&str> {
    if !key.is_empty()
        && key.len() <= 32
        && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        Ok(key)
    } else {
        bail!("invalid issue key")
    }
}

/// Wrap untrusted text in a fenced code block that it cannot close early.
pub fn fenced(text: &str) -> String {
    let longest = text.split(|c| c != '`').map(str::len).max().unwrap_or(0);
    let fence = "`".repeat(longest.max(2) + 1);
    format!("{fence}\n{}\n{fence}", text.trim_end())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fences_cannot_be_closed_by_content() {
        assert_eq!(fenced("hi"), "```\nhi\n```");
        let f = fenced("a ``` b\n````` c");
        assert!(f.starts_with("``````\n") && f.ends_with("\n``````"), "{f}");
    }

    #[test]
    fn project_mapping_has_defaults_and_validated_overrides() {
        let m = parse_projects("clip=NEWCLIP, evil=bad;drop, pad = pad2 ,../x=Y");
        assert_eq!(m["clip"], "NEWCLIP");
        assert_eq!(m["pad"], "PAD2");
        assert_eq!(m["bar"], "BAR");
        assert!(!m.contains_key("evil") && !m.contains_key("../x"));
    }

    #[test]
    fn client_requires_https_and_a_token() {
        assert!(BoardClient::new("http://board.example.com", "t", default_projects()).is_err());
        assert!(BoardClient::new("https://board.example.com", "", default_projects()).is_err());
        assert!(BoardClient::new("https://board.example.com/", "t", default_projects()).is_ok());
        assert!(BoardClient::new("http://127.0.0.1:1", "t", default_projects()).is_ok());
    }

    #[test]
    fn issue_keys_are_validated_before_use_in_paths() {
        for bad in ["", "../x", "A B", "A/1", &"A".repeat(40)] {
            assert!(safe_key(bad).is_err(), "{bad:?}");
        }
        assert!(safe_key("BREAD-14").is_ok());
    }
}
