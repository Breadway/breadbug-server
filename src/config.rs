//! Runtime configuration, read from the environment.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};

#[derive(Debug, Clone)]
pub struct Config {
    /// Where the database and the generated secret live.
    pub data_dir: PathBuf,
    /// Public intake listener (`/v1/*`, `/healthz`).
    pub public_addr: SocketAddr,
    /// Admin listener (triage UI). Keep it off the public internet.
    pub admin_addr: SocketAddr,
    /// Hex SHA-256 of the admin bearer token; admin is disabled when unset.
    pub admin_token_sha256: Option<String>,
    /// Hard cap on a request body in bytes.
    pub max_body_bytes: usize,
    /// Raw reports older than this are deleted; cluster metadata is kept.
    pub retention: Duration,
    /// Reports per install id per hour.
    pub per_install_per_hour: usize,
    /// Reports per coarse network bucket per hour.
    pub per_network_per_hour: usize,
    /// Reports per hour across everyone.
    pub global_per_hour: usize,
    /// Requests processed at once; the rest get 503.
    pub max_in_flight: usize,
    /// Read the client address from `X-Forwarded-For` (behind Caddy). The
    /// address is only used for an in-memory rate-limit bucket and is never
    /// stored or logged.
    pub trust_proxy: bool,
    /// Largest data directory the server will grow to, in bytes.
    pub max_db_bytes: u64,
    /// Debug symbols keyed by build-id (`<xx>/<build-id>.debug`), published
    /// by the release pipeline. Defaults to `<data_dir>/symbols`.
    pub symbol_dir: Option<PathBuf>,
    /// Cosine similarity at which a report joins an existing fuzzy cluster.
    /// Tuned on `tests/fixtures/fuzzy_eval.json` (see docs/embedding-eval.md).
    pub fuzzy_threshold: f32,
    /// Local embedding service (`http://127.0.0.1:...`); the built-in hashing
    /// embedder is used when unset.
    pub embed_url: Option<String>,
    /// Name recorded with vectors from `embed_url`, so a model change forces
    /// a re-embed instead of mixing vector spaces.
    pub embed_model: String,
    /// Optional TOML with severity rule overrides (see `triage::ScoreRules`).
    pub triage_rules: Option<PathBuf>,
    /// Breadboard base URL (`https://breadboard.breadway.dev`); promotion is
    /// off without it and a token.
    pub board_url: Option<String>,
    /// Breadboard API token. Prefer `BREADBUG_BOARD_TOKEN_FILE`.
    pub board_token: Option<String>,
    /// `app=PROJECT,...` overrides for the app to project mapping.
    pub board_projects: String,
    /// Public base URL of this server's cluster pages. When set, a promoted
    /// issue body links back to the cluster at `<cluster_url>/<id>`. Optional.
    pub cluster_url: Option<String>,
    /// Run lifecycle follow-ups (breadboard comments, regression checks)
    /// before answering instead of on a background thread. For tests.
    pub lifecycle_inline: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("data"),
            public_addr: "127.0.0.1:8120".parse().expect("static addr"),
            admin_addr: "127.0.0.1:8121".parse().expect("static addr"),
            admin_token_sha256: None,
            max_body_bytes: 1536 * 1024,
            retention: Duration::from_secs(90 * 24 * 3600),
            per_install_per_hour: 10,
            per_network_per_hour: 40,
            global_per_hour: 2000,
            max_in_flight: 16,
            trust_proxy: false,
            max_db_bytes: 2 * 1024 * 1024 * 1024,
            symbol_dir: None,
            fuzzy_threshold: 0.30,
            embed_url: None,
            embed_model: "default".to_string(),
            triage_rules: None,
            board_url: None,
            board_token: None,
            board_projects: String::new(),
            cluster_url: None,
            lifecycle_inline: false,
        }
    }
}

fn env_parse<T: std::str::FromStr>(name: &str) -> Result<Option<T>>
where
    T::Err: std::error::Error + Send + Sync + 'static,
{
    match std::env::var(name) {
        Ok(v) if !v.trim().is_empty() => Ok(Some(
            v.trim()
                .parse()
                .with_context(|| format!("{name} is not valid"))?,
        )),
        _ => Ok(None),
    }
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let mut c = Self::default();
        if let Some(v) = env_parse::<PathBuf>("BREADBUG_DATA_DIR")? {
            c.data_dir = v;
        }
        if let Some(v) = env_parse("BREADBUG_PUBLIC_ADDR")? {
            c.public_addr = v;
        }
        if let Some(v) = env_parse("BREADBUG_ADMIN_ADDR")? {
            c.admin_addr = v;
        }
        c.admin_token_sha256 = std::env::var("BREADBUG_ADMIN_TOKEN_SHA256")
            .ok()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty());
        if let Some(v) = env_parse("BREADBUG_MAX_BODY_BYTES")? {
            c.max_body_bytes = v;
        }
        if let Some(days) = env_parse::<u64>("BREADBUG_RETENTION_DAYS")? {
            c.retention = Duration::from_secs(days * 24 * 3600);
        }
        if let Some(v) = env_parse("BREADBUG_PER_INSTALL_PER_HOUR")? {
            c.per_install_per_hour = v;
        }
        if let Some(v) = env_parse("BREADBUG_PER_NETWORK_PER_HOUR")? {
            c.per_network_per_hour = v;
        }
        if let Some(v) = env_parse("BREADBUG_GLOBAL_PER_HOUR")? {
            c.global_per_hour = v;
        }
        if let Some(v) = env_parse("BREADBUG_MAX_IN_FLIGHT")? {
            c.max_in_flight = v;
        }
        if let Some(v) = env_parse::<u8>("BREADBUG_TRUST_PROXY")? {
            c.trust_proxy = v != 0;
        }
        if let Some(v) = env_parse("BREADBUG_MAX_DB_BYTES")? {
            c.max_db_bytes = v;
        }
        if let Some(v) = env_parse("BREADBUG_FUZZY_THRESHOLD")? {
            c.fuzzy_threshold = v;
        }
        c.embed_url = std::env::var("BREADBUG_EMBED_URL")
            .ok()
            .filter(|s| !s.trim().is_empty());
        if let Ok(v) = std::env::var("BREADBUG_EMBED_MODEL") {
            if !v.trim().is_empty() {
                c.embed_model = v.trim().to_string();
            }
        }
        c.triage_rules = env_parse::<PathBuf>("BREADBUG_TRIAGE_RULES")?;
        c.board_url = std::env::var("BREADBUG_BOARD_URL")
            .ok()
            .filter(|s| !s.trim().is_empty());
        c.cluster_url = std::env::var("BREADBUG_CLUSTER_URL")
            .ok()
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty());
        c.board_token = match env_parse::<PathBuf>("BREADBUG_BOARD_TOKEN_FILE")? {
            Some(path) => Some(
                std::fs::read_to_string(&path)
                    .with_context(|| format!("read {}", path.display()))?
                    .trim()
                    .to_string(),
            ),
            None => std::env::var("BREADBUG_BOARD_TOKEN")
                .ok()
                .filter(|s| !s.trim().is_empty()),
        };
        if let Ok(v) = std::env::var("BREADBUG_BOARD_PROJECTS") {
            c.board_projects = v;
        }
        if let Some(v) = env_parse::<PathBuf>("BREADBUG_SYMBOL_DIR")? {
            c.symbol_dir = Some(v);
        }
        Ok(c)
    }

    /// Where debug symbols are looked up.
    pub fn symbols_path(&self) -> PathBuf {
        self.symbol_dir
            .clone()
            .unwrap_or_else(|| self.data_dir.join("symbols"))
    }
}
