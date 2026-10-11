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
        Ok(c)
    }
}
