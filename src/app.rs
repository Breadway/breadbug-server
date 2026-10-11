//! The HTTP surface: router, handlers and background maintenance.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use axum::body::to_bytes;
use axum::extract::{DefaultBodyLimit, Path, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use tokio::sync::Semaphore;

use crate::config::Config;
use crate::crypto::{hmac_hex, keyed_u64, random_hex, sha256_hex};
use crate::db::{Db, NewReport};
use crate::ratelimit::Limiter;
use crate::rescrub::rescrub;
use crate::schema::Report;

const HOUR: Duration = Duration::from_secs(3600);

pub struct AppState {
    pub cfg: Config,
    pub db: Arc<Db>,
    secret: Vec<u8>,
    per_install: Limiter,
    per_network: Limiter,
    global: Limiter,
    in_flight: Arc<Semaphore>,
}

impl AppState {
    pub fn new(cfg: Config, db: Db, secret: Vec<u8>) -> Arc<Self> {
        Arc::new(Self {
            per_install: Limiter::new(cfg.per_install_per_hour, HOUR),
            per_network: Limiter::new(cfg.per_network_per_hour, HOUR),
            global: Limiter::new(cfg.global_per_hour, HOUR),
            in_flight: Arc::new(Semaphore::new(cfg.max_in_flight)),
            cfg,
            db: Arc::new(db),
            secret,
        })
    }
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn err(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

fn too_many(wait: Duration) -> Response {
    let mut r = err(StatusCode::TOO_MANY_REQUESTS, "rate limited");
    if let Ok(v) = wait.as_secs().max(1).to_string().parse() {
        r.headers_mut().insert(header::RETRY_AFTER, v);
    }
    r
}

/// The router for the public listener.
pub fn public_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/reports", post(post_report))
        .route("/v1/reports/{receipt}", delete(delete_report))
        .route("/v1/reports/{receipt}/status", get(report_status))
        .layer(DefaultBodyLimit::max(state.cfg.max_body_bytes))
        .with_state(state)
}

/// A coarse network bucket (/24 or /48) from the proxy's header, hashed.
/// Never stored or logged; only used as an in-memory rate-limit key.
fn network_key(state: &AppState, headers: &HeaderMap) -> u64 {
    let bucket: Vec<u8> = state
        .cfg
        .trust_proxy
        .then(|| headers.get("x-forwarded-for"))
        .flatten()
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit(',').next())
        .and_then(|v| v.trim().parse::<IpAddr>().ok())
        .map(|ip| match ip {
            IpAddr::V4(a) => a.octets()[..3].to_vec(),
            IpAddr::V6(a) => a.octets()[..6].to_vec(),
        })
        .unwrap_or_default();
    keyed_u64(&state.secret, "net", &bucket)
}

fn valid_install_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

fn valid_receipt(r: &str) -> bool {
    r.len() == 32 && r.bytes().all(|b| b.is_ascii_hexdigit())
}

async fn post_report(State(s): State<Arc<AppState>>, request: Request) -> Response {
    let Ok(_permit) = s.in_flight.clone().try_acquire_owned() else {
        return err(StatusCode::SERVICE_UNAVAILABLE, "busy, try again later");
    };
    let (parts, incoming) = request.into_parts();
    let headers = parts.headers;
    let now = Instant::now();
    if let Err(wait) = s.global.check(0, now) {
        return too_many(wait);
    }
    if let Err(wait) = s.per_network.check(network_key(&s, &headers), now) {
        return too_many(wait);
    }

    let Some(install) = headers
        .get("x-breadbug-install")
        .and_then(|v| v.to_str().ok())
        .filter(|v| valid_install_id(v))
    else {
        return err(
            StatusCode::BAD_REQUEST,
            "missing or invalid X-Breadbug-Install",
        );
    };
    let install_hash = hmac_hex(
        &s.secret,
        "install",
        install.to_ascii_lowercase().as_bytes(),
    );
    if let Err(wait) = s.per_install.check(
        keyed_u64(&s.secret, "install-rate", install_hash.as_bytes()),
        now,
    ) {
        return too_many(wait);
    }
    // Consume the stream only after admission. Rejected uploads are never
    // buffered, and accepted uploads remain bounded while they are read.
    let body = match to_bytes(incoming, s.cfg.max_body_bytes).await {
        Ok(body) => body,
        Err(_) => return err(StatusCode::PAYLOAD_TOO_LARGE, "body limit exceeded"),
    };
    if let Some(claimed) = headers
        .get("x-breadbug-sha256")
        .and_then(|v| v.to_str().ok())
    {
        if !claimed.eq_ignore_ascii_case(&sha256_hex(&body)) {
            return err(StatusCode::BAD_REQUEST, "payload hash mismatch");
        }
    }
    if body.is_empty() {
        return err(StatusCode::BAD_REQUEST, "empty body");
    }
    let report = match Report::parse(&body, now_unix()) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, &e),
    };

    let state = s.clone();
    let result =
        tokio::task::spawn_blocking(move || store_report(&state, &report, &body, &install_hash))
            .await;
    match result {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => {
            tracing::error!(error = %e, "storing a report failed");
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not store the report",
            )
        }
        Err(_) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not store the report",
        ),
    }
}

fn store_report(
    s: &AppState,
    report: &Report,
    body: &[u8],
    install_hash: &str,
) -> Result<Response> {
    let payload_sha = sha256_hex(body);
    if let Some(receipt) = s.db.find_duplicate(install_hash, &payload_sha)? {
        // Idempotent resend: same receipt, and no new deletion token (the
        // first one still works).
        return Ok((
            StatusCode::OK,
            Json(json!({ "receipt": receipt, "status": "received", "duplicate": true })),
        )
            .into_response());
    }
    if db_too_big(s) {
        // Reclaim free pages first, then evict in age order until the
        // byte-based data-directory quota is satisfied. Metadata alone can
        // exceed a tiny quota; in that case fail without looping forever.
        s.db.compact()?;
        while db_too_big(s) {
            if !s.db.evict_oldest()? {
                return Ok(err(StatusCode::SERVICE_UNAVAILABLE, "storage is full"));
            }
            s.db.compact()?;
        }
    }

    let value: Value = serde_json::from_slice(body)?;
    let outcome = rescrub(&value);
    let hits = serde_json::to_string(&outcome.hits)?;
    let raw = serde_json::to_string(&outcome.value)?;

    let receipt = random_hex(16);
    let token = random_hex(32);
    let report_id = s.db.insert_report(&NewReport {
        receipt: &receipt,
        token_hash: &sha256_hex(token.as_bytes()),
        install_hash,
        payload_sha: &payload_sha,
        received_at: now_unix(),
        app: &report.app.id,
        app_version: report.app.version.as_deref(),
        report_type: report.report_type.as_str(),
        quarantined: !outcome.clean(),
        rescrub_hits: &hits,
        raw: &raw,
    })?;
    // Quarantined reports stay out of clustering until someone reviews them.
    if outcome.clean() {
        if let Err(e) = crate::cluster::assign(&s.db, report_id, report, install_hash) {
            tracing::error!(error = %e, "clustering failed; the report is stored unclustered");
        }
    }
    Ok((
        StatusCode::CREATED,
        Json(json!({ "receipt": receipt, "deletion_token": token, "status": "received" })),
    )
        .into_response())
}

fn db_too_big(s: &AppState) -> bool {
    let size: u64 = std::fs::read_dir(&s.cfg.data_dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.metadata().ok())
        .map(|m| m.len())
        .sum();
    size > s.cfg.max_db_bytes
}

async fn delete_report(
    State(s): State<Arc<AppState>>,
    Path(receipt): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(token) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|t| t.len() == 64)
    else {
        return err(StatusCode::NOT_FOUND, "not found");
    };
    if !valid_receipt(&receipt) {
        return err(StatusCode::NOT_FOUND, "not found");
    }
    if let Err(wait) = s
        .per_network
        .check(network_key(&s, &headers), Instant::now())
    {
        return too_many(wait);
    }
    let token_hash = sha256_hex(token.as_bytes());
    let db = s.db.clone();
    let deleted = tokio::task::spawn_blocking(move || {
        let ok = db.delete_report(&receipt, &token_hash)?;
        if ok {
            db.compact()?;
        }
        anyhow::Ok(ok)
    })
    .await;
    match deleted {
        Ok(Ok(true)) => StatusCode::NO_CONTENT.into_response(),
        Ok(Ok(false)) => err(StatusCode::NOT_FOUND, "not found"),
        _ => err(StatusCode::INTERNAL_SERVER_ERROR, "could not delete"),
    }
}

async fn report_status(State(s): State<Arc<AppState>>, Path(receipt): Path<String>) -> Response {
    if !valid_receipt(&receipt) {
        return err(StatusCode::NOT_FOUND, "not found");
    }
    let db = s.db.clone();
    match tokio::task::spawn_blocking(move || db.status_of(&receipt)).await {
        Ok(Ok(Some(status))) => Json(json!({ "status": status })).into_response(),
        Ok(Ok(None)) => err(StatusCode::NOT_FOUND, "not found"),
        _ => err(StatusCode::INTERNAL_SERVER_ERROR, "lookup failed"),
    }
}

/// One maintenance pass: retention, then compaction.
pub fn maintain(s: &AppState) -> Result<usize> {
    let cutoff = now_unix().saturating_sub(s.cfg.retention.as_secs());
    let purged = s.db.purge_before(cutoff)?;
    if purged > 0 {
        s.db.compact()?;
    }
    Ok(purged)
}

/// Hourly retention job.
pub fn spawn_maintenance(s: Arc<AppState>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(HOUR);
        loop {
            tick.tick().await;
            let st = s.clone();
            match tokio::task::spawn_blocking(move || maintain(&st)).await {
                Ok(Ok(n)) if n > 0 => tracing::info!(purged = n, "retention purge"),
                Ok(Err(e)) => tracing::error!(error = %e, "retention purge failed"),
                _ => {}
            }
        }
    });
}
