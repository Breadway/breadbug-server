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

use crate::board::{parse_projects, BoardClient};
use crate::cluster::Fuzzy;
use crate::config::Config;
use crate::crypto::{hmac_hex, keyed_u64, random_hex, sha256_hex};
use crate::db::{Db, NewReport};
use crate::embed::{Embedder, HashEmbedder, HttpEmbedder};
use crate::ratelimit::Limiter;
use crate::rescrub::rescrub;
use crate::schema::Report;
use crate::symbolicate::SymbolStore;
use crate::triage::ScoreRules;

const HOUR: Duration = Duration::from_secs(3600);

pub struct AppState {
    pub cfg: Config,
    pub db: Arc<Db>,
    secret: Vec<u8>,
    per_install: Limiter,
    per_network: Limiter,
    global: Limiter,
    in_flight: Arc<Semaphore>,
    symbols: SymbolStore,
    embedder: Box<dyn Embedder>,
    rules: ScoreRules,
    login: Limiter,
    board: Option<BoardClient>,
}

impl AppState {
    pub(crate) fn secret(&self) -> &[u8] {
        &self.secret
    }

    pub(crate) fn login_limiter(&self) -> &Limiter {
        &self.login
    }

    pub fn board(&self) -> Option<&BoardClient> {
        self.board.as_ref()
    }

    pub fn rules(&self) -> &ScoreRules {
        &self.rules
    }

    /// Fuzzy-matching settings for clustering.
    pub fn fuzzy(&self) -> Fuzzy<'_> {
        Fuzzy {
            embedder: self.embedder.as_ref(),
            threshold: self.cfg.fuzzy_threshold,
        }
    }

    pub fn new(cfg: Config, db: Db, secret: Vec<u8>) -> Arc<Self> {
        Arc::new(Self {
            per_install: Limiter::new(cfg.per_install_per_hour, HOUR),
            per_network: Limiter::new(cfg.per_network_per_hour, HOUR),
            global: Limiter::new(cfg.global_per_hour, HOUR),
            in_flight: Arc::new(Semaphore::new(cfg.max_in_flight)),
            symbols: SymbolStore::new(cfg.symbols_path()),
            embedder: make_embedder(&cfg),
            rules: load_rules(&cfg),
            login: Limiter::new(10, Duration::from_secs(600)),
            board: make_board(&cfg),
            cfg,
            db: Arc::new(db),
            secret,
        })
    }
}

fn make_board(cfg: &Config) -> Option<BoardClient> {
    let (url, token) = (cfg.board_url.as_deref()?, cfg.board_token.as_deref()?);
    match BoardClient::new(url, token, parse_projects(&cfg.board_projects)) {
        Ok(b) => Some(b),
        Err(e) => {
            tracing::error!(error = %e, "breadboard promotion disabled");
            None
        }
    }
}

fn load_rules(cfg: &Config) -> ScoreRules {
    match &cfg.triage_rules {
        Some(path) => ScoreRules::load(path).unwrap_or_else(|e| {
            tracing::error!(error = %e, "triage rules unreadable; using defaults");
            ScoreRules::default()
        }),
        None => ScoreRules::default(),
    }
}

fn make_embedder(cfg: &Config) -> Box<dyn Embedder> {
    if let Some(url) = &cfg.embed_url {
        match HttpEmbedder::new(url, &cfg.embed_model) {
            Ok(e) => return Box::new(e),
            Err(e) => {
                tracing::error!(error = %e, "embedding service unusable; using the built-in embedder")
            }
        }
    }
    Box::new(HashEmbedder)
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
        .route("/v1/reports/{receipt}/follow", post(follow_report))
        .route("/v1/follows/{token}", delete(unfollow))
        .route("/v1/follows/{token}/notifications", get(follow_notices))
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
    {
        let db = s.db.clone();
        let hash = install_hash.clone();
        match tokio::task::spawn_blocking(move || db.is_banned(&hash)).await {
            Ok(Ok(true)) => return err(StatusCode::FORBIDDEN, "blocked"),
            Ok(Ok(false)) => {}
            _ => {
                return err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "could not check the request",
                )
            }
        }
    }

    if let Err(e) = Report::parse(&body, now_unix()) {
        return err(StatusCode::BAD_REQUEST, &e);
    }

    let state = s.clone();
    let result =
        tokio::task::spawn_blocking(move || store_report(&state, &body, &install_hash)).await;
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

fn store_report(s: &Arc<AppState>, body: &[u8], install_hash: &str) -> Result<Response> {
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
    let mut raw = serde_json::to_string(&outcome.value)?;

    // From here on, work with the scrubbed form only. Symbolication fills in
    // function names from the release symbol store; the stored copy carries
    // them so the triage view and re-fingerprinting see them.
    let mut report: Report = serde_json::from_value(outcome.value.clone())?;
    let stats = s.symbols.symbolicate(&mut report);
    if stats.resolved > 0 {
        raw = serde_json::to_string(&report)?;
    }
    if !stats.missing_build_ids.is_empty() {
        let ids: Vec<String> = stats.missing_build_ids.into_iter().collect();
        if let Err(e) = s.db.note_missing_symbols(
            &ids,
            &report.app.id,
            report.app.version.as_deref(),
            now_unix(),
        ) {
            tracing::error!(error = %e, "recording missing symbols failed");
        }
    }
    let report = &report;

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
        match crate::cluster::assign(
            &s.db,
            report_id,
            report,
            install_hash,
            Some(&Fuzzy {
                embedder: s.embedder.as_ref(),
                threshold: s.cfg.fuzzy_threshold,
            }),
        ) {
            Ok(Some(cluster_id)) => follow_up(s, cluster_id, report.app.version.clone()),
            Ok(None) => {}
            Err(e) => {
                tracing::error!(error = %e, "clustering failed; the report is stored unclustered")
            }
        }
    }
    Ok((
        StatusCode::CREATED,
        Json(json!({ "receipt": receipt, "deletion_token": token, "status": "received" })),
    )
        .into_response())
}

/// Regression checks and breadboard updates never delay or fail an intake:
/// they run on their own thread (inline only in tests).
fn follow_up(s: &Arc<AppState>, cluster_id: i64, version: Option<String>) {
    let st = Arc::clone(s);
    let run = move || {
        if let Err(e) = crate::lifecycle::after_report(&st, cluster_id, version.as_deref()) {
            tracing::error!(error = %e, "cluster follow-up failed");
        }
    };
    if s.cfg.lifecycle_inline {
        run();
    } else {
        let _ = std::thread::Builder::new()
            .name("lifecycle".into())
            .spawn(run);
    }
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

async fn report_status(
    State(s): State<Arc<AppState>>,
    Path(receipt): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !valid_receipt(&receipt) {
        return err(StatusCode::NOT_FOUND, "not found");
    }
    if let Err(wait) = s
        .per_network
        .check(network_key(&s, &headers), Instant::now())
    {
        return too_many(wait);
    }
    let db = s.db.clone();
    match tokio::task::spawn_blocking(move || db.public_status(&receipt)).await {
        Ok(Ok(Some(st))) => {
            let mut body = json!({ "status": st.status });
            if let Some(v) = st.fixed_in {
                body["fixed_in"] = json!(v);
            }
            if let Some(p) = st.progress {
                body["progress"] = json!(p);
            }
            if let Some(r) = st.releases {
                fn channel(
                    planned: Option<String>,
                    shipped: bool,
                    shipped_in: Option<String>,
                ) -> Value {
                    let mut c = json!({ "planned": planned, "shipped": shipped });
                    if let Some(v) = shipped_in {
                        c["shipped_in"] = json!(v);
                    }
                    c
                }
                body["releases"] = json!({
                    "beta": channel(r.beta.planned, r.beta.shipped, r.beta.shipped_in),
                    "stable": channel(r.stable.planned, r.stable.shipped, r.stable.shipped_in),
                });
            }
            Json(body).into_response()
        }
        Ok(Ok(None)) => err(StatusCode::NOT_FOUND, "not found"),
        _ => err(StatusCode::INTERNAL_SERVER_ERROR, "lookup failed"),
    }
}

/// Follow the cluster behind a report: no account. Two authorized flows:
/// the reporter proves themselves with the report's deletion token in the
/// Authorization header, while any other subscriber proves themselves with
/// their install id. A fresh token is returned either way, replacing an
/// earlier one for the same caller so a lost response can be recovered.
/// Nothing about other followers is revealed.
async fn follow_report(
    State(s): State<Arc<AppState>>,
    Path(receipt): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !valid_receipt(&receipt) {
        return err(StatusCode::NOT_FOUND, "not found");
    }
    if let Err(wait) = s
        .per_network
        .check(network_key(&s, &headers), Instant::now())
    {
        return too_many(wait);
    }
    let reporter_token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(str::to_string);
    let install = headers
        .get("x-breadbug-install")
        .and_then(|v| v.to_str().ok())
        .filter(|v| valid_install_id(v))
        .map(str::to_string);
    if reporter_token.is_none() && install.is_none() {
        return err(
            StatusCode::BAD_REQUEST,
            "provide X-Breadbug-Install or the reporter deletion token",
        );
    }
    let install_hash = match reporter_token.as_deref() {
        Some(tok) => {
            let db = s.db.clone();
            let receipt_c = receipt.clone();
            let token_hash = sha256_hex(tok.as_bytes());
            match tokio::task::spawn_blocking(move || {
                db.deletion_token_matches(&receipt_c, &token_hash)
            })
            .await
            {
                Ok(Ok(true)) => hmac_hex(&s.secret, "reporter", receipt.as_bytes()),
                // A wrong deletion token may still be a plain subscriber.
                Ok(Ok(false)) => match install.as_deref() {
                    Some(inst) => {
                        hmac_hex(&s.secret, "install", inst.to_ascii_lowercase().as_bytes())
                    }
                    None => {
                        return err(
                            StatusCode::FORBIDDEN,
                            "the deletion token does not match this report",
                        )
                    }
                },
                _ => {
                    return err(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "could not check the request",
                    )
                }
            }
        }
        None => {
            let inst = install.as_deref().unwrap_or_default();
            hmac_hex(&s.secret, "install", inst.to_ascii_lowercase().as_bytes())
        }
    };
    {
        let db = s.db.clone();
        let hash = install_hash.clone();
        match tokio::task::spawn_blocking(move || db.is_banned(&hash)).await {
            Ok(Ok(true)) => return err(StatusCode::FORBIDDEN, "blocked"),
            Ok(Ok(false)) => {}
            _ => {
                return err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "could not check the request",
                )
            }
        }
    }
    let db = s.db.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        let cluster = db.cluster_of(&receipt)?;
        let Some(cid) = cluster else {
            // Unknown receipt (404) or a stored report with no group yet
            // (409): tell them apart so clients know a retry may help.
            let known = db.status_of(&receipt)?.is_some();
            return anyhow::Ok(Err(known));
        };
        // Follow the live target when clusters were merged.
        let mut target = cid;
        for _ in 0..16 {
            match db.cluster(target)? {
                Some(c) => match c.merged_into {
                    Some(t) => target = t,
                    None => break,
                },
                None => break,
            }
        }
        let token = random_hex(32);
        let replaced = db.follow(
            target,
            &sha256_hex(token.as_bytes()),
            &install_hash,
            now_unix(),
        )?;
        anyhow::Ok(Ok((replaced, token)))
    })
    .await;
    match outcome {
        // A fresh follow is 201; a retry that rotates the token is 200. Both
        // return a usable token, so a client that lost the first response can
        // recover by retrying.
        Ok(Ok(Ok((replaced, token)))) => (
            if replaced {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            },
            Json(json!({ "follow_token": token, "status": "following" })),
        )
            .into_response(),
        Ok(Ok(Err(true))) => err(StatusCode::CONFLICT, "report is not grouped yet"),
        Ok(Ok(Err(false))) => err(StatusCode::NOT_FOUND, "not found"),
        _ => err(StatusCode::INTERNAL_SERVER_ERROR, "lookup failed"),
    }
}

/// Stop following with a follow token. Unknown tokens are 404, same as an
/// unknown receipt, so tokens cannot be probed for anything but validity.
async fn unfollow(
    State(s): State<Arc<AppState>>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> Response {
    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
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
    match tokio::task::spawn_blocking(move || db.unfollow(&token_hash)).await {
        Ok(Ok(true)) => StatusCode::NO_CONTENT.into_response(),
        Ok(Ok(false)) => err(StatusCode::NOT_FOUND, "not found"),
        _ => err(StatusCode::INTERNAL_SERVER_ERROR, "lookup failed"),
    }
}

/// Read a follow's pending notifications. Drain on read: notices are
/// returned once and marked delivered, so a retry never delivers a
/// duplicate. Unknown tokens are 404, like unfollow. Clients should check
/// the report status first and only fetch here when progress or releases
/// changed, rather than polling on a timer.
async fn follow_notices(
    State(s): State<Arc<AppState>>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> Response {
    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
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
    match tokio::task::spawn_blocking(move || {
        if !db.has_follow(&token_hash)? {
            return anyhow::Ok(None);
        }
        Ok(Some(db.take_notices(&token_hash)?))
    })
    .await
    {
        Ok(Ok(Some(notices))) => {
            let list: Vec<Value> = notices
                .into_iter()
                .map(|n| json!({ "event": n.event, "text": n.text, "at": n.created_at }))
                .collect();
            Json(json!({ "notices": list })).into_response()
        }
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
    match crate::lifecycle::sync_issue_states(s) {
        Ok(n) if n > 0 => tracing::info!(fixed = n, "clusters marked fixed from breadboard"),
        Ok(_) => {}
        Err(e) => tracing::error!(error = %e, "breadboard sync failed"),
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
