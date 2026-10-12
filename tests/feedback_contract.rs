//! The BOS Settings feedback contract: the documented fixtures are valid,
//! the documented flows work end to end, and responses carry the documented
//! keys and shape. See `docs/feedback-api.md`.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use breadbug_server::admin::admin_router;
use breadbug_server::app::{public_router, AppState};
use breadbug_server::config::Config;
use breadbug_server::crypto::sha256_hex;
use breadbug_server::db::Db;
use breadbug_server::schema::Report;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

const MANUAL: &str = include_str!("fixtures/manual_report.json");
const REQUEST: &str = include_str!("fixtures/feature_request.json");
const FOLLOW: &str = include_str!("fixtures/feedback_follow.json");
const STATUS: &str = include_str!("fixtures/feedback_status.json");
const NOTIFICATIONS: &str = include_str!("fixtures/feedback_notifications.json");
const INSTALL: &str = "0123456789abcdef0123456789abcdef";
const TOKEN: &str = "correct horse battery staple admin token";

/// The documented progress stages and notification events. Kept in the test so
/// the fixtures and the docs cannot drift from the contract.
const PROGRESS: &[&str] = &[
    "accepted",
    "in_development",
    "fixed",
    "targeting_release",
    "completed",
    "declined",
    "deferred",
];
const EVENTS: &[&str] = &["fixed", "beta", "stable"];

struct Harness {
    state: Arc<AppState>,
    _dir: tempfile::TempDir,
}

fn harness() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config {
        data_dir: dir.path().to_path_buf(),
        admin_token_sha256: Some(sha256_hex(TOKEN.as_bytes())),
        per_install_per_hour: 1000,
        per_network_per_hour: 1000,
        ..Config::default()
    };
    Harness {
        state: AppState::new(cfg, Db::open_memory().unwrap(), vec![3u8; 32]),
        _dir: dir,
    }
}

async fn call(h: &Harness, req: Request<Body>) -> (StatusCode, Value) {
    let resp = public_router(h.state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn post(body: &[u8]) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/v1/reports")
        .header("x-breadbug-install", INSTALL)
        .header("x-breadbug-sha256", sha256_hex(body))
        .body(Body::from(body.to_vec()))
        .unwrap()
}

async fn submit(h: &Harness, body: &str) -> String {
    let (status, resp) = call(h, post(body.as_bytes())).await;
    assert_eq!(status, StatusCode::CREATED, "{resp}");
    resp["receipt"].as_str().unwrap().to_string()
}

async fn follow(h: &Harness, receipt: &str) -> String {
    let (status, resp) = call(
        h,
        Request::builder()
            .method("POST")
            .uri(format!("/v1/reports/{receipt}/follow"))
            .header("x-breadbug-install", INSTALL)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{resp}");
    assert_follow_response(&resp);
    resp["follow_token"].as_str().unwrap().to_string()
}

async fn status_of(h: &Harness, receipt: &str) -> Value {
    let (status, v) = call(
        h,
        Request::builder()
            .uri(format!("/v1/reports/{receipt}/status"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_status_response(&v);
    v
}

async fn notices(h: &Harness, token: &str) -> Value {
    let (status, v) = call(
        h,
        Request::builder()
            .uri(format!("/v1/follows/{token}/notifications"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_notifications_response(&v);
    v
}

async fn wait(h: &Harness, token: &str) -> Value {
    let (status, v) = call(
        h,
        Request::builder()
            .uri(format!("/v1/follows/{token}/notifications/wait"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_notifications_response(&v);
    v
}

async fn ack(h: &Harness, token: &str, ids: &[i64]) {
    let body = json!({ "ids": ids }).to_string();
    let (status, _) = call(
        h,
        Request::builder()
            .method("POST")
            .uri(format!("/v1/follows/{token}/notifications/ack"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

async fn admin_post(h: &Harness, uri: &str, form: &str) -> StatusCode {
    admin_router(h.state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .body(Body::from(form.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

// --- shape validators, one per documented response ---

fn assert_follow_response(v: &Value) {
    assert_eq!(v["status"], json!("following"));
    let t = v["follow_token"].as_str().expect("follow_token");
    assert_eq!(t.len(), 64, "{t}");
    assert!(t.bytes().all(|b| b.is_ascii_hexdigit()), "{t}");
}

fn assert_status_response(v: &Value) {
    let s = v["status"].as_str().expect("status");
    assert!(
        ["received", "duplicate", "investigating", "fixed", "closed"].contains(&s),
        "{s}"
    );
    if let Some(p) = v.get("progress") {
        let p = p.as_str().unwrap();
        assert!(PROGRESS.contains(&p), "unknown progress {p}");
    }
    if let Some(r) = v.get("releases") {
        for ch in ["beta", "stable"] {
            let c = &r[ch];
            assert!(c["planned"].is_null() || c["planned"].is_string());
            assert!(c["shipped"].is_boolean());
            if c["shipped"] == json!(true) {
                assert!(c["shipped_in"].is_string(), "{c}");
            }
        }
    }
}

fn assert_notifications_response(v: &Value) {
    let list = v["notices"].as_array().expect("notices array");
    for n in list {
        assert!(n["id"].is_i64(), "{n}");
        let e = n["event"].as_str().unwrap();
        assert!(EVENTS.contains(&e), "unknown event {e}");
        assert!(n["text"].as_str().is_some_and(|t| !t.is_empty()), "{n}");
        assert!(n["at"].is_number(), "{n}");
    }
}

#[test]
fn documented_fixtures_parse_against_the_schema() {
    for (name, text) in [("manual", MANUAL), ("request", REQUEST)] {
        let report = Report::parse(text.as_bytes(), 2000).unwrap();
        assert_eq!(report.app.id, "bar", "{name}");
        assert!(
            report.title.as_deref().is_some_and(|t| !t.is_empty()),
            "{name}"
        );
    }
}

#[test]
fn documented_response_fixtures_match_their_schemas() {
    let follow: Value = serde_json::from_str(FOLLOW).unwrap();
    assert_follow_response(&follow);
    let status: Value = serde_json::from_str(STATUS).unwrap();
    assert_status_response(&status);
    let notices: Value = serde_json::from_str(NOTIFICATIONS).unwrap();
    assert_notifications_response(&notices);
    // The notification fixture exercises the fixed, beta and stable wording.
    let events: Vec<&str> = notices["notices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["event"].as_str().unwrap())
        .collect();
    for e in EVENTS {
        assert!(events.contains(e), "missing {e} in the fixture");
    }
}

#[tokio::test]
async fn documented_submit_follow_status_flow() {
    let h = harness();
    for text in [MANUAL, REQUEST] {
        let (status, body) = call(&h, post(text.as_bytes())).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let receipt = body["receipt"].as_str().unwrap().to_string();
        assert!(body["deletion_token"].is_string());

        let _token = follow(&h, &receipt).await;

        // Status carries the documented keys and nothing internal.
        let st = status_of(&h, &receipt).await;
        assert_eq!(st["status"], json!("received"));
        assert!(st.get("progress").is_none(), "unpromoted: {st}");
        assert!(st.get("releases").is_none(), "untracked: {st}");
        for forbidden in ["install", "token", "issue_key", "cluster"] {
            assert!(!st.to_string().contains(forbidden), "{st}");
        }
    }
}

#[tokio::test]
async fn documented_notice_flow_is_peek_ack_and_wait() {
    let h = harness();
    let receipt = submit(&h, MANUAL).await;
    let id = h.state.db.clusters().unwrap()[0].id;
    let token = follow(&h, &receipt).await;

    assert_eq!(notices(&h, &token).await, json!({"notices": []}));
    assert_eq!(
        admin_post(&h, &format!("/admin/clusters/{id}/fixed"), "version=1.4.0").await,
        StatusCode::SEE_OTHER
    );

    // Peek: one notice with a stable id, not consumed.
    let peek = notices(&h, &token).await;
    assert_eq!(peek["notices"].as_array().unwrap().len(), 1);
    let nid = peek["notices"][0]["id"].as_i64().unwrap();

    // The wait channel returns the pending notice without consuming it.
    assert_eq!(
        wait(&h, &token).await["notices"].as_array().unwrap().len(),
        1
    );
    // Reading again keeps it until it is acked.
    assert_eq!(
        notices(&h, &token).await["notices"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    ack(&h, &token, &[nid]).await;
    assert_eq!(notices(&h, &token).await, json!({"notices": []}));
}

#[tokio::test]
async fn documented_validation_rules_hold() {
    let h = harness();
    // Manual without a title, request without a why, want on a manual, and a
    // diagnostic reference without consent.
    for body in [
        json!({"schema": 1, "report_type": "manual", "created_unix": 1,
            "app": {"id": "bar"}, "notes": "no title"}),
        json!({"schema": 1, "report_type": "request", "created_unix": 1,
            "app": {"id": "bar"}, "title": "t", "want": "w", "notes": "  "}),
        json!({"schema": 1, "report_type": "manual", "created_unix": 1,
            "app": {"id": "bar"}, "title": "t", "notes": "d", "want": "w"}),
        json!({"schema": 1, "report_type": "manual", "created_unix": 1,
            "app": {"id": "bar"}, "title": "t", "notes": "d",
            "diagnostics_reference": "diag/1"}),
    ] {
        let bytes = serde_json::to_vec(&body).unwrap();
        let (status, _) = call(&h, post(&bytes)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    }
    assert_eq!(h.state.db.report_count().unwrap(), 0);
}
