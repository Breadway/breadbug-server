//! The BOS Settings feedback contract: the documented fixtures are valid,
//! the documented flows work end to end, and responses carry the documented
//! keys. See `docs/feedback-api.md`.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use breadbug_server::app::{public_router, AppState};
use breadbug_server::config::Config;
use breadbug_server::crypto::sha256_hex;
use breadbug_server::db::Db;
use breadbug_server::schema::Report;
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

const MANUAL: &str = include_str!("fixtures/manual_report.json");
const REQUEST: &str = include_str!("fixtures/feature_request.json");
const INSTALL: &str = "0123456789abcdef0123456789abcdef";

struct Harness {
    state: Arc<AppState>,
    _dir: tempfile::TempDir,
}

fn harness() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config {
        data_dir: dir.path().to_path_buf(),
        per_install_per_hour: 1000,
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

#[test]
fn documented_fixtures_parse_against_the_schema() {
    for (name, text) in [("manual", MANUAL), ("request", REQUEST)] {
        let v: Value = serde_json::from_str(text).unwrap();
        let report = Report::parse(text.as_bytes(), 2000).unwrap();
        assert_eq!(report.app.id, "bar", "{name}");
        assert!(
            report.title.as_deref().is_some_and(|t| !t.is_empty()),
            "{name}"
        );
        let _ = v;
    }
}

#[tokio::test]
async fn documented_submit_follow_status_flow() {
    let h = harness();
    // Submit the documented fixtures exactly as a client would send them.
    for text in [MANUAL, REQUEST] {
        let (status, body) = call(&h, post(text.as_bytes())).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let receipt = body["receipt"].as_str().unwrap().to_string();
        assert!(body["deletion_token"].is_string());

        // Follow the issue behind the report.
        let (status, followed) = call(
            &h,
            Request::builder()
                .method("POST")
                .uri(format!("/v1/reports/{receipt}/follow"))
                .header("x-breadbug-install", INSTALL)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{followed}");
        let token = followed["follow_token"].as_str().unwrap().to_string();

        // Status carries the documented keys and nothing internal.
        let (status, st) = call(
            &h,
            Request::builder()
                .uri(format!("/v1/reports/{receipt}/status"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(st["status"].is_string(), "{st}");
        assert!(st.get("progress").is_none(), "unpromoted: {st}");
        assert!(st.get("releases").is_none(), "untracked: {st}");
        for forbidden in ["install", "token", "issue_key", "cluster"] {
            assert!(!st.to_string().contains(forbidden), "{st}");
        }

        // Notices start empty and keep the documented shape.
        let (status, notices) = call(
            &h,
            Request::builder()
                .uri(format!("/v1/follows/{token}/notifications"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(notices, serde_json::json!({"notices": []}));
    }
}

#[tokio::test]
async fn documented_validation_rules_hold() {
    let h = harness();
    // Manual without a title, request without a why, want on a manual.
    for body in [
        serde_json::json!({"schema": 1, "report_type": "manual", "created_unix": 1,
            "app": {"id": "bar"}, "notes": "no title"}),
        serde_json::json!({"schema": 1, "report_type": "request", "created_unix": 1,
            "app": {"id": "bar"}, "title": "t", "want": "w", "notes": "  "}),
        serde_json::json!({"schema": 1, "report_type": "manual", "created_unix": 1,
            "app": {"id": "bar"}, "title": "t", "notes": "d", "want": "w"}),
    ] {
        let bytes = serde_json::to_vec(&body).unwrap();
        let (status, _) = call(&h, post(&bytes)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    }
    assert_eq!(h.state.db.report_count().unwrap(), 0);
}
