use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use breadbug_server::app::{public_router, AppState};
use breadbug_server::config::Config;
use breadbug_server::crypto::sha256_hex;
use breadbug_server::db::Db;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

const FIXTURE: &str = include_str!("fixtures/report_v1.json");
const INSTALL_A: &str = "0123456789abcdef0123456789abcdef";
const INSTALL_B: &str = "fedcba9876543210fedcba9876543210";

struct Harness {
    state: Arc<AppState>,
    _dir: tempfile::TempDir,
}

fn harness(edit: impl FnOnce(&mut Config)) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config {
        data_dir: dir.path().to_path_buf(),
        ..Config::default()
    };
    edit(&mut cfg);
    let state = AppState::new(cfg, Db::open_memory().unwrap(), vec![7u8; 32]);
    Harness { state, _dir: dir }
}

async fn call(h: &Harness, req: Request<Body>) -> (StatusCode, Value) {
    let resp = public_router(h.state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

fn post_report(body: &[u8], install: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/v1/reports")
        .header("x-breadbug-install", install)
        .header("x-breadbug-sha256", sha256_hex(body))
        .body(Body::from(body.to_vec()))
        .unwrap()
}

fn with_notes(notes: &str) -> Vec<u8> {
    let mut v: Value = serde_json::from_str(FIXTURE).unwrap();
    v["notes"] = json!(notes);
    serde_json::to_vec(&v).unwrap()
}

fn follow(receipt: &str, install: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(format!("/v1/reports/{receipt}/follow"));
    if let Some(i) = install {
        b = b.header("x-breadbug-install", i);
    }
    b.body(Body::empty()).unwrap()
}

fn unfollow(token: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(format!("/v1/follows/{token}"))
        .body(Body::empty())
        .unwrap()
}

async fn submit(h: &Harness, install: &str, body: &[u8]) -> String {
    let (status, resp) = call(h, post_report(body, install)).await;
    assert_eq!(status, StatusCode::CREATED, "{resp}");
    resp["receipt"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn follow_returns_a_token_and_a_retry_rotates_it() {
    let h = harness(|_| {});
    let receipt = submit(&h, INSTALL_A, &with_notes("follow this problem")).await;
    let (status, body) = call(&h, follow(&receipt, Some(INSTALL_A))).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let token = body["follow_token"].as_str().unwrap().to_string();
    assert_eq!(token.len(), 64);
    // The response carries no install identity and no deletion token.
    assert!(!body.to_string().contains(INSTALL_A));
    assert!(body.get("deletion_token").is_none());

    let cluster = h.state.db.cluster_of(&receipt).unwrap().unwrap();
    assert_eq!(h.state.db.follow_count(cluster).unwrap(), 1);

    let (status, again) = call(&h, follow(&receipt, Some(INSTALL_A))).await;
    assert_eq!(status, StatusCode::OK);
    // The retry rotates the capability and returns a usable token, so a
    // client that lost the first response can recover.
    let token2 = again["follow_token"].as_str().unwrap().to_string();
    assert_eq!(token2.len(), 64);
    assert_ne!(token2, token);
    assert_eq!(h.state.db.follow_count(cluster).unwrap(), 1);
    assert_eq!(call(&h, unfollow(&token)).await.0, StatusCode::NOT_FOUND);
    assert_eq!(call(&h, unfollow(&token2)).await.0, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn other_installs_can_follow_the_same_issue() {
    let h = harness(|_| {});
    let receipt = submit(&h, INSTALL_A, &with_notes("shared problem here")).await;
    let (s1, _) = call(&h, follow(&receipt, Some(INSTALL_A))).await;
    let (s2, b2) = call(&h, follow(&receipt, Some(INSTALL_B))).await;
    assert_eq!((s1, s2), (StatusCode::CREATED, StatusCode::CREATED));
    assert!(b2["follow_token"].is_string());
    let cluster = h.state.db.cluster_of(&receipt).unwrap().unwrap();
    assert_eq!(h.state.db.follow_count(cluster).unwrap(), 2);
}

#[tokio::test]
async fn unfollow_stops_and_unknown_tokens_are_404() {
    let h = harness(|_| {});
    let receipt = submit(&h, INSTALL_A, &with_notes("unfollow test note")).await;
    let (_, body) = call(&h, follow(&receipt, Some(INSTALL_A))).await;
    let token = body["follow_token"].as_str().unwrap().to_string();
    let cluster = h.state.db.cluster_of(&receipt).unwrap().unwrap();

    // A near-miss token is not accepted.
    let mut bad = token.clone();
    bad.replace_range(..1, if &token[..1] == "a" { "b" } else { "a" });
    assert_eq!(call(&h, unfollow(&bad)).await.0, StatusCode::NOT_FOUND);
    assert_eq!(
        call(&h, unfollow(&"0".repeat(64))).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(call(&h, unfollow("nope")).await.0, StatusCode::NOT_FOUND);

    assert_eq!(call(&h, unfollow(&token)).await.0, StatusCode::NO_CONTENT);
    assert_eq!(h.state.db.follow_count(cluster).unwrap(), 0);
    assert_eq!(call(&h, unfollow(&token)).await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn unknown_receipts_are_404_and_ungrouped_reports_are_409() {
    let h = harness(|_| {});
    assert_eq!(
        call(&h, follow(&"0".repeat(32), Some(INSTALL_A))).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(&h, follow("nope", Some(INSTALL_A))).await.0,
        StatusCode::NOT_FOUND
    );

    // A quarantined report is stored but grouped nowhere: 409, not 404.
    let mut v: Value = serde_json::from_str(FIXTURE).unwrap();
    v["notes"] = json!("mail leak@example.org");
    let leaked = serde_json::to_vec(&v).unwrap();
    let (_, body) = call(&h, post_report(&leaked, INSTALL_A)).await;
    let receipt = body["receipt"].as_str().unwrap();
    assert_eq!(
        call(&h, follow(receipt, Some(INSTALL_A))).await.0,
        StatusCode::CONFLICT
    );

    // Missing install header is a 400 even for a followable receipt.
    let receipt = submit(&h, INSTALL_A, &with_notes("needs an install header")).await;
    assert_eq!(
        call(&h, follow(&receipt, None)).await.0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn banned_installs_cannot_follow() {
    let h = harness(|_| {});
    let receipt = submit(&h, INSTALL_A, &with_notes("ban test note")).await;
    let id: i64 = h
        .state
        .db
        .report_id_for_test(&receipt)
        .unwrap()
        .expect("report stored");
    h.state.db.ban_install_of_report(id, "spam", 2).unwrap();
    assert_eq!(
        call(&h, follow(&receipt, Some(INSTALL_A))).await.0,
        StatusCode::FORBIDDEN
    );
    // Another install is unaffected.
    assert_eq!(
        call(&h, follow(&receipt, Some(INSTALL_B))).await.0,
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn merging_clusters_folds_follows_into_the_target() {
    let h = harness(|c| c.per_install_per_hour = 100);
    let mut v: Value = serde_json::from_str(FIXTURE).unwrap();
    v["markers"][0]["message"] = json!("first problem");
    let first = serde_json::to_vec(&v).unwrap();
    v["markers"][0]["message"] = json!("second problem");
    v["markers"][0]["frames"] = json!([{"symbol": "other::thing::h4444444444444444"}]);
    let second = serde_json::to_vec(&v).unwrap();
    let r1 = submit(&h, INSTALL_A, &first).await;
    let r2 = submit(&h, INSTALL_B, &second).await;
    let c1 = h.state.db.cluster_of(&r1).unwrap().unwrap();
    let c2 = h.state.db.cluster_of(&r2).unwrap().unwrap();
    assert_ne!(c1, c2);

    // Both installs follow both clusters: 2 follows each.
    let (_, b1) = call(&h, follow(&r1, Some(INSTALL_A))).await;
    let alias_a = b1["follow_token"].as_str().unwrap().to_string();
    let (_, b2) = call(&h, follow(&r2, Some(INSTALL_A))).await;
    let survivor = b2["follow_token"].as_str().unwrap().to_string();
    call(&h, follow(&r1, Some(INSTALL_B))).await;
    call(&h, follow(&r2, Some(INSTALL_B))).await;
    assert_eq!(h.state.db.follow_count(c1).unwrap(), 2);
    assert_eq!(h.state.db.follow_count(c2).unwrap(), 2);

    assert!(h.state.db.merge_clusters(c1, c2).unwrap());
    // Distinct installs fold: the target reports 2 installs, not 4, and the
    // source is empty.
    assert_eq!(h.state.db.follow_count(c2).unwrap(), 2);
    assert_eq!(h.state.db.follow_count(c1).unwrap(), 0);
    // Install A followed both clusters, so both of its capability tokens stay
    // valid as aliases on the target instead of one silently dying.
    assert_eq!(call(&h, unfollow(&alias_a)).await.0, StatusCode::NO_CONTENT);
    assert_eq!(h.state.db.follow_count(c2).unwrap(), 2);
    assert_eq!(
        call(&h, unfollow(&survivor)).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(h.state.db.follow_count(c2).unwrap(), 1);
    // Following through the merged-away receipt now acts on the target.
    let (status, again) = call(&h, follow(&r1, Some(INSTALL_A))).await;
    assert!(
        status == StatusCode::CREATED || status == StatusCode::OK,
        "{status}"
    );
    assert!(again["follow_token"].is_string());
}

#[tokio::test]
async fn reporter_follows_with_the_deletion_token() {
    let h = harness(|_| {});
    let body = with_notes("reporter follow note");
    let (_, resp) = call(&h, post_report(&body, INSTALL_A)).await;
    let receipt = resp["receipt"].as_str().unwrap().to_string();
    let deletion = resp["deletion_token"].as_str().unwrap().to_string();

    // No install header: the deletion token authenticates the reporter.
    let reporter = |token: &str| {
        Request::builder()
            .method("POST")
            .uri(format!("/v1/reports/{receipt}/follow"))
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    };
    let (status, b) = call(&h, reporter(&deletion)).await;
    assert_eq!(status, StatusCode::CREATED, "{b}");
    assert!(b["follow_token"].is_string());
    let cluster = h.state.db.cluster_of(&receipt).unwrap().unwrap();
    assert_eq!(h.state.db.follow_count(cluster).unwrap(), 1);

    // A wrong deletion token with no install is refused, not treated as a
    // non-reporter follow.
    assert_eq!(
        call(&h, reporter(&"0".repeat(64))).await.0,
        StatusCode::FORBIDDEN
    );
    // A wrong deletion token plus a valid install falls back to the install
    // flow (a separate subscriber), which is allowed.
    let req = Request::builder()
        .method("POST")
        .uri(format!("/v1/reports/{receipt}/follow"))
        .header("authorization", format!("Bearer {}", "0".repeat(64)))
        .header("x-breadbug-install", INSTALL_B)
        .body(Body::empty())
        .unwrap();
    assert_eq!(call(&h, req).await.0, StatusCode::CREATED);
    assert_eq!(h.state.db.follow_count(cluster).unwrap(), 2);
}

#[tokio::test]
async fn a_lost_follow_response_can_be_recovered() {
    let h = harness(|_| {});
    let receipt = submit(&h, INSTALL_A, &with_notes("lost response note")).await;
    // First follow, whose response is (say) lost before the client sees it.
    let (_, _first) = call(&h, follow(&receipt, Some(INSTALL_A))).await;
    // Retry: a usable token comes back.
    let (status, retry) = call(&h, follow(&receipt, Some(INSTALL_A))).await;
    assert_eq!(status, StatusCode::OK);
    let token = retry["follow_token"].as_str().unwrap().to_string();
    assert_eq!(call(&h, unfollow(&token)).await.0, StatusCode::NO_CONTENT);
}
