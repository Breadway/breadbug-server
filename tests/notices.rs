use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use breadbug_server::admin::admin_router;
use breadbug_server::app::{public_router, AppState};
use breadbug_server::config::Config;
use breadbug_server::crypto::sha256_hex;
use breadbug_server::db::Db;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

const TOKEN: &str = "correct horse battery staple admin token";
const INSTALL_A: &str = "0123456789abcdef0123456789abcdef";
const INSTALL_B: &str = "fedcba9876543210fedcba9876543210";

struct H {
    st: Arc<AppState>,
    _d: tempfile::TempDir,
}

fn harness() -> H {
    let d = tempfile::tempdir().unwrap();
    let cfg = Config {
        data_dir: d.path().to_path_buf(),
        admin_token_sha256: Some(sha256_hex(TOKEN.as_bytes())),
        per_install_per_hour: 1000,
        per_network_per_hour: 1000,
        ..Config::default()
    };
    H {
        st: AppState::new(cfg, Db::open_memory().unwrap(), vec![9u8; 32]),
        _d: d,
    }
}

fn crash() -> Value {
    json!({
        "schema": 1, "report_type": "crash", "created_unix": 1,
        "app": {"id": "bar", "version": "1.3.0"},
        "markers": [{"t": 1, "kind": "panic", "message": "boom",
                     "frames": [{"symbol": "bar::run"}, {"symbol": "bar::main"}]}],
    })
}

async fn public(h: &H, req: Request<Body>) -> (StatusCode, Value) {
    let resp = public_router(h.st.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let b = resp.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&b).unwrap_or(Value::Null))
}

async fn submit(h: &H, install: &str) -> String {
    let body = serde_json::to_vec(&crash()).unwrap();
    let (status, resp) = public(
        h,
        Request::builder()
            .method("POST")
            .uri("/v1/reports")
            .header("x-breadbug-install", install)
            .header("x-breadbug-sha256", sha256_hex(&body))
            .body(Body::from(body))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{resp}");
    resp["receipt"].as_str().unwrap().to_string()
}

async fn follow(h: &H, receipt: &str, install: &str) -> String {
    let (status, resp) = public(
        h,
        Request::builder()
            .method("POST")
            .uri(format!("/v1/reports/{receipt}/follow"))
            .header("x-breadbug-install", install)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{resp}");
    resp["follow_token"].as_str().unwrap().to_string()
}

async fn notices(h: &H, token: &str) -> (StatusCode, Value) {
    public(
        h,
        Request::builder()
            .uri(format!("/v1/follows/{token}/notifications"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
}

async fn ack(h: &H, token: &str, ids: &[i64]) -> StatusCode {
    let body = json!({ "ids": ids }).to_string();
    public(
        h,
        Request::builder()
            .method("POST")
            .uri(format!("/v1/follows/{token}/notifications/ack"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap(),
    )
    .await
    .0
}

async fn wait(h: &H, token: &str) -> (StatusCode, Value) {
    public(
        h,
        Request::builder()
            .uri(format!("/v1/follows/{token}/notifications/wait"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
}

async fn admin_post(h: &H, uri: &str, form: &str) -> StatusCode {
    admin_router(h.st.clone())
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

fn ids_of(v: &Value) -> Vec<i64> {
    v["notices"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|n| n["id"].as_i64())
        .collect()
}

#[tokio::test]
async fn notices_are_peeked_and_acked_and_each_transition_notifies_once() {
    let h = harness();
    let receipt = submit(&h, INSTALL_A).await;
    let id = h.st.db.clusters().unwrap()[0].id;
    let token_a = follow(&h, &receipt, INSTALL_A).await;
    let token_b = follow(&h, &receipt, INSTALL_B).await;

    // Nothing happened yet: empty list.
    assert_eq!(notices(&h, &token_a).await.1, json!({"notices": []}));

    // Mark fixed: one notice, with app, version and a stable id.
    assert_eq!(
        admin_post(&h, &format!("/admin/clusters/{id}/fixed"), "version=1.3.1").await,
        StatusCode::SEE_OTHER
    );
    let (status, first) = notices(&h, &token_a).await;
    assert_eq!(status, StatusCode::OK);
    let list = first["notices"].as_array().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["event"], json!("fixed"));
    assert!(list[0]["id"].is_number());
    assert_eq!(
        list[0]["text"],
        json!("A bug you follow in bar has been fixed in 1.3.1. Thanks for helping us improve it!")
    );
    let nid = list[0]["id"].as_i64().unwrap();

    // Reading without acking keeps the notice: a lost response does not lose
    // it, and the id is stable.
    let again = notices(&h, &token_a).await.1;
    assert_eq!(ids_of(&again), vec![nid]);

    // Ack it: now it is gone.
    assert_eq!(ack(&h, &token_a, &[nid]).await, StatusCode::OK);
    assert_eq!(notices(&h, &token_a).await.1, json!({"notices": []}));

    // Repeating the identical transition does not create a new notice.
    assert_eq!(
        admin_post(&h, &format!("/admin/clusters/{id}/fixed"), "version=1.3.1").await,
        StatusCode::SEE_OTHER
    );
    assert_eq!(notices(&h, &token_a).await.1, json!({"notices": []}));

    // A new fix version is new information.
    assert_eq!(
        admin_post(&h, &format!("/admin/clusters/{id}/fixed"), "version=1.3.2").await,
        StatusCode::SEE_OTHER
    );
    let list = notices(&h, &token_a).await.1["notices"]
        .as_array()
        .cloned()
        .unwrap();
    assert_eq!(list.len(), 1);
    assert!(list[0]["text"].as_str().unwrap().contains("1.3.2"));

    // B never read or acked, so both fix versions are pending there.
    let blist = notices(&h, &token_b).await.1["notices"]
        .as_array()
        .cloned()
        .unwrap();
    assert_eq!(blist.len(), 2);
    assert!(blist[0]["text"].as_str().unwrap().contains("1.3.1"));
    assert!(blist[1]["text"].as_str().unwrap().contains("1.3.2"));

    // Clear A's pending fixed notices before the release steps.
    let ids = ids_of(&notices(&h, &token_a).await.1);
    assert_eq!(ack(&h, &token_a, &ids).await, StatusCode::OK);

    // Beta then stable: distinct notices, distinct wording.
    admin_post(
        &h,
        &format!("/admin/clusters/{id}/release-target"),
        "channel=beta&version=1.4-beta1",
    )
    .await;
    assert_eq!(
        admin_post(
            &h,
            &format!("/admin/clusters/{id}/release-confirmed"),
            "channel=beta&version=1.4-beta2"
        )
        .await,
        StatusCode::SEE_OTHER
    );
    let beta = notices(&h, &token_a).await.1;
    assert_eq!(beta["notices"][0]["event"], json!("beta"));
    assert_eq!(
        beta["notices"][0]["text"],
        json!("A bug you follow in bar is available in the 1.4-beta2 beta.")
    );
    let bid = beta["notices"][0]["id"].as_i64().unwrap();
    assert_eq!(ack(&h, &token_a, &[bid]).await, StatusCode::OK);

    admin_post(
        &h,
        &format!("/admin/clusters/{id}/release-target"),
        "channel=stable&version=1.4",
    )
    .await;
    assert_eq!(
        admin_post(
            &h,
            &format!("/admin/clusters/{id}/release-confirmed"),
            "channel=stable&version=1.4"
        )
        .await,
        StatusCode::SEE_OTHER
    );
    let stable = notices(&h, &token_a).await.1;
    assert_eq!(stable["notices"][0]["event"], json!("stable"));
    assert_eq!(
        stable["notices"][0]["text"],
        json!("A bug you follow in bar is available in 1.4 stable.")
    );
}

#[tokio::test]
async fn wait_returns_pending_notices_without_consuming_them() {
    let h = harness();
    let receipt = submit(&h, INSTALL_A).await;
    let id = h.st.db.clusters().unwrap()[0].id;
    let token = follow(&h, &receipt, INSTALL_A).await;
    assert_eq!(
        admin_post(&h, &format!("/admin/clusters/{id}/fixed"), "version=1.3.1").await,
        StatusCode::SEE_OTHER
    );

    let (status, body) = wait(&h, &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["notices"].as_array().unwrap().len(), 1);
    // The wait does not consume: the notice is still pending until acked.
    assert_eq!(
        notices(&h, &token).await.1["notices"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    assert_eq!(wait(&h, "nope").await.0, StatusCode::NOT_FOUND);
    assert_eq!(ack(&h, &"0".repeat(64), &[1]).await, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn unfollowing_stops_future_notices_and_unknown_tokens_are_404() {
    let h = harness();
    let receipt = submit(&h, INSTALL_A).await;
    let id = h.st.db.clusters().unwrap()[0].id;
    let token_a = follow(&h, &receipt, INSTALL_A).await;
    let token_b = follow(&h, &receipt, INSTALL_B).await;

    // B unsubscribes before anything ships.
    let (status, _) = public(
        &h,
        Request::builder()
            .method("DELETE")
            .uri(format!("/v1/follows/{token_b}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    assert_eq!(
        admin_post(&h, &format!("/admin/clusters/{id}/fixed"), "version=1.3.1").await,
        StatusCode::SEE_OTHER
    );
    // A still gets the notice; B's token is dead and nothing is queued for it.
    assert_eq!(
        notices(&h, &token_a).await.1["notices"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(notices(&h, &token_b).await.0, StatusCode::NOT_FOUND);
    assert_eq!(notices(&h, "nope").await.0, StatusCode::NOT_FOUND);
}
