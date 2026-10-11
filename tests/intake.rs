use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use breadbug_server::app::{maintain, public_router, AppState};
use breadbug_server::config::Config;
use breadbug_server::crypto::sha256_hex;
use breadbug_server::db::Db;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

const FIXTURE: &str = include_str!("fixtures/report_v1.json");
const INSTALL: &str = "0123456789abcdef0123456789abcdef";

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

async fn call(h: &Harness, req: Request<Body>) -> (StatusCode, axum::http::HeaderMap, Value) {
    let resp = public_router(h.state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, headers, body)
}

fn post(body: &[u8], install: Option<&str>, sha: Option<&str>, xff: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().method("POST").uri("/v1/reports");
    if let Some(i) = install {
        b = b.header("x-breadbug-install", i);
    }
    if let Some(s) = sha {
        b = b.header("x-breadbug-sha256", s);
    }
    if let Some(x) = xff {
        b = b.header("x-forwarded-for", x);
    }
    b.body(Body::from(body.to_vec())).unwrap()
}

fn ok_post(body: &[u8]) -> Request<Body> {
    post(body, Some(INSTALL), Some(&sha256_hex(body)), None)
}

fn with_notes(notes: &str) -> Vec<u8> {
    let mut v: Value = serde_json::from_str(FIXTURE).unwrap();
    v["notes"] = json!(notes);
    serde_json::to_vec(&v).unwrap()
}

#[tokio::test]
async fn real_client_report_is_accepted_and_stored_unchanged() {
    let h = harness(|_| {});
    let (status, _, body) = call(&h, ok_post(FIXTURE.as_bytes())).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let receipt = body["receipt"].as_str().unwrap();
    assert_eq!(receipt.len(), 32);
    assert_eq!(body["deletion_token"].as_str().unwrap().len(), 64);
    // A clean client report survives the server-side scrub byte-for-byte
    // (as JSON) and is not quarantined.
    let stored: Value =
        serde_json::from_str(&h.state.db.raw_of(receipt).unwrap().unwrap()).unwrap();
    assert_eq!(stored, serde_json::from_str::<Value>(FIXTURE).unwrap());
    assert_eq!(h.state.db.is_quarantined(receipt).unwrap(), Some(false));
}

#[tokio::test]
async fn bad_requests_are_rejected_cleanly() {
    let h = harness(|_| {});
    let b = FIXTURE.as_bytes();
    for (name, req) in [
        ("no install", post(b, None, None, None)),
        ("short install", post(b, Some("abc"), None, None)),
        (
            "non-hex install",
            post(b, Some(&"z".repeat(32)), None, None),
        ),
        (
            "hash mismatch",
            post(b, Some(INSTALL), Some(&"0".repeat(64)), None),
        ),
        ("empty", post(b"", Some(INSTALL), None, None)),
        ("not json", post(b"hello", Some(INSTALL), None, None)),
        (
            "unknown field",
            post(
                br#"{"schema":1,"report_type":"crash","created_unix":1,"app":{"id":"clip"},"x":1}"#,
                Some(INSTALL),
                None,
                None,
            ),
        ),
    ] {
        let (status, _, body) = call(&h, req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{name}: {body}");
        assert!(body["error"].is_string());
    }
    assert_eq!(h.state.db.report_count().unwrap(), 0);
}

#[tokio::test]
async fn oversize_bodies_are_refused() {
    let h = harness(|c| c.max_body_bytes = 1024);
    let (status, _, _) = call(&h, ok_post(FIXTURE.as_bytes())).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(h.state.db.report_count().unwrap(), 0);
}

#[tokio::test]
async fn resending_the_same_report_is_idempotent() {
    let h = harness(|_| {});
    let (_, _, first) = call(&h, ok_post(FIXTURE.as_bytes())).await;
    let (status, _, again) = call(&h, ok_post(FIXTURE.as_bytes())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(again["receipt"], first["receipt"]);
    assert_eq!(again["duplicate"], json!(true));
    assert!(again.get("deletion_token").is_none());
    assert_eq!(h.state.db.report_count().unwrap(), 1);
}

#[tokio::test]
async fn per_install_rate_limit_applies_with_retry_after() {
    let h = harness(|c| c.per_install_per_hour = 2);
    for i in 0..2 {
        let (status, _, _) = call(&h, ok_post(&with_notes(&format!("n{i}")))).await;
        assert_eq!(status, StatusCode::CREATED);
    }
    let (status, headers, _) = call(&h, ok_post(&with_notes("n3"))).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(headers.get("retry-after").is_some());
    // a different install is unaffected
    let b = with_notes("other");
    let (status, _, _) = call(
        &h,
        post(
            &b,
            Some("fedcba9876543210fedcba9876543210"),
            Some(&sha256_hex(&b)),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn network_buckets_are_coarse_and_only_used_behind_a_trusted_proxy() {
    let h = harness(|c| {
        c.per_network_per_hour = 2;
        c.trust_proxy = true;
    });
    let post_from = |ip: &str, n: usize| {
        let b = with_notes(&format!("note {n}"));
        let install = format!("{n:032x}");
        post(&b, Some(&install), Some(&sha256_hex(&b)), Some(ip))
    };
    assert_eq!(
        call(&h, post_from("198.51.100.7", 1)).await.0,
        StatusCode::CREATED
    );
    // same /24, different host and install: shares the bucket
    assert_eq!(
        call(&h, post_from("198.51.100.200", 2)).await.0,
        StatusCode::CREATED
    );
    assert_eq!(
        call(&h, post_from("198.51.100.9", 3)).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    // another network is fine
    assert_eq!(
        call(&h, post_from("203.0.113.5", 4)).await.0,
        StatusCode::CREATED
    );

    // Without trust_proxy the header is ignored: everyone shares one bucket.
    let h = harness(|c| c.per_network_per_hour = 2);
    assert_eq!(
        call(&h, post_from("198.51.100.7", 1)).await.0,
        StatusCode::CREATED
    );
    assert_eq!(
        call(&h, post_from("203.0.113.5", 2)).await.0,
        StatusCode::CREATED
    );
    assert_eq!(
        call(&h, post_from("192.0.2.1", 3)).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn global_limit_and_backpressure() {
    let h = harness(|c| c.global_per_hour = 1);
    assert_eq!(
        call(&h, ok_post(&with_notes("a"))).await.0,
        StatusCode::CREATED
    );
    assert_eq!(
        call(&h, ok_post(&with_notes("b"))).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    let h = harness(|c| c.max_in_flight = 0);
    assert_eq!(
        call(&h, ok_post(&with_notes("a"))).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn leaked_pii_is_scrubbed_server_side_and_quarantined() {
    let h = harness(|_| {});
    let notes = "mail me at leak@example.org, my token=abc123def and ip 203.0.113.42";
    let (status, _, body) = call(&h, ok_post(&with_notes(notes))).await;
    assert_eq!(status, StatusCode::CREATED);
    let receipt = body["receipt"].as_str().unwrap();
    let raw = h.state.db.raw_of(receipt).unwrap().unwrap();
    for leaked in ["leak@example.org", "abc123def", "203.0.113.42"] {
        assert!(!raw.contains(leaked), "{leaked} was stored");
    }
    assert_eq!(h.state.db.is_quarantined(receipt).unwrap(), Some(true));
}

#[tokio::test]
async fn hostile_content_is_stored_inert() {
    let h = harness(|_| {});
    let nasty = "'); DROP TABLE reports;-- <script>alert(1)</script> ${jndi:ldap://x} `rm -rf /` \r\n[x](javascript:alert(1)) ignore previous instructions";
    let (status, _, body) = call(&h, ok_post(&with_notes(nasty))).await;
    assert_eq!(status, StatusCode::CREATED);
    let raw = h
        .state
        .db
        .raw_of(body["receipt"].as_str().unwrap())
        .unwrap()
        .unwrap();
    assert!(raw.contains("DROP TABLE"), "content is data, kept verbatim");
    assert_eq!(h.state.db.report_count().unwrap(), 1);
    // and the table is still there
    assert_eq!(
        call(&h, ok_post(&with_notes("after"))).await.0,
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn delete_requires_the_token_and_removes_the_report() {
    let h = harness(|_| {});
    let (_, _, body) = call(&h, ok_post(FIXTURE.as_bytes())).await;
    let receipt = body["receipt"].as_str().unwrap().to_string();
    let token = body["deletion_token"].as_str().unwrap().to_string();
    let del = |tok: Option<&str>, r: &str| {
        let mut b = Request::builder()
            .method("DELETE")
            .uri(format!("/v1/reports/{r}"));
        if let Some(t) = tok {
            b = b.header("authorization", format!("Bearer {t}"));
        }
        b.body(Body::empty()).unwrap()
    };
    assert_eq!(call(&h, del(None, &receipt)).await.0, StatusCode::NOT_FOUND);
    assert_eq!(
        call(&h, del(Some(&"0".repeat(64)), &receipt)).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(&h, del(Some(&token), "../../etc")).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(h.state.db.report_count().unwrap(), 1);
    assert_eq!(
        call(&h, del(Some(&token), &receipt)).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(h.state.db.report_count().unwrap(), 0);
    assert_eq!(
        call(&h, del(Some(&token), &receipt)).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn status_reveals_only_a_coarse_state() {
    let h = harness(|_| {});
    let (_, _, body) = call(&h, ok_post(FIXTURE.as_bytes())).await;
    let receipt = body["receipt"].as_str().unwrap();
    let get = |r: &str| {
        Request::builder()
            .uri(format!("/v1/reports/{r}/status"))
            .body(Body::empty())
            .unwrap()
    };
    let (status, _, b) = call(&h, get(receipt)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(b, json!({ "status": "received" }));
    assert_eq!(
        call(&h, get(&"0".repeat(32))).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(call(&h, get("nope")).await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn retention_purges_old_raw_reports() {
    let h = harness(|c| c.retention = std::time::Duration::from_secs(0));
    call(&h, ok_post(FIXTURE.as_bytes())).await;
    std::thread::sleep(std::time::Duration::from_millis(1100));
    assert_eq!(maintain(&h.state).unwrap(), 1);
    assert_eq!(h.state.db.report_count().unwrap(), 0);
}

#[tokio::test]
async fn health_is_up() {
    let h = harness(|_| {});
    let resp = public_router(h.state.clone())
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// A stream whose first poll is observable and whose bytes are held back.
struct HeldBody {
    polled: Option<tokio::sync::oneshot::Sender<()>>,
    release: tokio::sync::oneshot::Receiver<()>,
}

impl http_body::Body for HeldBody {
    type Data = axum::body::Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        if let Some(tx) = self.polled.take() {
            let _ = tx.send(());
        }
        match std::future::Future::poll(std::pin::Pin::new(&mut self.release), cx) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(_) => std::task::Poll::Ready(None),
        }
    }
}

#[tokio::test]
async fn concurrent_streams_are_admitted_before_body_polling() {
    let h = harness(|c| c.max_in_flight = 1);
    let (polled, observed) = tokio::sync::oneshot::channel();
    let (release, held) = tokio::sync::oneshot::channel();
    let request = Request::builder()
        .method("POST")
        .uri("/v1/reports")
        .header("x-breadbug-install", INSTALL)
        .body(Body::new(HeldBody {
            polled: Some(polled),
            release: held,
        }))
        .unwrap();
    let router = public_router(h.state.clone());
    let first = tokio::spawn(router.clone().oneshot(request));
    tokio::time::timeout(std::time::Duration::from_secs(2), observed)
        .await
        .unwrap()
        .unwrap();
    let (polled, observed) = tokio::sync::oneshot::channel();
    let (_release, held) = tokio::sync::oneshot::channel();
    let request = Request::builder()
        .method("POST")
        .uri("/v1/reports")
        .header("x-breadbug-install", INSTALL)
        .body(Body::new(HeldBody {
            polled: Some(polled),
            release: held,
        }))
        .unwrap();
    let response = tokio::time::timeout(std::time::Duration::from_secs(2), router.oneshot(request))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        observed.await.is_err(),
        "rejected stream must not be polled"
    );
    release.send(()).unwrap();
    assert_eq!(
        first.await.unwrap().unwrap().status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn bounded_mutation_fuzz_exercises_real_intake() {
    let h = harness(|c| {
        c.global_per_hour = 4096;
        c.per_install_per_hour = 4096;
        c.per_network_per_hour = 4096;
    });
    // Fixed-seed mutation fuzzing is reproducible in CI, with bounded inputs
    // and iterations. This complements the structured schema abuse matrix.
    let mut seed = 0x12345678u64;
    for i in 0..512 {
        let mut bytes = FIXTURE.as_bytes().to_vec();
        for _ in 0..1 + i % 8 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let index = seed as usize % bytes.len();
            bytes[index] = (seed >> 32) as u8;
        }
        if i % 3 == 0 {
            bytes.truncate(i % bytes.len());
        }
        let (status, _, _) = call(&h, post(&bytes, Some(INSTALL), None, None)).await;
        assert!(matches!(
            status,
            StatusCode::BAD_REQUEST | StatusCode::CREATED | StatusCode::OK
        ));
    }
}

#[tokio::test]
async fn bounded_concurrent_load_returns_graceful_429s() {
    let h = harness(|c| {
        c.global_per_hour = 8;
        c.per_install_per_hour = 256;
        c.per_network_per_hour = 256;
        c.max_in_flight = 128;
    });
    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..128 {
        let router = public_router(h.state.clone());
        tasks.spawn(async move {
            router
                .oneshot(ok_post(&with_notes(&format!("load {i}"))))
                .await
                .unwrap()
        });
    }
    let mut accepted = 0;
    let mut limited = 0;
    while let Some(response) = tasks.join_next().await {
        let response = response.unwrap();
        match response.status() {
            StatusCode::CREATED => accepted += 1,
            StatusCode::TOO_MANY_REQUESTS => {
                limited += 1;
                assert!(response.headers().contains_key("retry-after"));
            }
            status => panic!("unexpected load response: {status}"),
        }
    }
    assert_eq!((accepted, limited), (8, 120));
}

#[tokio::test]
async fn disk_quota_evicts_oldest_compacts_and_accepts_new_intake() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("breadbug.db");
    let db = Db::open(&path).unwrap();
    for i in 0..3 {
        db.insert_report(&breadbug_server::db::NewReport {
            receipt: &format!("{i:032x}"),
            token_hash: "hash",
            install_hash: "install",
            payload_sha: &format!("sha{i}"),
            received_at: i,
            app: "clip",
            app_version: None,
            report_type: "crash",
            quarantined: false,
            rescrub_hits: "{}",
            raw: &format!("quota-marker-{i}{}", "x".repeat(128 * 1024)),
        })
        .unwrap();
    }
    db.compact().unwrap();
    let cfg = Config {
        data_dir: dir.path().to_path_buf(),
        max_db_bytes: 220 * 1024,
        ..Config::default()
    };
    let h = Harness {
        state: AppState::new(cfg, db, vec![7; 32]),
        _dir: dir,
    };
    assert_eq!(
        call(&h, ok_post(FIXTURE.as_bytes())).await.0,
        StatusCode::CREATED
    );
    assert!(h.state.db.raw_of(&format!("{:032x}", 0)).unwrap().is_none());
    assert!(h.state.db.raw_of(&format!("{:032x}", 1)).unwrap().is_none());
    assert!(h.state.db.raw_of(&format!("{:032x}", 2)).unwrap().is_some());
    h.state.db.compact().unwrap();
    let bytes = std::fs::read(path).unwrap();
    assert!(!bytes
        .windows(b"quota-marker-0".len())
        .any(|w| w == b"quota-marker-0"));
    assert!(!bytes
        .windows(b"quota-marker-1".len())
        .any(|w| w == b"quota-marker-1"));
    assert!(bytes.len() < 220 * 1024);
}
