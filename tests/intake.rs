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

// ---- clustering ---------------------------------------------------------

fn crash(version: &str, sym: &str, msg: &str, os_build: &str) -> Vec<u8> {
    let mut v: Value = serde_json::from_str(FIXTURE).unwrap();
    v["app"]["version"] = json!(version);
    v["system"]["os_build"] = json!(os_build);
    v["markers"][0]["frames"] = json!([
        {"symbol": "core::panicking::panic::h1111111111111111"},
        {"symbol": format!("{sym}::h{:016x}", version.len() as u64 * 7919)},
        {"symbol": "clip::main::h3333333333333333"}
    ]);
    v["markers"][0]["message"] = json!(msg);
    serde_json::to_vec(&v).unwrap()
}

fn post_as(install: &str, body: &[u8]) -> Request<Body> {
    post(body, Some(install), Some(&sha256_hex(body)), None)
}

#[tokio::test]
async fn the_same_bug_from_different_versions_and_installs_forms_one_cluster() {
    let h = harness(|c| c.per_install_per_hour = 100);
    let msg = "called `Option::unwrap()` on a `None` value";
    let a = crash("0.3.1", "clip::sync::run", msg, "rolling-a");
    let b = crash("0.3.22", "clip::sync::run", msg, "rolling-b");
    let (s1, _, r1) = call(&h, post_as(&"1".repeat(32), &a)).await;
    let (s2, _, r2) = call(&h, post_as(&"2".repeat(32), &b)).await;
    assert_eq!((s1, s2), (StatusCode::CREATED, StatusCode::CREATED));
    let c1 = h
        .state
        .db
        .cluster_of(r1["receipt"].as_str().unwrap())
        .unwrap()
        .unwrap();
    let c2 = h
        .state
        .db
        .cluster_of(r2["receipt"].as_str().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(c1, c2);
    let cluster = h.state.db.cluster(c1).unwrap().unwrap();
    assert_eq!(cluster.count, 2);
    assert_eq!(cluster.installs, 2);
    assert_eq!(cluster.versions.len(), 2);
    assert_eq!(cluster.os_builds.len(), 2);
    assert_eq!(cluster.kind, "crash");
    assert_eq!(cluster.title, "called `Option::unwrap()` on a `None` value");
    assert_eq!(h.state.db.clusters().unwrap().len(), 1);
}

#[tokio::test]
async fn a_different_bug_gets_its_own_cluster() {
    let h = harness(|c| c.per_install_per_hour = 100);
    let msg = "boom";
    let (_, _, r1) = call(
        &h,
        post_as(&"1".repeat(32), &crash("0.3", "clip::sync::run", msg, "x")),
    )
    .await;
    let (_, _, r2) = call(
        &h,
        post_as(&"1".repeat(32), &crash("0.3", "clip::paste::run", msg, "x")),
    )
    .await;
    let c1 = h
        .state
        .db
        .cluster_of(r1["receipt"].as_str().unwrap())
        .unwrap();
    let c2 = h
        .state
        .db
        .cluster_of(r2["receipt"].as_str().unwrap())
        .unwrap();
    assert_ne!(c1, c2);
    assert_eq!(h.state.db.clusters().unwrap().len(), 2);
}

#[tokio::test]
async fn quarantined_and_unfingerprintable_reports_are_not_clustered() {
    let h = harness(|c| c.per_install_per_hour = 100);
    // leaked PII -> quarantined -> stays out of clusters
    let mut v: Value = serde_json::from_slice(&crash("0.3", "clip::a", "m", "x")).unwrap();
    v["notes"] = json!("mail leak@example.org");
    let (_, _, r) = call(
        &h,
        post_as(&"1".repeat(32), &serde_json::to_vec(&v).unwrap()),
    )
    .await;
    assert_eq!(
        h.state
            .db
            .cluster_of(r["receipt"].as_str().unwrap())
            .unwrap(),
        None
    );
    // behavior report with no evidence -> no fingerprint
    let beh = json!({"schema":1,"report_type":"behavior","created_unix":1,"app":{"id":"clip"},"notes":"weird"});
    let (status, _, r) = call(
        &h,
        post_as(&"2".repeat(32), &serde_json::to_vec(&beh).unwrap()),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        h.state
            .db
            .cluster_of(r["receipt"].as_str().unwrap())
            .unwrap(),
        None
    );
    assert!(h.state.db.clusters().unwrap().is_empty());
}

#[tokio::test]
async fn deleting_a_report_shrinks_its_cluster() {
    let h = harness(|c| c.per_install_per_hour = 100);
    let body = crash("0.3", "clip::sync::run", "boom", "x");
    let (_, _, r1) = call(&h, post_as(&"1".repeat(32), &body)).await;
    let mut other = serde_json::from_slice::<Value>(&body).unwrap();
    other["created_unix"] = json!(5);
    let (_, _, r2) = call(
        &h,
        post_as(&"2".repeat(32), &serde_json::to_vec(&other).unwrap()),
    )
    .await;
    let cid = h
        .state
        .db
        .cluster_of(r1["receipt"].as_str().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(h.state.db.cluster(cid).unwrap().unwrap().count, 2);

    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/reports/{}", r1["receipt"].as_str().unwrap()))
        .header(
            "authorization",
            format!("Bearer {}", r1["deletion_token"].as_str().unwrap()),
        )
        .body(Body::empty())
        .unwrap();
    assert_eq!(call(&h, req).await.0, StatusCode::NO_CONTENT);
    let c = h.state.db.cluster(cid).unwrap().unwrap();
    assert_eq!((c.count, c.installs), (1, 1));
    assert_eq!(c.versions.get("0.3"), Some(&1));
    let _ = r2;
}

#[tokio::test]
async fn refingerprint_moves_reports_when_rules_change_and_is_a_noop_otherwise() {
    let h = harness(|c| c.per_install_per_hour = 100);
    let (_, _, r) = call(
        &h,
        post_as(
            &"1".repeat(32),
            &crash("0.3", "clip::sync::run", "boom", "x"),
        ),
    )
    .await;
    let receipt = r["receipt"].as_str().unwrap();
    let before = h.state.db.cluster_of(receipt).unwrap().unwrap();
    // Unchanged rules: nothing moves.
    assert_eq!(
        breadbug_server::cluster::refingerprint_all(&h.state.db).unwrap(),
        0
    );
    assert_eq!(h.state.db.cluster_of(receipt).unwrap(), Some(before));
    // Simulate an old rule set: point the report at a cluster with a stale fingerprint.
    h.state
        .db
        .corrupt_fingerprint_for_test(before, "stale-fingerprint")
        .unwrap();
    assert_eq!(
        breadbug_server::cluster::refingerprint_all(&h.state.db).unwrap(),
        1
    );
    let after = h.state.db.cluster_of(receipt).unwrap().unwrap();
    assert_ne!(after, before);
    assert_eq!(h.state.db.cluster(after).unwrap().unwrap().count, 1);
    // The emptied stale cluster was pruned.
    assert!(h.state.db.cluster(before).unwrap().is_none());
    assert_eq!(h.state.db.clusters().unwrap().len(), 1);
}

#[tokio::test]
async fn public_status_follows_the_cluster_and_reveals_nothing_else() {
    let h = harness(|c| c.per_install_per_hour = 100);
    let status_of = |h: &Harness, receipt: String| {
        let req = Request::builder()
            .uri(format!("/v1/reports/{receipt}/status"))
            .body(Body::empty())
            .unwrap();
        let h2 = h.state.clone();
        async move {
            let resp = public_router(h2).oneshot(req).await.unwrap();
            let status = resp.status();
            let b = resp.into_body().collect().await.unwrap().to_bytes();
            (
                status,
                serde_json::from_slice::<Value>(&b).unwrap_or(Value::Null),
            )
        }
    };
    let body = crash("0.3", "clip::sync::run", "boom", "x");
    let (_, _, r1) = call(&h, post_as(&"1".repeat(32), &body)).await;
    let rec1 = r1["receipt"].as_str().unwrap().to_string();
    assert_eq!(
        status_of(&h, rec1.clone()).await.1,
        json!({"status": "received"})
    );

    // a second install reports the same problem: both are now a known issue
    let (_, _, r2) = call(&h, post_as(&"2".repeat(32), &body)).await;
    let rec2 = r2["receipt"].as_str().unwrap().to_string();
    assert_eq!(
        status_of(&h, rec1.clone()).await.1,
        json!({"status": "duplicate"})
    );
    assert_eq!(status_of(&h, rec2).await.1, json!({"status": "duplicate"}));

    let cid = h.state.db.cluster_of(&rec1).unwrap().unwrap();
    h.state.db.set_status(cid, "investigating").unwrap();
    assert_eq!(
        status_of(&h, rec1.clone()).await.1,
        json!({"status": "investigating"})
    );
    h.state.db.mark_fixed(cid, "0.4.0").unwrap();
    assert_eq!(
        status_of(&h, rec1.clone()).await.1,
        json!({"status": "fixed", "fixed_in": "0.4.0"})
    );
    h.state.db.set_status(cid, "dismissed").unwrap();
    assert_eq!(
        status_of(&h, rec1.clone()).await.1,
        json!({"status": "closed"})
    );

    // merged clusters report their target's state
    let other = crash("0.3", "clip::other", "other", "x");
    let (_, _, r3) = call(&h, post_as(&"3".repeat(32), &other)).await;
    let rec3 = r3["receipt"].as_str().unwrap().to_string();
    let c3 = h.state.db.cluster_of(&rec3).unwrap().unwrap();
    h.state.db.set_status(cid, "fixed").unwrap();
    h.state.db.merge_clusters(c3, cid).unwrap();
    assert_eq!(status_of(&h, rec3).await.1["status"], json!("fixed"));

    // quarantined reports look merely received; unknown receipts are 404
    let mut leaked: Value = serde_json::from_slice(&body).unwrap();
    leaked["notes"] = json!("mail leak@example.org");
    let (_, _, r4) = call(
        &h,
        post_as(&"4".repeat(32), &serde_json::to_vec(&leaked).unwrap()),
    )
    .await;
    assert_eq!(
        status_of(&h, r4["receipt"].as_str().unwrap().to_string())
            .await
            .1,
        json!({"status": "received"})
    );
    assert_eq!(status_of(&h, "0".repeat(32)).await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn status_lookups_are_rate_limited() {
    let h = harness(|c| c.per_network_per_hour = 3);
    let mut last = StatusCode::OK;
    for _ in 0..5 {
        let req = Request::builder()
            .uri(format!("/v1/reports/{}/status", "a".repeat(32)))
            .body(Body::empty())
            .unwrap();
        last = public_router(h.state.clone())
            .oneshot(req)
            .await
            .unwrap()
            .status();
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
}

// ---- manual reports -------------------------------------------------------

fn manual_report(title: &str, notes: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": 1,
        "report_type": "manual",
        "created_unix": 1000,
        "app": {"id": "clip", "version": "0.3.1"},
        "title": title,
        "notes": notes,
    }))
    .unwrap()
}

#[tokio::test]
async fn manual_reports_are_accepted_and_clustered_by_text() {
    let h = harness(|c| c.per_install_per_hour = 100);
    let title = "Panel flickers on workspace switch";
    let a = manual_report(
        title,
        "The top panel flickers for a second on every switch.",
    );
    let b = manual_report(
        title,
        "Switching workspaces makes the top panel flicker briefly.",
    );
    let (s1, _, r1) = call(&h, post_as(&"1".repeat(32), &a)).await;
    let (s2, _, r2) = call(&h, post_as(&"2".repeat(32), &b)).await;
    assert_eq!((s1, s2), (StatusCode::CREATED, StatusCode::CREATED));
    assert!(r1.get("deletion_token").is_some());
    // Idempotent resend of the same body from the same install.
    let (s3, _, again) = call(&h, post_as(&"1".repeat(32), &a)).await;
    assert_eq!(s3, StatusCode::OK);
    assert_eq!(again["receipt"], r1["receipt"]);
    // Both installs describe the same problem: one cluster, titled as filed.
    let c1 = h
        .state
        .db
        .cluster_of(r1["receipt"].as_str().unwrap())
        .unwrap()
        .unwrap();
    let c2 = h
        .state
        .db
        .cluster_of(r2["receipt"].as_str().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(c1, c2);
    let cluster = h.state.db.cluster(c1).unwrap().unwrap();
    assert_eq!(cluster.kind, "manual");
    assert_eq!(cluster.title, title);
    assert_eq!((cluster.count, cluster.installs), (2, 2));
}

#[tokio::test]
async fn manual_reports_without_title_or_description_are_rejected() {
    let h = harness(|_| {});
    for body in [
        manual_report("", "has words but no title here"),
        manual_report("A title with no description", "   "),
        serde_json::to_vec(&json!({
            "schema": 1, "report_type": "manual", "created_unix": 1000,
            "app": {"id": "clip"}, "notes": "no title at all in this one",
        }))
        .unwrap(),
    ] {
        let (status, _, _) = call(&h, post_as(&"1".repeat(32), &body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    assert_eq!(h.state.db.report_count().unwrap(), 0);
}

#[tokio::test]
async fn leaked_pii_in_a_manual_title_is_scrubbed_and_quarantined() {
    let h = harness(|_| {});
    let body = manual_report(
        "Breaks for leak@example.org",
        "Contact me at leak@example.org about this",
    );
    let (status, _, r) = call(&h, post_as(&"1".repeat(32), &body)).await;
    assert_eq!(status, StatusCode::CREATED);
    let receipt = r["receipt"].as_str().unwrap();
    let raw = h.state.db.raw_of(receipt).unwrap().unwrap();
    assert!(!raw.contains("leak@example.org"));
    assert_eq!(h.state.db.is_quarantined(receipt).unwrap(), Some(true));
}

#[tokio::test]
async fn manual_diagnostics_and_screenshot_need_consent() {
    let h = harness(|c| c.per_install_per_hour = 100);
    // A reference without consent is refused.
    let body = serde_json::to_vec(&json!({
        "schema": 1, "report_type": "manual", "created_unix": 1000,
        "app": {"id": "clip", "version": "0.3"},
        "title": "Panel flickers",
        "notes": "The panel flickers on every workspace switch today.",
        "diagnostics_reference": "diag/2026-10-11",
    }))
    .unwrap();
    let (s, _, _) = call(&h, post_as(&"1".repeat(32), &body)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(h.state.db.report_count().unwrap(), 0);

    // With consent, both references are accepted and stored.
    let body = serde_json::to_vec(&json!({
        "schema": 1, "report_type": "manual", "created_unix": 1000,
        "app": {"id": "clip", "version": "0.3"},
        "title": "Panel flickers",
        "notes": "The panel flickers on every workspace switch today.",
        "diagnostics_reference": "diag/2026-10-11",
        "screenshot_reference": "shot/42",
        "consent": true,
    }))
    .unwrap();
    let (s, _, r) = call(&h, post_as(&"1".repeat(32), &body)).await;
    assert_eq!(s, StatusCode::CREATED);
    let raw = h
        .state
        .db
        .raw_of(r["receipt"].as_str().unwrap())
        .unwrap()
        .unwrap();
    assert!(
        raw.contains("diag/2026-10-11") && raw.contains("shot/42"),
        "{raw}"
    );
}

#[tokio::test]
async fn manual_reports_respect_rate_limit_and_delete() {
    let h = harness(|c| c.per_install_per_hour = 1);
    let a = manual_report(
        "Panel flickers",
        "The panel flickers on every switch today.",
    );
    let b = manual_report(
        "Clipboard lost",
        "The clipboard contents vanish after unlock.",
    );
    let (s1, _, r1) = call(&h, post_as(&"1".repeat(32), &a)).await;
    assert_eq!(s1, StatusCode::CREATED);
    let (s2, hdr, _) = call(&h, post_as(&"1".repeat(32), &b)).await;
    assert_eq!(s2, StatusCode::TOO_MANY_REQUESTS);
    assert!(hdr.contains_key("retry-after"), "{hdr:?}");

    let receipt = r1["receipt"].as_str().unwrap().to_string();
    let token = r1["deletion_token"].as_str().unwrap().to_string();
    let del = |tok: &str| {
        Request::builder()
            .method("DELETE")
            .uri(format!("/v1/reports/{receipt}"))
            .header("authorization", format!("Bearer {tok}"))
            .body(Body::empty())
            .unwrap()
    };
    assert_eq!(
        call(&h, del(&"0".repeat(64))).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(h.state.db.report_count().unwrap(), 1);
    assert_eq!(call(&h, del(&token)).await.0, StatusCode::NO_CONTENT);
    assert_eq!(h.state.db.report_count().unwrap(), 0);
}

#[tokio::test]
async fn manual_reports_are_covered_by_retention() {
    let h = harness(|c| c.retention = std::time::Duration::from_secs(0));
    let body = manual_report(
        "Panel flickers",
        "The panel flickers on every switch today.",
    );
    call(&h, post_as(&"1".repeat(32), &body)).await;
    std::thread::sleep(std::time::Duration::from_millis(1100));
    assert_eq!(maintain(&h.state).unwrap(), 1);
    assert_eq!(h.state.db.report_count().unwrap(), 0);
}

// ---- feature requests -----------------------------------------------------

fn feature_request(title: &str, want: &str, why: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": 1,
        "report_type": "request",
        "created_unix": 1000,
        "app": {"id": "clip", "version": "0.3.1"},
        "title": title,
        "want": want,
        "notes": why,
    }))
    .unwrap()
}

#[tokio::test]
async fn feature_requests_are_accepted_and_grouped_by_text() {
    let h = harness(|c| c.per_install_per_hour = 100);
    let title = "Dark mode for the panel";
    let a = feature_request(
        title,
        "A dark theme option for the top panel.",
        "I work at night and the bright panel hurts.",
    );
    let b = feature_request(
        title,
        "Let the top panel use a dark theme.",
        "Night shifts here, the bright panel is painful.",
    );
    let (s1, _, r1) = call(&h, post_as(&"1".repeat(32), &a)).await;
    let (s2, _, r2) = call(&h, post_as(&"2".repeat(32), &b)).await;
    assert_eq!((s1, s2), (StatusCode::CREATED, StatusCode::CREATED));
    let c1 = h
        .state
        .db
        .cluster_of(r1["receipt"].as_str().unwrap())
        .unwrap()
        .unwrap();
    let c2 = h
        .state
        .db
        .cluster_of(r2["receipt"].as_str().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(c1, c2);
    let cluster = h.state.db.cluster(c1).unwrap().unwrap();
    assert_eq!(cluster.kind, "request");
    assert_eq!(cluster.title, title);
    assert_eq!((cluster.count, cluster.installs), (2, 2));
}

#[tokio::test]
async fn feature_requests_need_what_and_why() {
    let h = harness(|_| {});
    for body in [
        feature_request("", "some want", "some why"),
        feature_request("A title", "", "some why"),
        feature_request("A title", "some want", "  "),
    ] {
        let (status, _, _) = call(&h, post_as(&"1".repeat(32), &body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    assert_eq!(h.state.db.report_count().unwrap(), 0);
}

#[tokio::test]
async fn feature_request_resend_delete_and_token_are_safe() {
    let h = harness(|c| c.per_install_per_hour = 100);
    let body = feature_request(
        "Dark mode for the panel",
        "A dark theme option for the top panel.",
        "I work at night and the bright panel hurts.",
    );
    let (s1, _, r1) = call(&h, post_as(&"1".repeat(32), &body)).await;
    assert_eq!(s1, StatusCode::CREATED);
    let receipt = r1["receipt"].as_str().unwrap().to_string();
    let token = r1["deletion_token"].as_str().unwrap().to_string();
    // Idempotent resend: same receipt, no second report.
    let (s2, _, r2) = call(&h, post_as(&"1".repeat(32), &body)).await;
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(r2["receipt"], r1["receipt"]);
    assert_eq!(h.state.db.report_count().unwrap(), 1);
    // Delete needs the token; a wrong token leaves the report in place.
    let del = |tok: &str| {
        Request::builder()
            .method("DELETE")
            .uri(format!("/v1/reports/{receipt}"))
            .header("authorization", format!("Bearer {tok}"))
            .body(Body::empty())
            .unwrap()
    };
    assert_eq!(
        call(&h, del(&"0".repeat(64))).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(h.state.db.report_count().unwrap(), 1);
    assert_eq!(call(&h, del(&token)).await.0, StatusCode::NO_CONTENT);
    assert_eq!(h.state.db.report_count().unwrap(), 0);
}

#[tokio::test]
async fn hostile_text_in_a_request_is_scrubbed_and_quarantined() {
    let h = harness(|_| {});
    let body = feature_request(
        "Breaks for leak@example.org",
        "Email leak@example.org when it happens.",
        "Reach me at leak@example.org about it.",
    );
    let (status, _, r) = call(&h, post_as(&"1".repeat(32), &body)).await;
    assert_eq!(status, StatusCode::CREATED);
    let receipt = r["receipt"].as_str().unwrap();
    let raw = h.state.db.raw_of(receipt).unwrap().unwrap();
    assert!(!raw.contains("leak@example.org"));
    assert_eq!(h.state.db.is_quarantined(receipt).unwrap(), Some(true));
}

#[tokio::test]
async fn manual_and_request_reports_never_join_a_crash_cluster() {
    let h = harness(|c| c.per_install_per_hour = 100);
    // An automatic crash with panic frames.
    let crash_body = crash("0.3.1", "clip::draw", "boom at the panel", "os-1");
    let (_, _, cr) = call(&h, post_as(&"1".repeat(32), &crash_body)).await;
    let crash_cluster = h
        .state
        .db
        .cluster_of(cr["receipt"].as_str().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(
        h.state.db.cluster(crash_cluster).unwrap().unwrap().kind,
        "crash"
    );

    // The very same panic frames, but filed by hand and as a request.
    let mut manual: Value = serde_json::from_slice(&crash_body).unwrap();
    manual["report_type"] = json!("manual");
    manual["title"] = json!("The panel dies when I open settings");
    manual["notes"] = json!("Opening settings today closes the whole top panel instantly.");
    let manual = serde_json::to_vec(&manual).unwrap();
    let mut request: Value = serde_json::from_slice(&crash_body).unwrap();
    request["report_type"] = json!("request");
    request["title"] = json!("Stop the panel closing");
    request["want"] = json!("The panel should stay open when I open settings.");
    request["notes"] = json!("It closes the shell when I open settings, please change that.");
    let request = serde_json::to_vec(&request).unwrap();

    let (_, _, mr) = call(&h, post_as(&"2".repeat(32), &manual)).await;
    let (_, _, rr) = call(&h, post_as(&"3".repeat(32), &request)).await;
    let m_cluster = h
        .state
        .db
        .cluster_of(mr["receipt"].as_str().unwrap())
        .unwrap();
    let r_cluster = h
        .state
        .db
        .cluster_of(rr["receipt"].as_str().unwrap())
        .unwrap();
    assert_ne!(m_cluster, Some(crash_cluster));
    assert_ne!(r_cluster, Some(crash_cluster));
    // And the crash cluster keeps only the automatic report.
    assert_eq!(h.state.db.cluster(crash_cluster).unwrap().unwrap().count, 1);
    for (id, kind) in [(m_cluster, "manual"), (r_cluster, "request")] {
        if let Some(id) = id {
            assert_eq!(h.state.db.cluster(id).unwrap().unwrap().kind, kind);
        }
    }
}
