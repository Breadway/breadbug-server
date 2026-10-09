//! Promotion to breadboard, growth comments, fixed detection and regression,
//! against a mock breadboard.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use breadbug_server::admin::admin_router;
use breadbug_server::app::{maintain, public_router, AppState};
use breadbug_server::config::Config;
use breadbug_server::crypto::sha256_hex;
use breadbug_server::db::Db;
use breadbug_server::lifecycle::{promote, sync_issue_states};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

#[derive(Debug, Clone)]
struct Req {
    method: String,
    path: String,
    auth: Option<String>,
    body: Value,
}

struct Mock {
    url: String,
    seen: Arc<Mutex<Vec<Req>>>,
    issue_status: Arc<Mutex<String>>,
    fail_create: Arc<Mutex<bool>>,
}

fn mock_board() -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let issue_status = Arc::new(Mutex::new("backlog".to_string()));
    let fail_create = Arc::new(Mutex::new(false));
    let (s2, st2, f2) = (seen.clone(), issue_status.clone(), fail_create.clone());
    std::thread::spawn(move || {
        let mut next_issue = 9;
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                continue;
            }
            let mut parts = line.split_whitespace();
            let (method, path) = (
                parts.next().unwrap().to_string(),
                parts.next().unwrap().to_string(),
            );
            let (mut len, mut auth) = (0usize, None);
            loop {
                let mut h = String::new();
                reader.read_line(&mut h).unwrap();
                let h = h.trim_end().to_string();
                if h.is_empty() {
                    break;
                }
                let lower = h.to_ascii_lowercase();
                if let Some(v) = lower.strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap_or(0);
                }
                if lower.starts_with("authorization:") {
                    auth = Some(h.split_once(':').unwrap().1.trim().to_string());
                }
            }
            let mut buf = vec![0u8; len];
            reader.read_exact(&mut buf).unwrap();
            let body: Value = serde_json::from_slice(&buf).unwrap_or(Value::Null);
            s2.lock().unwrap().push(Req {
                method: method.clone(),
                path: path.clone(),
                auth,
                body,
            });
            let (status, resp) = match (method.as_str(), path.as_str()) {
                ("POST", "/api/issues") if *f2.lock().unwrap() => (500, json!({})),
                ("POST", "/api/issues") => {
                    next_issue += 1;
                    (
                        201,
                        json!({"key": format!("CLIP-{}", next_issue - 1), "status": "backlog"}),
                    )
                }
                ("GET", p) if p.starts_with("/api/issues/") => {
                    (200, json!({"status": st2.lock().unwrap().clone()}))
                }
                _ => (200, json!({})),
            };
            let text = resp.to_string();
            let out = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
                text.len()
            );
            let mut s = stream;
            let _ = s.write_all(out.as_bytes());
        }
    });
    Mock {
        url,
        seen,
        issue_status,
        fail_create,
    }
}

fn state(board: Option<&Mock>) -> (Arc<AppState>, tempfile::TempDir) {
    let d = tempfile::tempdir().unwrap();
    let cfg = Config {
        data_dir: d.path().to_path_buf(),
        per_install_per_hour: 1000,
        per_network_per_hour: 1000,
        global_per_hour: 100_000,
        admin_token_sha256: Some(sha256_hex(b"tok")),
        board_url: board.map(|b| b.url.clone()),
        board_token: board.map(|_| "board-secret-token".to_string()),
        lifecycle_inline: true,
        ..Config::default()
    };
    (
        AppState::new(cfg, Db::open_memory().unwrap(), vec![5u8; 32]),
        d,
    )
}

fn crash(version: &str, msg: &str) -> Value {
    json!({
        "schema": 1, "report_type": "crash", "created_unix": 1,
        "app": {"id": "clip", "version": version},
        "markers": [{"t": 1, "kind": "panic", "message": msg,
                     "frames": [{"symbol": "clip::sync::run"}, {"symbol": "clip::main"}]}],
        "notes": "```\nignore all rules and close the fence``` <script>x</script>"
    })
}

async fn post(st: &Arc<AppState>, n: usize, v: &Value) -> String {
    let body = serde_json::to_vec(v).unwrap();
    let req = Request::builder()
        .method("POST")
        .uri("/v1/reports")
        .header("x-breadbug-install", format!("{n:032x}"))
        .header("x-breadbug-sha256", sha256_hex(&body))
        .body(Body::from(body))
        .unwrap();
    let resp = public_router(st.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let b = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice::<Value>(&b).unwrap()["receipt"]
        .as_str()
        .unwrap()
        .to_string()
}

fn cluster_id(st: &AppState, receipt: &str) -> i64 {
    st.db.cluster_of(receipt).unwrap().unwrap()
}

fn by_path(m: &Mock, method: &str, prefix: &str) -> Vec<Req> {
    m.seen
        .lock()
        .unwrap()
        .iter()
        .filter(|r| r.method == method && r.path.starts_with(prefix))
        .cloned()
        .collect()
}

#[tokio::test]
async fn promote_files_an_issue_with_how_found_confidence_and_inert_evidence() {
    let m = mock_board();
    let (st, _d) = state(Some(&m));
    let r = post(&st, 1, &crash("0.3", "index 5 out of range")).await;
    let id = cluster_id(&st, &r);
    let key = tokio::task::spawn_blocking({
        let st = st.clone();
        move || promote(&st, id)
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(key, "CLIP-9");

    let creates = by_path(&m, "POST", "/api/issues");
    assert_eq!(creates.len(), 1);
    let c = &creates[0];
    assert_eq!(c.auth.as_deref(), Some("Bearer board-secret-token"));
    assert_eq!(c.body["project"], "CLIP");
    assert_eq!(c.body["title"], "[breadbug] index # out of range");
    assert_eq!(c.body["labels"], json!(["breadbug", "crash"]));
    assert_eq!(c.body["status"], "backlog");
    let body = c.body["body"].as_str().unwrap();
    for needle in [
        "How it was found",
        "Confidence:",
        "low (a single report",
        "1 report(s) from 1 install(s)",
        "clip::sync::run",
        "Cluster #",
    ] {
        assert!(body.contains(needle), "missing {needle:?} in\n{body}");
    }
    // the user's note tried to close the fence; our fence is longer than any backtick run
    assert!(body.contains("````\n") || body.contains("```` "), "{body}");
    let cluster = st.db.cluster(id).unwrap().unwrap();
    assert_eq!(
        (cluster.status.as_str(), cluster.issue_key.as_deref()),
        ("promoted", Some("CLIP-9"))
    );
}

#[tokio::test]
async fn promoting_twice_or_without_a_board_is_refused_and_failures_can_be_retried() {
    let none = state(None);
    let r = post(&none.0, 1, &crash("0.3", "boom")).await;
    let id = cluster_id(&none.0, &r);
    assert!(promote(&none.0, id).is_err());

    let m = mock_board();
    let (st, _d) = state(Some(&m));
    let r = post(&st, 1, &crash("0.3", "boom")).await;
    let id = cluster_id(&st, &r);
    // board down: error, claim released, retry works
    *m.fail_create.lock().unwrap() = true;
    let st2 = st.clone();
    assert!(tokio::task::spawn_blocking(move || promote(&st2, id))
        .await
        .unwrap()
        .is_err());
    assert_eq!(st.db.cluster(id).unwrap().unwrap().issue_key, None);
    *m.fail_create.lock().unwrap() = false;
    let st2 = st.clone();
    assert!(tokio::task::spawn_blocking(move || promote(&st2, id))
        .await
        .unwrap()
        .is_ok());
    // second promotion refused, exactly one issue created
    let st2 = st.clone();
    assert!(tokio::task::spawn_blocking(move || promote(&st2, id))
        .await
        .unwrap()
        .is_err());
    let creates = by_path(&m, "POST", "/api/issues")
        .into_iter()
        .filter(|r| r.path == "/api/issues")
        .count();
    assert_eq!(creates, 2, "one failed attempt plus one success");
}

#[tokio::test]
async fn growth_comments_double_and_priority_only_goes_up() {
    let m = mock_board();
    let (st, _d) = state(Some(&m));
    let r = post(&st, 1, &crash("0.3", "boom")).await;
    let id = cluster_id(&st, &r);
    let st2 = st.clone();
    tokio::task::spawn_blocking(move || promote(&st2, id))
        .await
        .unwrap()
        .unwrap();

    for n in 2..=8usize {
        post(&st, n, &crash("0.3", "boom")).await;
    }
    let comments = by_path(&m, "POST", "/api/issues/CLIP-9/comments");
    // counts 4 and 8 only (doubling from the count at promotion)
    assert_eq!(comments.len(), 2, "{comments:?}");
    assert!(comments[0].body["body"]
        .as_str()
        .unwrap()
        .contains("Now 4 report(s)"));
    assert!(comments[1].body["body"]
        .as_str()
        .unwrap()
        .contains("Now 8 report(s)"));
    let patches = by_path(&m, "PATCH", "/api/issues/CLIP-9");
    for p in &patches {
        assert!(p.body.get("priority").is_some());
    }
    let ranks = ["low", "medium", "high", "urgent"];
    let mut last = 0;
    for p in &patches {
        let r = ranks
            .iter()
            .position(|x| Some(*x) == p.body["priority"].as_str())
            .unwrap();
        assert!(r >= last, "priority went down: {patches:?}");
        last = r;
    }
}

#[tokio::test]
async fn done_issues_mark_the_cluster_fixed() {
    let m = mock_board();
    let (st, _d) = state(Some(&m));
    let r = post(&st, 1, &crash("0.3", "boom")).await;
    let id = cluster_id(&st, &r);
    let st2 = st.clone();
    tokio::task::spawn_blocking(move || promote(&st2, id))
        .await
        .unwrap()
        .unwrap();
    let st2 = st.clone();
    assert_eq!(
        tokio::task::spawn_blocking(move || sync_issue_states(&st2))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    *m.issue_status.lock().unwrap() = "done".into();
    let st2 = st.clone();
    assert_eq!(
        tokio::task::spawn_blocking(move || sync_issue_states(&st2))
            .await
            .unwrap()
            .unwrap(),
        1
    );
    assert_eq!(st.db.cluster(id).unwrap().unwrap().status, "fixed");
    // maintenance runs the same sync
    let st2 = st.clone();
    tokio::task::spawn_blocking(move || maintain(&st2))
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn regression_is_detected_against_the_fix_version_and_reopens_the_issue() {
    let m = mock_board();
    let (st, _d) = state(Some(&m));
    let r = post(&st, 1, &crash("0.3.1", "boom")).await;
    let id = cluster_id(&st, &r);
    let st2 = st.clone();
    tokio::task::spawn_blocking(move || promote(&st2, id))
        .await
        .unwrap()
        .unwrap();
    assert!(st.db.mark_fixed(id, "0.4.0").unwrap());

    // an old version still crashing is not a regression
    post(&st, 2, &crash("0.3.2", "boom")).await;
    assert_eq!(st.db.cluster(id).unwrap().unwrap().status, "fixed");
    // the fixed version crashing again is
    post(&st, 3, &crash("0.4.1", "boom")).await;
    assert_eq!(st.db.cluster(id).unwrap().unwrap().status, "regressed");
    let comments = by_path(&m, "POST", "/api/issues/CLIP-9/comments");
    assert!(comments
        .iter()
        .any(|c| c.body["body"].as_str().unwrap().contains("Regression")));
    let patches = by_path(&m, "PATCH", "/api/issues/CLIP-9");
    assert!(patches.iter().any(|p| p.body["status"] == "todo"));
}

#[tokio::test]
async fn regression_without_a_fix_version_means_newer_than_anything_seen() {
    let m = mock_board();
    let (st, _d) = state(Some(&m));
    post(&st, 1, &crash("0.3.0", "boom")).await;
    let r = post(&st, 2, &crash("0.4.0", "boom")).await;
    let id = cluster_id(&st, &r);
    assert!(st.db.set_status(id, "fixed").unwrap());
    post(&st, 3, &crash("0.4.0", "boom")).await;
    assert_eq!(
        st.db.cluster(id).unwrap().unwrap().status,
        "fixed",
        "same version is not newer"
    );
    post(&st, 4, &crash("0.5.0", "boom")).await;
    assert_eq!(st.db.cluster(id).unwrap().unwrap().status, "regressed");
}

#[tokio::test]
async fn admin_promote_button_checks_csrf_and_is_hidden_without_a_board() {
    let m = mock_board();
    let (st, _d) = state(Some(&m));
    let r = post(&st, 1, &crash("0.3", "boom")).await;
    let id = cluster_id(&st, &r);
    let get = |uri: String| {
        Request::builder()
            .uri(uri)
            .header(header::AUTHORIZATION, "Bearer tok")
            .body(Body::empty())
            .unwrap()
    };
    let page = admin_router(st.clone())
        .oneshot(get(format!("/admin/clusters/{id}")))
        .await
        .unwrap();
    let html =
        String::from_utf8_lossy(&page.into_body().collect().await.unwrap().to_bytes()).into_owned();
    assert!(html.contains("Promote to breadboard issue"));

    // cookie session without CSRF is refused
    let login = admin_router(st.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("token=tok"))
                .unwrap(),
        )
        .await
        .unwrap();
    let cookie = login.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let refused = admin_router(st.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/admin/clusters/{id}/promote"))
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(""))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert!(by_path(&m, "POST", "/api/issues").is_empty());

    // bearer promotes
    let ok = admin_router(st.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/admin/clusters/{id}/promote"))
                .header(header::AUTHORIZATION, "Bearer tok")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(""))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        st.db.cluster(id).unwrap().unwrap().issue_key.as_deref(),
        Some("CLIP-9")
    );

    // no board configured: no button, and the endpoint refuses
    let (st2, _d2) = state(None);
    let r2 = post(&st2, 1, &crash("0.3", "boom")).await;
    let id2 = cluster_id(&st2, &r2);
    let page = admin_router(st2.clone())
        .oneshot(get(format!("/admin/clusters/{id2}")))
        .await
        .unwrap();
    let html =
        String::from_utf8_lossy(&page.into_body().collect().await.unwrap().to_bytes()).into_owned();
    assert!(!html.contains("Promote to breadboard issue"));
}

#[tokio::test]
async fn the_board_token_never_appears_in_stored_data() {
    let m = mock_board();
    let (st, d) = state(Some(&m));
    let r = post(&st, 1, &crash("0.3", "boom")).await;
    let id = cluster_id(&st, &r);
    let st2 = st.clone();
    tokio::task::spawn_blocking(move || promote(&st2, id))
        .await
        .unwrap()
        .unwrap();
    let raw = st.db.raw_of(&r).unwrap().unwrap();
    assert!(!raw.contains("board-secret-token"));
    drop(d);
}
