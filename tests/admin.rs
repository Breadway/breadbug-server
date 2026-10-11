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

struct H {
    st: Arc<AppState>,
    _d: tempfile::TempDir,
}

fn harness(with_admin: bool) -> H {
    let d = tempfile::tempdir().unwrap();
    let cfg = Config {
        data_dir: d.path().to_path_buf(),
        admin_token_sha256: with_admin.then(|| sha256_hex(TOKEN.as_bytes())),
        per_install_per_hour: 1000,
        per_network_per_hour: 1000,
        ..Config::default()
    };
    H {
        st: AppState::new(cfg, Db::open_memory().unwrap(), vec![9u8; 32]),
        _d: d,
    }
}

async fn public_post(h: &H, install: &str, v: &Value) -> (StatusCode, Value) {
    let body = serde_json::to_vec(v).unwrap();
    let req = Request::builder()
        .method("POST")
        .uri("/v1/reports")
        .header("x-breadbug-install", install)
        .header("x-breadbug-sha256", sha256_hex(&body))
        .body(Body::from(body))
        .unwrap();
    let resp = public_router(h.st.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let b = resp.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&b).unwrap_or(Value::Null))
}

struct Resp {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: String,
}

async fn admin(h: &H, req: Request<Body>) -> Resp {
    let resp = admin_router(h.st.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let b = resp.into_body().collect().await.unwrap().to_bytes();
    Resp {
        status,
        headers,
        body: String::from_utf8_lossy(&b).into_owned(),
    }
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .body(Body::empty())
        .unwrap()
}

fn post_form(uri: &str, form: &str, auth: &[(&str, String)]) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    for (k, v) in auth {
        b = b.header(*k, v.as_str());
    }
    b.body(Body::from(form.to_string())).unwrap()
}

fn bearer() -> Vec<(&'static str, String)> {
    vec![("authorization", format!("Bearer {TOKEN}"))]
}

fn crash(sym: &str, msg: &str, app: &str, version: &str) -> Value {
    json!({
        "schema": 1, "report_type": "crash", "created_unix": 1,
        "app": {"id": app, "version": version},
        "markers": [{"t": 1, "kind": "panic", "message": msg, "frames": [{"symbol": sym}]}]
    })
}

fn behavior(notes: &str) -> Value {
    json!({"schema": 1, "report_type": "behavior", "created_unix": 1, "app": {"id": "clip"}, "notes": notes})
}

fn extract(body: &str, name: &str) -> String {
    let marker = format!("name=\"{name}\" value=\"");
    let i = body.find(&marker).expect("field present") + marker.len();
    let j = body[i..].find('"').expect("closing quote");
    body[i..i + j].to_string()
}

#[tokio::test]
async fn admin_is_off_without_a_token_and_locked_without_credentials() {
    let h = harness(false);
    assert_eq!(
        admin(&h, get("/admin/")).await.status,
        StatusCode::NOT_FOUND
    );
    let h = harness(true);
    let r = admin(
        &h,
        Request::builder()
            .uri("/admin/")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(r.headers[header::LOCATION], "/admin/login");
    let wrong = Request::builder()
        .uri("/admin/")
        .header(header::AUTHORIZATION, "Bearer nope")
        .body(Body::empty())
        .unwrap();
    assert_eq!(admin(&h, wrong).await.status, StatusCode::SEE_OTHER);
    for uri in ["/admin/clusters/1", "/admin/quarantine", "/admin/symbols"] {
        let r = admin(&h, Request::builder().uri(uri).body(Body::empty()).unwrap()).await;
        assert_eq!(r.status, StatusCode::SEE_OTHER, "{uri}");
    }
    // POSTs are protected too
    let r = admin(
        &h,
        post_form("/admin/clusters/1/status", "status=dismissed", &[]),
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn inbox_ranks_by_explainable_score_and_sets_security_headers() {
    let h = harness(true);
    public_post(
        &h,
        &"1".repeat(32),
        &behavior("clipboard hangs when pasting a large image"),
    )
    .await;
    public_post(
        &h,
        &"2".repeat(32),
        &crash("clip::sync::run", "boom", "clip", "0.3"),
    )
    .await;
    let r = admin(&h, get("/admin/")).await;
    assert_eq!(r.status, StatusCode::OK);
    let crash_pos = r.body.find("boom").unwrap();
    let behavior_pos = r.body.find("clipboard hangs").unwrap();
    assert!(crash_pos < behavior_pos, "crash must rank above behavior");
    let csp = r.headers[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
    assert!(csp.contains("default-src 'none'") && !csp.contains("script-src"));
    assert_eq!(r.headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert_eq!(r.headers[header::CACHE_CONTROL], "no-store");

    let id =
        h.st.db
            .clusters()
            .unwrap()
            .iter()
            .find(|c| c.kind == "crash")
            .unwrap()
            .id;
    let d = admin(&h, get(&format!("/admin/clusters/{id}"))).await;
    assert!(
        d.body.contains("score:") && d.body.contains("kind +100"),
        "{}",
        d.body
    );
}

#[tokio::test]
async fn hostile_report_text_is_escaped_everywhere() {
    let h = harness(true);
    let evil = "<script>alert(1)</script><img src=x onerror=alert(2)>\"'&";
    public_post(
        &h,
        &"1".repeat(32),
        &crash("clip::run", evil, "clip", "0.3"),
    )
    .await;
    let mut v = behavior("a long enough note about <b>bold</b> <script>x()</script> things");
    v["markers"] = json!([{"t": 1, "kind": "freeze", "message": "<svg onload=alert(3)>"}]);
    public_post(&h, &"2".repeat(32), &v).await;
    let id =
        h.st.db
            .clusters()
            .unwrap()
            .iter()
            .find(|c| c.kind == "crash")
            .unwrap()
            .id;
    for uri in [
        "/admin/".to_string(),
        format!("/admin/clusters/{id}"),
        "/admin/quarantine".into(),
        "/admin/symbols".into(),
    ] {
        let r = admin(&h, get(&uri)).await;
        assert_eq!(r.status, StatusCode::OK, "{uri}");
        for bad in ["<script", "<img src=x", "<svg onload", "<b>bold</b>"] {
            assert!(!r.body.contains(bad), "{uri} rendered {bad} unescaped");
        }
    }
    // The raw text is shown (escaped) in the report evidence.
    let detail = admin(&h, get(&format!("/admin/clusters/{id}"))).await;
    assert!(
        detail
            .body
            .contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
        "{}",
        detail.body
    );
}

#[tokio::test]
async fn cookie_login_requires_csrf_for_actions() {
    let h = harness(true);
    public_post(
        &h,
        &"1".repeat(32),
        &crash("clip::run", "boom", "clip", "0.3"),
    )
    .await;
    let id = h.st.db.clusters().unwrap()[0].id;

    // wrong token
    let r = admin(&h, post_form("/admin/login", "token=wrong", &[])).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    // right token
    let form = format!("token={}", TOKEN.replace(' ', "+"));
    let r = admin(&h, post_form("/admin/login", &form, &[])).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let set = r.headers[header::SET_COOKIE].to_str().unwrap().to_string();
    assert!(
        set.contains("HttpOnly") && set.contains("SameSite=Strict") && set.contains("Path=/admin")
    );
    let cookie = set.split(';').next().unwrap().to_string();

    let page = admin(
        &h,
        Request::builder()
            .uri(format!("/admin/clusters/{id}"))
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(page.status, StatusCode::OK);
    let csrf = extract(&page.body, "csrf");

    let auth = [("cookie", cookie.clone())];
    let no_csrf = admin(
        &h,
        post_form(
            &format!("/admin/clusters/{id}/status"),
            "status=dismissed",
            &auth,
        ),
    )
    .await;
    assert_eq!(no_csrf.status, StatusCode::FORBIDDEN);
    let bad_csrf = admin(
        &h,
        post_form(
            &format!("/admin/clusters/{id}/status"),
            "csrf=zzz&status=dismissed",
            &auth,
        ),
    )
    .await;
    assert_eq!(bad_csrf.status, StatusCode::FORBIDDEN);
    assert_eq!(h.st.db.cluster(id).unwrap().unwrap().status, "new");
    let ok = admin(
        &h,
        post_form(
            &format!("/admin/clusters/{id}/status"),
            &format!("csrf={csrf}&status=dismissed"),
            &auth,
        ),
    )
    .await;
    assert_eq!(ok.status, StatusCode::SEE_OTHER);
    assert_eq!(h.st.db.cluster(id).unwrap().unwrap().status, "dismissed");
}

#[tokio::test]
async fn status_fixed_merge_and_filters() {
    let h = harness(true);
    public_post(
        &h,
        &"1".repeat(32),
        &crash("clip::a", "first", "clip", "0.3"),
    )
    .await;
    public_post(
        &h,
        &"2".repeat(32),
        &crash("clip::b", "second", "clip", "0.4"),
    )
    .await;
    public_post(
        &h,
        &"3".repeat(32),
        &crash("pad::c", "other app", "pad", "0.1"),
    )
    .await;
    let all = h.st.db.clusters().unwrap();
    let by = |t: &str| all.iter().find(|c| c.title == t).unwrap().id;
    let (a, b, p) = (by("first"), by("second"), by("other app"));

    // status + fixed
    let r = admin(
        &h,
        post_form(
            &format!("/admin/clusters/{a}/status"),
            "status=investigating",
            &bearer(),
        ),
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let bad = admin(
        &h,
        post_form(
            &format!("/admin/clusters/{a}/status"),
            "status=bogus",
            &bearer(),
        ),
    )
    .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    let r = admin(
        &h,
        post_form(
            &format!("/admin/clusters/{a}/fixed"),
            "version=0.5.1",
            &bearer(),
        ),
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let c = h.st.db.cluster(a).unwrap().unwrap();
    assert_eq!(
        (c.status.as_str(), c.fixed_in.as_deref()),
        ("fixed", Some("0.5.1"))
    );
    assert_eq!(
        admin(
            &h,
            post_form(&format!("/admin/clusters/{a}/fixed"), "version=", &bearer())
        )
        .await
        .status,
        StatusCode::BAD_REQUEST
    );

    // fixed clusters leave the default view but show under ?status=fixed
    let open = admin(&h, get("/admin/")).await.body;
    assert!(!open.contains(">first<") && open.contains("second"));
    assert!(admin(&h, get("/admin/?status=fixed"))
        .await
        .body
        .contains("first"));
    assert!(admin(&h, get("/admin/?status=all&app=pad"))
        .await
        .body
        .contains("other app"));

    // merge: different apps are refused, same app folds counts and versions
    let bad = admin(
        &h,
        post_form(
            &format!("/admin/clusters/{b}/merge"),
            &format!("into={p}"),
            &bearer(),
        ),
    )
    .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    let ok = admin(
        &h,
        post_form(
            &format!("/admin/clusters/{b}/merge"),
            &format!("into=%23{a}"),
            &bearer(),
        ),
    )
    .await;
    assert_eq!(ok.status, StatusCode::SEE_OTHER);
    let merged = h.st.db.cluster(a).unwrap().unwrap();
    assert_eq!((merged.count, merged.installs), (2, 2));
    assert_eq!(merged.versions.len(), 2);
    assert!(admin(&h, get(&format!("/admin/clusters/{b}")))
        .await
        .body
        .contains("merged into"));
    assert_eq!(h.st.db.clusters().unwrap().len(), 2);
    // self-merge refused
    let r = admin(
        &h,
        post_form(
            &format!("/admin/clusters/{a}/merge"),
            &format!("into={a}"),
            &bearer(),
        ),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn merged_clusters_keep_collecting_into_their_target() {
    let h = harness(true);
    public_post(
        &h,
        &"1".repeat(32),
        &crash("clip::a", "first", "clip", "0.3"),
    )
    .await;
    public_post(
        &h,
        &"2".repeat(32),
        &crash("clip::b", "second", "clip", "0.4"),
    )
    .await;
    let all = h.st.db.clusters().unwrap();
    let (a, b) = (
        all.iter().find(|c| c.title == "first").unwrap().id,
        all.iter().find(|c| c.title == "second").unwrap().id,
    );
    assert!(h.st.db.merge_clusters(b, a).unwrap());
    // a new report with b's fingerprint lands in a
    let (_, r) = public_post(
        &h,
        &"3".repeat(32),
        &crash("clip::b", "second", "clip", "0.5"),
    )
    .await;
    assert_eq!(
        h.st.db.cluster_of(r["receipt"].as_str().unwrap()).unwrap(),
        Some(a)
    );
    assert_eq!(h.st.db.cluster(a).unwrap().unwrap().count, 3);
}

#[tokio::test]
async fn quarantine_release_delete_and_ban() {
    let h = harness(true);
    let mut leaked = crash("clip::a", "boom", "clip", "0.3");
    leaked["notes"] = json!("contact leak@example.org please");
    public_post(&h, &"7".repeat(32), &leaked).await;
    assert!(h.st.db.clusters().unwrap().is_empty());
    let page = admin(&h, get("/admin/quarantine")).await;
    assert!(page.body.contains("EMAIL"), "{}", page.body);
    assert!(!page.body.contains("leak@example.org"));
    let qid = h.st.db.quarantined(10).unwrap()[0].id;

    // release -> clustered
    let r = admin(
        &h,
        post_form(&format!("/admin/quarantine/{qid}/release"), "", &bearer()),
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(h.st.db.clusters().unwrap().len(), 1);
    assert!(h.st.db.quarantined(10).unwrap().is_empty());

    // another leak: delete + ban the install
    let mut again = crash("clip::z", "zzz", "clip", "0.3");
    again["notes"] = json!("also bob@example.org");
    public_post(&h, &"8".repeat(32), &again).await;
    let qid = h.st.db.quarantined(10).unwrap()[0].id;
    let r = admin(
        &h,
        post_form(&format!("/admin/quarantine/{qid}/ban"), "", &bearer()),
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(h.st.db.ban_count().unwrap(), 1);
    let (status, _) = public_post(&h, &"8".repeat(32), &crash("clip::q", "q", "clip", "0.3")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // other installs are fine
    assert_eq!(
        public_post(&h, &"9".repeat(32), &crash("clip::q", "q", "clip", "0.3"))
            .await
            .0,
        StatusCode::CREATED
    );
    // unknown action / id
    assert_eq!(
        admin(
            &h,
            post_form("/admin/quarantine/999/release", "", &bearer())
        )
        .await
        .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        admin(
            &h,
            post_form(&format!("/admin/quarantine/{qid}/explode"), "", &bearer())
        )
        .await
        .status,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn login_attempts_are_rate_limited() {
    let h = harness(true);
    let mut last = StatusCode::OK;
    for _ in 0..12 {
        last = admin(&h, post_form("/admin/login", "token=wrong", &[]))
            .await
            .status;
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn missing_symbols_page_lists_build_ids() {
    let h = harness(true);
    let v = json!({
        "schema": 1, "report_type": "crash", "created_unix": 1, "app": {"id": "clip", "version": "0.3"},
        "markers": [{"t": 1, "kind": "panic", "frames": [{"offset": 5, "build_id": "aabbccddeeff0011"}]}]
    });
    public_post(&h, &"1".repeat(32), &v).await;
    let r = admin(&h, get("/admin/symbols")).await;
    assert!(r.body.contains("aabbccddeeff0011"));
}

#[tokio::test]
async fn inbox_kind_filter_separates_manual_and_request_from_crashes() {
    let h = harness(true);
    public_post(
        &h,
        &"1".repeat(32),
        &crash("clip::a", "a crash happened", "clip", "0.3"),
    )
    .await;
    public_post(
        &h,
        &"2".repeat(32),
        &json!({
            "schema": 1, "report_type": "manual", "created_unix": 1,
            "app": {"id": "clip", "version": "0.3"},
            "title": "Panel flickers on switch",
            "notes": "The panel flickers whenever I switch workspaces today.",
        }),
    )
    .await;
    public_post(
        &h,
        &"3".repeat(32),
        &json!({
            "schema": 1, "report_type": "request", "created_unix": 1,
            "app": {"id": "clip", "version": "0.3"},
            "title": "Dark mode please",
            "want": "A dark theme for the panel.",
            "notes": "Working at night with a bright panel hurts my eyes.",
        }),
    )
    .await;

    let crashes = admin(&h, get("/admin/?status=all&kind=crash")).await.body;
    assert!(crashes.contains("a crash happened"), "{crashes}");
    assert!(!crashes.contains("Panel flickers on switch"), "{crashes}");
    assert!(!crashes.contains("Dark mode please"), "{crashes}");

    let manual = admin(&h, get("/admin/?status=all&kind=manual")).await.body;
    assert!(manual.contains("Panel flickers on switch"), "{manual}");
    assert!(!manual.contains("a crash happened"), "{manual}");

    let requests = admin(&h, get("/admin/?status=all&kind=request")).await.body;
    assert!(requests.contains("Dark mode please"), "{requests}");
    assert!(!requests.contains("a crash happened"), "{requests}");
}

#[tokio::test]
async fn release_targets_and_confirmations_flow_to_public_status() {
    let h = harness(true);
    let (_, posted) = public_post(
        &h,
        &"1".repeat(32),
        &crash("clip::run", "boom", "bar", "1.3"),
    )
    .await;
    let receipt = posted["receipt"].as_str().unwrap().to_string();
    let id = h.st.db.clusters().unwrap()[0].id;
    let target = |channel: &str, version: &str| {
        post_form(
            &format!("/admin/clusters/{id}/release-target"),
            &format!("channel={channel}&version={version}"),
            &bearer(),
        )
    };
    let confirm = |channel: &str, version: &str| {
        post_form(
            &format!("/admin/clusters/{id}/release-confirmed"),
            &format!("channel={channel}&version={version}"),
            &bearer(),
        )
    };

    // No releases tracked yet: no releases field in public status.
    let (_, before) = public_post(
        &h,
        &"2".repeat(32),
        &crash("clip::run", "boom", "bar", "1.3"),
    )
    .await;
    let _ = before;
    let status = public_status(&h, &receipt).await;
    assert!(status.get("releases").is_none(), "{status}");

    // Confirming before planning is refused; bad channels and bad ordering too.
    assert_eq!(
        admin(&h, confirm("beta", "1.4-beta1")).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        admin(&h, target("nightly", "1.4")).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        admin(&h, target("beta", "1.4-beta1")).await.status,
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        admin(&h, target("stable", "1.3")).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        admin(&h, target("stable", "1.4")).await.status,
        StatusCode::SEE_OTHER
    );

    // Planned but unshipped on both channels.
    assert_eq!(
        public_status(&h, &receipt).await,
        json!({
            "status": "duplicate",
            "releases": {
                "beta": {"planned": "1.4-beta1", "shipped": false},
                "stable": {"planned": "1.4", "shipped": false},
            },
        })
    );

    // Confirm beta: shipped with the confirmed version named.
    assert_eq!(
        admin(&h, confirm("beta", "1.4-beta2")).await.status,
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        public_status(&h, &receipt).await,
        json!({
            "status": "duplicate",
            "releases": {
                "beta": {"planned": "1.4-beta1", "shipped": true, "shipped_in": "1.4-beta2"},
                "stable": {"planned": "1.4", "shipped": false},
            },
        })
    );
    // The detail page shows the same plan.
    let page = admin(&h, get(&format!("/admin/clusters/{id}"))).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(
        page.body.contains("1.4-beta1") && page.body.contains("shipped 1.4-beta2"),
        "{}",
        page.body
    );
}

#[tokio::test]
async fn singleton_cluster_exposes_release_plan() {
    let h = harness(true);
    let (_, posted) = public_post(
        &h,
        &"3".repeat(32),
        &crash("clip::run", "boom", "bar", "1.3"),
    )
    .await;
    let receipt = posted["receipt"].as_str().unwrap().to_string();
    let id = h.st.db.clusters().unwrap()[0].id;
    // One report only: still "received", but a planned release must show.
    let status = public_status(&h, &receipt).await;
    assert_eq!(status["status"], "received");
    assert!(status.get("releases").is_none(), "{status}");
    assert_eq!(
        admin(
            &h,
            post_form(
                &format!("/admin/clusters/{id}/release-target"),
                "channel=beta&version=1.4-beta1",
                &bearer(),
            )
        )
        .await
        .status,
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        public_status(&h, &receipt).await,
        json!({
            "status": "received",
            "releases": {
                "beta": {"planned": "1.4-beta1", "shipped": false},
                "stable": {"planned": null, "shipped": false},
            },
        })
    );
}

async fn public_status(h: &H, receipt: &str) -> Value {
    let resp = public_router(h.st.clone())
        .oneshot(
            Request::builder()
                .uri(format!("/v1/reports/{receipt}/status"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let b = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&b).unwrap()
}
