//! Intake with symbolication, using a real binary with debug info.

use std::path::Path;
use std::process::Command;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use breadbug_server::app::{public_router, AppState};
use breadbug_server::config::Config;
use breadbug_server::crypto::sha256_hex;
use breadbug_server::db::Db;
use http_body_util::BodyExt;
use object::{Object, ObjectSymbol};
use serde_json::{json, Value};
use tower::ServiceExt;

#[ctor::ctor]
fn enter_symbol_worker() {
    if breadbug_server::symbol_worker_entry() {
        std::process::exit(0);
    }
}

fn build_fixture(dir: &Path) -> (std::path::PathBuf, String, u64) {
    if let Ok(worker) = std::env::current_exe() {
        std::env::set_var("BREADBUG_SYMBOL_WORKER_BIN", worker);
    }
    let src = dir.join("fixture.rs");
    std::fs::write(
        &src,
        "#[no_mangle] #[inline(never)] pub extern \"C\" fn target_fn(x: u32) -> u32 { std::hint::black_box(x) + 1 }\nfn main() { std::process::exit(target_fn(1) as i32 & 0); }\n",
    )
    .unwrap();
    let bin = dir.join("fixture");
    assert!(Command::new("rustc")
        .args([
            "-g",
            "-C",
            "opt-level=0",
            "-C",
            "link-arg=-Wl,--build-id",
            "-o"
        ])
        .arg(&bin)
        .arg(&src)
        .status()
        .unwrap()
        .success());
    let data = std::fs::read(&bin).unwrap();
    let file = object::File::parse(&*data).unwrap();
    let id: String = file
        .build_id()
        .unwrap()
        .unwrap()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let addr = file
        .symbols()
        .find(|s| s.name() == Ok("target_fn"))
        .unwrap()
        .address();
    (bin, id, addr)
}

async fn post(state: &std::sync::Arc<AppState>, install: &str, v: &Value) -> (StatusCode, Value) {
    let body = serde_json::to_vec(v).unwrap();
    let req = Request::builder()
        .method("POST")
        .uri("/v1/reports")
        .header("x-breadbug-install", install)
        .header("x-breadbug-sha256", sha256_hex(&body))
        .body(Body::from(body))
        .unwrap();
    let resp = public_router(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn crash_with(frame: Value) -> Value {
    json!({
        "schema": 1, "report_type": "crash", "created_unix": 1,
        "app": {"id": "clip", "version": "0.3"},
        "markers": [{"t": 1, "kind": "panic", "message": "boom", "frames": [frame]}]
    })
}

fn state(dir: &Path, symbols: &Path) -> std::sync::Arc<AppState> {
    let cfg = Config {
        data_dir: dir.to_path_buf(),
        symbol_dir: Some(symbols.to_path_buf()),
        per_install_per_hour: 100,
        ..Config::default()
    };
    AppState::new(cfg, Db::open_memory().unwrap(), vec![1u8; 32])
}

#[tokio::test]
async fn unsymbolicated_frames_are_resolved_and_group_with_client_side_symbols() {
    let work = tempfile::tempdir().unwrap();
    let (bin, id, addr) = build_fixture(work.path());
    let syms = tempfile::tempdir().unwrap();
    let dest = syms.path().join(&id[..2]);
    std::fs::create_dir_all(&dest).unwrap();
    std::fs::copy(&bin, dest.join(format!("{id}.debug"))).unwrap();
    let data = tempfile::tempdir().unwrap();
    let st = state(data.path(), syms.path());

    // A stripped client sends only build-id + offset.
    let (s1, r1) = post(
        &st,
        &"1".repeat(32),
        &crash_with(json!({"module": "clip", "offset": addr + 4, "build_id": id})),
    )
    .await;
    assert_eq!(s1, StatusCode::CREATED, "{r1}");
    let raw: Value = serde_json::from_str(
        &st.db
            .raw_of(r1["receipt"].as_str().unwrap())
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    let frame = &raw["markers"][0]["frames"][0];
    assert!(
        frame["symbol"].as_str().unwrap().contains("target_fn"),
        "{frame}"
    );
    assert!(frame["file"].as_str().unwrap().ends_with("fixture.rs"));

    // Another user's client already had the symbol; both land in one cluster.
    let sym = frame["symbol"].as_str().unwrap().to_string();
    let (s2, r2) = post(&st, &"2".repeat(32), &crash_with(json!({"symbol": sym}))).await;
    assert_eq!(s2, StatusCode::CREATED);
    let c1 = st.db.cluster_of(r1["receipt"].as_str().unwrap()).unwrap();
    let c2 = st.db.cluster_of(r2["receipt"].as_str().unwrap()).unwrap();
    assert!(c1.is_some());
    assert_eq!(c1, c2);
}

#[tokio::test]
async fn missing_symbols_are_recorded_and_the_report_still_stored() {
    let syms = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let st = state(data.path(), syms.path());
    let frame = json!({"module": "clip", "offset": 4660, "build_id": "aabbccddeeff0011"});
    for i in 0..2 {
        let mut v = crash_with(frame.clone());
        v["created_unix"] = json!(i + 1);
        let (status, _) = post(&st, &format!("{i:032x}"), &v).await;
        assert_eq!(status, StatusCode::CREATED);
    }
    let missing = st.db.missing_symbols().unwrap();
    assert_eq!(
        missing,
        vec![(
            "aabbccddeeff0011".into(),
            "clip".into(),
            Some("0.3".into()),
            2
        )]
    );
    assert_eq!(st.db.report_count().unwrap(), 2);
}

#[tokio::test]
async fn hostile_build_ids_never_touch_the_filesystem() {
    let syms = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let st = state(data.path(), syms.path());
    for (i, bad) in ["../../../../etc/passwd", "AA/../..", "", "zz"]
        .iter()
        .enumerate()
    {
        let (status, _) = post(
            &st,
            &format!("{i:032x}"),
            &crash_with(json!({"offset": 1, "build_id": bad})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{bad}");
    }
    assert!(st.db.missing_symbols().unwrap().is_empty());
}
