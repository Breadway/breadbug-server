//! Fuzzy clustering: quality on a labeled set, and behavior through intake.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use breadbug_server::app::{public_router, AppState};
use breadbug_server::cluster::{reembed_all, reembed_cluster, reembed_stale};
use breadbug_server::config::Config;
use breadbug_server::crypto::sha256_hex;
use breadbug_server::db::Db;
use breadbug_server::embed::{cosine, Embedder, HashEmbedder};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

const EVAL: &str = include_str!("fixtures/fuzzy_eval.json");

#[test]
fn quality_on_the_labeled_set_meets_the_bar() {
    let v: Value = serde_json::from_str(EVAL).unwrap();
    let threshold = Config::default().fuzzy_threshold;
    let e = HashEmbedder;
    let mut items = Vec::new();
    for (gi, g) in v["groups"].as_array().unwrap().iter().enumerate() {
        for t in g["texts"].as_array().unwrap() {
            items.push((gi, e.embed(t.as_str().unwrap()).unwrap()));
        }
    }
    let (mut tp, mut fp, mut fn_) = (0u32, 0u32, 0u32);
    for i in 0..items.len() {
        for j in i + 1..items.len() {
            let same = items[i].0 == items[j].0;
            let hit = cosine(&items[i].1, &items[j].1) >= threshold;
            match (same, hit) {
                (true, true) => tp += 1,
                (false, true) => fp += 1,
                (true, false) => fn_ += 1,
                _ => {}
            }
        }
    }
    let precision = f64::from(tp) / f64::from(tp + fp).max(1.0);
    let recall = f64::from(tp) / f64::from(tp + fn_).max(1.0);
    eprintln!("threshold {threshold}: precision {precision:.2}, recall {recall:.2} (tp {tp}, fp {fp}, fn {fn_})");
    assert!(precision >= 0.95, "precision {precision}");
    assert!(recall >= 0.65, "recall {recall}");
}

fn state(edit: impl FnOnce(&mut Config)) -> (Arc<AppState>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config {
        data_dir: dir.path().to_path_buf(),
        per_install_per_hour: 1000,
        per_network_per_hour: 1000,
        ..Config::default()
    };
    edit(&mut cfg);
    (
        AppState::new(cfg, Db::open_memory().unwrap(), vec![3u8; 32]),
        dir,
    )
}

async fn send(st: &Arc<AppState>, n: usize, app: &str, kind: &str, notes: &str) -> String {
    let v = json!({
        "schema": 1, "report_type": kind, "created_unix": 1,
        "app": {"id": app, "version": "0.3"},
        "notes": notes
    });
    let body = serde_json::to_vec(&v).unwrap();
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

#[tokio::test]
async fn paraphrased_behavior_reports_cluster_and_unrelated_ones_do_not() {
    let (st, _d) = state(|_| {});
    let a1 = send(
        &st,
        1,
        "clip",
        "behavior",
        "clipboard hangs when I paste a large image",
    )
    .await;
    let a2 = send(
        &st,
        2,
        "clip",
        "behavior",
        "pasting a big image from the clipboard freezes everything for a while",
    )
    .await;
    let b1 = send(
        &st,
        3,
        "clip",
        "behavior",
        "lock screen rejects the correct password sometimes",
    )
    .await;
    let c = |r: &str| st.db.cluster_of(r).unwrap().unwrap();
    assert_eq!(c(&a1), c(&a2));
    assert_ne!(c(&a1), c(&b1));
    let cluster = st.db.cluster(c(&a1)).unwrap().unwrap();
    assert_eq!((cluster.count, cluster.installs), (2, 2));
    assert!(cluster.fingerprint.is_none());
    assert_eq!(cluster.kind, "behavior");
    assert_eq!(cluster.title, "clipboard hangs when I paste a large image");
}

#[tokio::test]
async fn fuzzy_matching_never_crosses_apps_or_kinds() {
    let (st, _d) = state(|_| {});
    let text = "clipboard hangs when I paste a large image";
    let a = send(&st, 1, "clip", "behavior", text).await;
    let other_app = send(&st, 2, "pad", "behavior", text).await;
    let other_kind = send(&st, 3, "clip", "freeze", text).await;
    let c = |r: &str| st.db.cluster_of(r).unwrap().unwrap();
    assert_ne!(c(&a), c(&other_app));
    assert_ne!(c(&a), c(&other_kind));
}

#[tokio::test]
async fn reports_with_too_little_text_stay_unclustered() {
    let (st, _d) = state(|_| {});
    let r = send(&st, 1, "clip", "behavior", "it broke").await;
    assert_eq!(st.db.cluster_of(&r).unwrap(), None);
}

#[tokio::test]
async fn threshold_is_configurable() {
    let (st, _d) = state(|c| c.fuzzy_threshold = 0.99);
    let a = send(
        &st,
        1,
        "clip",
        "behavior",
        "clipboard hangs when I paste a large image",
    )
    .await;
    let b = send(
        &st,
        2,
        "clip",
        "behavior",
        "pasting a large image makes the clipboard hang",
    )
    .await;
    assert_ne!(st.db.cluster_of(&a).unwrap(), st.db.cluster_of(&b).unwrap());
}

#[tokio::test]
async fn merging_folds_the_moved_wording_into_the_survivor() {
    let (st, _d) = state(|_| {});
    let x = send(
        &st,
        1,
        "pad",
        "behavior",
        "notes written in the scratchpad vanish after closing it",
    )
    .await;
    let z = send(
        &st,
        2,
        "pad",
        "behavior",
        "text typed into the scratchpad is gone when it is closed and reopened",
    )
    .await;
    let cx = st.db.cluster_of(&x).unwrap().unwrap();
    let cz = st.db.cluster_of(&z).unwrap().unwrap();
    assert_ne!(cx, cz, "below the threshold, so they start apart");

    assert!(st.db.merge_clusters(cz, cx).unwrap());
    reembed_cluster(&st.db, &HashEmbedder, cx).unwrap();

    // Same wording as the merged-away report: it must join the survivor
    // instead of starting yet another cluster.
    let again = send(
        &st,
        3,
        "pad",
        "behavior",
        "text typed into the scratchpad is gone when it is closed and reopened",
    )
    .await;
    assert_eq!(st.db.cluster_of(&again).unwrap(), Some(cx));
}

#[tokio::test]
async fn a_model_switch_reembeds_only_stale_clusters() {
    let (st, _d) = state(|_| {});
    send(
        &st,
        1,
        "clip",
        "behavior",
        "clipboard hangs when I paste a large image",
    )
    .await;
    assert_eq!(
        st.db
            .stale_fuzzy_cluster_ids("hash-v1-256")
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        st.db.stale_fuzzy_cluster_ids("other-v2").unwrap().len(),
        1
    );
    assert_eq!(reembed_stale(&st.db, &Other).unwrap(), 1);
    assert_eq!(
        st.db.stale_fuzzy_cluster_ids("other-v2").unwrap().len(),
        0
    );
    assert_eq!(reembed_stale(&st.db, &Other).unwrap(), 0);
}

struct Other;
impl Embedder for Other {
    fn model(&self) -> &str {
        "other-v2"
    }
    fn embed(&self, text: &str) -> anyhow::Result<Vec<f32>> {
        HashEmbedder.embed(&format!("{text} {text}"))
    }
}

#[tokio::test]
async fn changing_the_model_does_not_mix_vector_spaces_and_reembed_fixes_it() {
    let (st, _d) = state(|_| {});
    let a = send(
        &st,
        1,
        "clip",
        "behavior",
        "clipboard hangs when I paste a large image",
    )
    .await;
    let cid = st.db.cluster_of(&a).unwrap().unwrap();
    // Vectors from a different model are never candidates.
    assert!(st
        .db
        .fuzzy_candidates("clip", "behavior", "other-v2")
        .unwrap()
        .is_empty());
    assert_eq!(
        st.db
            .fuzzy_candidates("clip", "behavior", "hash-v1-256")
            .unwrap()
            .len(),
        1
    );
    assert_eq!(reembed_all(&st.db, &Other).unwrap(), 1);
    assert!(st
        .db
        .fuzzy_candidates("clip", "behavior", "hash-v1-256")
        .unwrap()
        .is_empty());
    let after = st
        .db
        .fuzzy_candidates("clip", "behavior", "other-v2")
        .unwrap();
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].0, cid);
}
