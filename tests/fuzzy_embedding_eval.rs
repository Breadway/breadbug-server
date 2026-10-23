//! Quality gate for a real embedding backend. Ignored by default because it
//! needs the local service; CI has no model. Run it before trusting a new
//! model or threshold:
//!
//! ```sh
//! BREADBUG_EVAL_EMBED_URL=http://127.0.0.1:8181/embed \
//! BREADBUG_EVAL_THRESHOLD=0.50 \
//!   cargo test --test fuzzy_embedding_eval -- --ignored --nocapture
//! ```
//!
//! The first fixture was written alongside the built-in hashing embedder and
//! flatters it. The second was written against the symptom, with synonyms and
//! hard negatives, and is the number that matters.

use std::env;

use breadbug_server::embed::{cosine, Embedder, HttpEmbedder};
use serde_json::Value;

const V1: &str = include_str!("fixtures/fuzzy_eval.json");
const V2: &str = include_str!("fixtures/fuzzy_eval_v2.json");

struct Metrics {
    precision: f64,
    recall: f64,
    same_min: f32,
    same_max: f32,
    diff_max: f32,
}

fn measure(raw: &str, e: &dyn Embedder, threshold: f32) -> Metrics {
    let v: Value = serde_json::from_str(raw).unwrap();
    let mut items = Vec::new();
    for (gi, g) in v["groups"].as_array().unwrap().iter().enumerate() {
        for t in g["texts"].as_array().unwrap() {
            items.push((gi, e.embed(t.as_str().unwrap()).unwrap()));
        }
    }
    let (mut tp, mut fp, mut fn_, mut same_min, mut same_max, mut diff_max) =
        (0u32, 0u32, 0u32, f32::MAX, f32::MIN, f32::MIN);
    for i in 0..items.len() {
        for j in i + 1..items.len() {
            let same = items[i].0 == items[j].0;
            let s = cosine(&items[i].1, &items[j].1);
            if same {
                same_min = same_min.min(s);
                same_max = same_max.max(s);
            } else {
                diff_max = diff_max.max(s);
            }
            match (same, s >= threshold) {
                (true, true) => tp += 1,
                (false, true) => fp += 1,
                (true, false) => fn_ += 1,
                _ => {}
            }
        }
    }
    Metrics {
        precision: f64::from(tp) / f64::from(tp + fp).max(1.0),
        recall: f64::from(tp) / f64::from(tp + fn_).max(1.0),
        same_min,
        same_max,
        diff_max,
    }
}

#[test]
#[ignore = "needs a local embedding service"]
fn configured_embedder_separates_paraphrases_from_other_reports() {
    let url = env::var("BREADBUG_EVAL_EMBED_URL").expect("BREADBUG_EVAL_EMBED_URL");
    let threshold: f32 = env::var("BREADBUG_EVAL_THRESHOLD")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.50);
    let model = env::var("BREADBUG_EVAL_EMBED_MODEL").unwrap_or_else(|_| "eval".into());
    let e = HttpEmbedder::new(&url, &model).expect("local embedding service");

    for (name, raw) in [("v1", V1), ("v2", V2)] {
        let m = measure(raw, &e, threshold);
        eprintln!(
            "{name} @ {threshold:.2}: precision {:.2}, recall {:.2} \
             (same {:.2}..{:.2}, different max {:.2})",
            m.precision, m.recall, m.same_min, m.same_max, m.diff_max
        );
        assert!(
            m.precision >= 0.90,
            "{name}: precision {:.2} below 0.90",
            m.precision
        );
        assert!(
            m.recall >= 0.55,
            "{name}: recall {:.2} below 0.55",
            m.recall
        );
    }
}
