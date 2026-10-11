use super::*;
use serde_json::json;

fn report(v: serde_json::Value) -> Report {
    let mut base = json!({
        "schema": 1, "report_type": "crash", "created_unix": 1,
        "app": {"id": "clip", "version": "0.3.1"}
    });
    for (k, val) in v.as_object().unwrap() {
        base[k] = val.clone();
    }
    serde_json::from_value(base).unwrap()
}

fn panic_marker(frames: serde_json::Value, loc: &str, msg: &str) -> serde_json::Value {
    json!({"markers": [{"t": 1, "kind": "panic", "message": msg, "location": loc, "frames": frames}]})
}

#[test]
fn symbols_are_normalized() {
    assert_eq!(
        normalize_symbol("clip::sync::run::h0123456789abcdef"),
        "clip::sync::run"
    );
    assert_eq!(
        normalize_symbol("alloc::vec::Vec<T,A>::push::h0123456789abcdef"),
        "alloc::vec::Vec::push"
    );
    assert_eq!(
        normalize_symbol("<clip::Foo as core::fmt::Debug>::fmt"),
        "fmt"
    );
    assert_eq!(
        normalize_symbol("clip::run::{{closure}}"),
        "clip::run::{closure}"
    );
    assert_eq!(
        normalize_symbol("clip::run::{closure#12}"),
        "clip::run::{closure}"
    );
    assert_eq!(normalize_symbol("not_a_hash::habc"), "not_a_hash::habc");
}

#[test]
fn noise_frames_are_recognised() {
    for n in [
        "core::panicking::panic",
        "std::rt::lang_start",
        "rust_begin_unwind",
        "_start",
        "g_main_context_iterate",
    ] {
        assert!(is_noise(n), "{n}");
    }
    assert!(!is_noise("clip::sync::run"));
}

#[test]
fn locations_lose_home_versions_but_keep_panic_sites() {
    assert_eq!(
        normalize_location("<HOME>/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.40.0/src/rt.rs:42:5"),
        "tokio/src/rt.rs:42:5"
    );
    assert_eq!(
        normalize_location("<HOME>/Projects/breadclip/src/main.rs:7:1"),
        "breadclip/src/main.rs:7:1"
    );
}

#[test]
fn messages_drop_numbers_and_markers() {
    assert_eq!(
        normalize_message("index 12 out of range for len 3 at <HOME>/x"),
        "index # out of range for len # at /x"
    );
    assert_eq!(normalize_message("  a   b  "), "a b");
    assert_eq!(normalize_message(&"x".repeat(500)).len(), 120);
}

#[test]
fn same_bug_across_versions_and_machines_gets_the_same_fingerprint() {
    let a = report(panic_marker(
        json!([
            {"symbol": "core::panicking::panic::h1111111111111111"},
            {"symbol": "clip::sync::run::h2222222222222222", "offset": 4660},
            {"symbol": "clip::main::h3333333333333333", "offset": 10}
        ]),
        "<HOME>/Projects/breadclip/src/sync.rs:42:13",
        "called `Option::unwrap()` on a `None` value",
    ));
    let b = report(panic_marker(
        json!([
            {"symbol": "core::panicking::panic::haaaaaaaaaaaaaaaa"},
            {"symbol": "clip::sync::run::hbbbbbbbbbbbbbbbb", "offset": 9999},
            {"symbol": "clip::main::hcccccccccccccccc", "offset": 77}
        ]),
        "<HOME>/other/breadclip/src/sync.rs:42:13",
        "called `Option::unwrap()` on a `None` value",
    ));
    let fa = fingerprint(&a).unwrap();
    assert_eq!(fa.key, fingerprint(&b).unwrap().key);
    assert_eq!(fa.key.len(), 32);
}

#[test]
fn different_bugs_get_different_fingerprints() {
    let base = |sym: &str, msg: &str, app: &str| {
        let mut r = report(panic_marker(
            json!([{"symbol": sym}]),
            "breadclip/src/a.rs:1:1",
            msg,
        ));
        r.app.id = app.into();
        fingerprint(&r).unwrap().key
    };
    let k = base("clip::a", "boom", "clip");
    assert_ne!(k, base("clip::b", "boom", "clip"));
    assert_ne!(k, base("clip::a", "other", "clip"));
    assert_ne!(k, base("clip::a", "boom", "pad"));
}

#[test]
fn unsymbolicated_frames_fall_back_to_module_and_offset() {
    let r = report(panic_marker(
        json!([{"build_id": "abc", "module": "/usr/bin/breadclip", "offset": 4660}]),
        "",
        "boom",
    ));
    let f = fingerprint(&r).unwrap();
    let r2 = report(panic_marker(
        json!([{"build_id": "abc", "module": "/opt/breadclip", "offset": 4660}]),
        "",
        "boom",
    ));
    assert_eq!(
        f.key,
        fingerprint(&r2).unwrap().key,
        "module path does not matter"
    );
    let r3 = report(panic_marker(
        json!([{"build_id": "abc", "module": "breadclip", "offset": 4661}]),
        "",
        "boom",
    ));
    assert_ne!(f.key, fingerprint(&r3).unwrap().key);
    let other_build = report(panic_marker(
        json!([{"build_id": "def", "module": "breadclip", "offset": 4660}]),
        "",
        "boom",
    ));
    assert_ne!(f.key, fingerprint(&other_build).unwrap().key);
    let unknown_build = report(panic_marker(
        json!([{"module": "breadclip", "offset": 4660}]),
        "",
        "boom",
    ));
    assert!(fingerprint(&unknown_build).is_none());
}

#[test]
fn separate_panic_sites_in_same_function_remain_separate() {
    let key = |location| {
        fingerprint(&report(panic_marker(
            json!([{"symbol": "clip::sync::run"}]),
            location,
            "boom",
        )))
        .unwrap()
        .key
    };
    assert_ne!(key("src/sync.rs:42:5"), key("src/sync.rs:43:5"));
    assert_ne!(key("src/sync.rs:42:5"), key("src/sync.rs:42:17"));
}

#[test]
fn only_the_top_frames_count() {
    let frames = |tail: &str| {
        let mut v: Vec<_> = (0..TOP_FRAMES)
            .map(|i| json!({"symbol": format!("clip::f{i}")}))
            .collect();
        v.push(json!({"symbol": tail}));
        json!(v)
    };
    let a = fingerprint(&report(panic_marker(frames("clip::x"), "", "m"))).unwrap();
    let b = fingerprint(&report(panic_marker(frames("clip::y"), "", "m"))).unwrap();
    assert_eq!(a.key, b.key);
}

#[test]
fn freeze_uses_the_live_stack_and_no_evidence_means_no_fingerprint() {
    let r = report(json!({
        "report_type": "freeze",
        "markers": [{"t": 1, "kind": "freeze", "message": "no heartbeat for 20s"}],
        "live_stack": [{"symbol": "__poll"}, {"symbol": "clip::clipboard::wait_for_selection"}]
    }));
    let f = fingerprint(&r).unwrap();
    assert!(f.title.contains("clip::clipboard::wait_for_selection"));
    assert!(fingerprint(&report(
        json!({"report_type": "freeze", "markers": [{"t":1,"kind":"freeze"}]})
    ))
    .is_none());
    assert!(fingerprint(&report(json!({"report_type": "behavior"}))).is_none());
}

#[test]
fn title_prefers_the_message() {
    let r = report(panic_marker(
        json!([{"symbol": "clip::a"}]),
        "",
        "index 5 out of range",
    ));
    assert_eq!(fingerprint(&r).unwrap().title, "index # out of range");
}
