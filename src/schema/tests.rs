use super::*;
use serde_json::json;

pub fn minimal() -> Value {
    json!({
        "schema": 1,
        "report_type": "crash",
        "created_unix": 1000,
        "app": { "id": "clip", "version": "0.3.1", "build_id": null }
    })
}

fn parse(v: &Value) -> Result<Report, String> {
    Report::parse(&serde_json::to_vec(v).unwrap(), 2000)
}

#[test]
fn minimal_report_is_valid() {
    assert!(parse(&minimal()).is_ok());
}

#[test]
fn unknown_fields_are_rejected_at_every_level() {
    let mut v = minimal();
    v["extra"] = json!(1);
    assert!(parse(&v).is_err());
    let mut v = minimal();
    v["app"]["secret"] = json!("x");
    assert!(parse(&v).is_err());
    let mut v = minimal();
    v["markers"] = json!([{ "t": 1, "kind": "panic", "frames": [{ "offset": 1, "evil": true }] }]);
    assert!(parse(&v).is_err());
}

#[test]
fn bad_types_and_values_are_rejected() {
    for (path, val) in [
        ("schema", json!(2)),
        ("report_type", json!("explosion")),
        ("created_unix", json!(10_000_000_000u64)),
        ("app", json!({ "id": "../x" })),
        ("app", json!({ "id": "Clip" })),
    ] {
        let mut v = minimal();
        v[path] = val;
        assert!(parse(&v).is_err(), "{path}");
    }
}

#[test]
fn size_limits_apply() {
    let long = "x".repeat(MAX_STR + 1);
    let mut v = minimal();
    v["notes"] = json!(long);
    assert!(parse(&v).is_err());
    let mut v = minimal();
    v["logs"] = json!((0..MAX_LOGS + 1)
        .map(|i| json!({"t": i, "level": "INFO", "msg": "x"}))
        .collect::<Vec<_>>());
    assert!(parse(&v).is_err());
    let mut v = minimal();
    v["markers"] = json!([{ "t": 1, "kind": "panic", "frames": vec![json!({}); MAX_FRAMES + 1] }]);
    assert!(parse(&v).is_err());
}

#[test]
fn event_data_is_bounded() {
    let mut deep = json!("x");
    for _ in 0..20 {
        deep = json!([deep]);
    }
    let mut v = minimal();
    v["events"] = json!([{ "t": 1, "name": "bread.x", "data": deep }]);
    assert!(parse(&v).is_err());
    let wide: serde_json::Map<String, Value> =
        (0..100).map(|i| (format!("k{i}"), json!(i))).collect();
    let mut v = minimal();
    v["events"] = json!([{ "t": 1, "name": "bread.x", "data": wide }]);
    assert!(parse(&v).is_err());
}

#[test]
fn garbage_is_an_error_not_a_panic() {
    for body in [
        &b""[..],
        b"{",
        b"[]",
        b"null",
        b"\xff\xfe",
        b"{\"schema\":1}",
    ] {
        assert!(Report::parse(body, 2000).is_err());
    }
}

#[test]
fn app_id_rules() {
    assert!(valid_app_id("clip"));
    assert!(valid_app_id("a-b_c9"));
    for bad in ["", "9a", "A", "a b", "a/b", &"x".repeat(33)] {
        assert!(!valid_app_id(bad), "{bad:?}");
    }
}
