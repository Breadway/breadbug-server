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
fn stopped_marker_is_accepted_and_round_trips() {
    let mut v = minimal();
    v["report_type"] = json!("freeze");
    v["markers"] = json!([
        { "t": 10, "kind": "freeze", "message": "no heartbeat for 20s" },
        { "t": 30, "kind": "stopped" }
    ]);
    let report = parse(&v).expect("a stopped marker must not reject the report");
    assert_eq!(report.markers[1].kind, MarkerKind::Stopped);
    let wire = serde_json::to_value(&report).unwrap();
    assert_eq!(wire["markers"][1]["kind"], json!("stopped"));
    let again = Report::parse(&serde_json::to_vec(&wire).unwrap(), 2000).unwrap();
    assert_eq!(again.markers[1].kind, MarkerKind::Stopped);
}

#[test]
fn unknown_marker_kind_is_still_rejected() {
    let mut v = minimal();
    v["markers"] = json!([{ "t": 1, "kind": "lingering" }]);
    let err = parse(&v).expect_err("an unknown marker kind must still be rejected");
    assert!(err.contains("unknown variant"), "{err}");
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

fn manual() -> Value {
    json!({
        "schema": 1,
        "report_type": "manual",
        "created_unix": 1000,
        "app": { "id": "clip", "version": "0.3.1" },
        "title": "Panel flickers on workspace switch",
        "notes": "The top panel flickers for a second whenever I switch workspaces."
    })
}

#[test]
fn manual_report_needs_title_and_description() {
    assert!(parse(&manual()).is_ok());
    for (path, val) in [
        ("title", json!(null)),
        ("title", json!("   ")),
        ("title", json!("x".repeat(MAX_TITLE + 1))),
        ("notes", json!(null)),
        ("notes", json!("  ")),
    ] {
        let mut v = manual();
        v[path] = val;
        assert!(parse(&v).is_err(), "{path}");
    }
}

#[test]
fn title_is_only_for_manual_reports() {
    let mut v = minimal();
    v["title"] = json!("sneaky");
    assert!(parse(&v).is_err());
    let mut v = minimal();
    v["want"] = json!("sneaky");
    assert!(parse(&v).is_err());
    let mut v = manual();
    v["want"] = json!("sneaky");
    assert!(parse(&v).is_err());
}

fn request() -> Value {
    json!({
        "schema": 1,
        "report_type": "request",
        "created_unix": 1000,
        "app": { "id": "clip", "version": "0.3.1" },
        "title": "Dark mode for the panel",
        "want": "A dark theme option for the top panel.",
        "notes": "I work at night and the bright panel hurts my eyes."
    })
}

#[test]
fn feature_request_needs_title_want_and_why() {
    assert!(parse(&request()).is_ok());
    for (path, val) in [
        ("title", json!(null)),
        ("title", json!("  ")),
        ("want", json!(null)),
        ("want", json!(" ")),
        ("notes", json!(null)),
        ("notes", json!("")),
    ] {
        let mut v = request();
        v[path] = val;
        assert!(parse(&v).is_err(), "{path}");
    }
}
