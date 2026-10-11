use super::*;

#[test]
fn versions_order_sensibly() {
    use Ordering::*;
    let cases = [
        ("0.3.1", "0.3.22", Less),
        ("0.9.1-dev.20260929181236+4774581", "0.9.1", Less),
        ("0.9.1", "0.9.2-dev.2026", Less),
        ("0.9.1-dev.20260929", "0.9.1-dev.20261001", Less),
        ("1.0.0", "0.99.99", Greater),
        ("0.3", "0.3.0", Equal),
        ("0.4.0-rc.1", "0.4.0", Less),
    ];
    for (a, b, want) in cases {
        assert_eq!(version_cmp(a, b), want, "{a} vs {b}");
        assert_eq!(version_cmp(b, a), want.reverse(), "{b} vs {a}");
    }
}

#[test]
fn prerelease_stages_order_dev_beta_rc_release() {
    use Ordering::*;
    let cases = [
        ("1.4-dev.20260101", "1.4-beta1", Less),
        ("1.4-beta1", "1.4-rc.1", Less),
        ("1.4-rc.1", "1.4", Less),
        ("1.4-dev.20260101", "1.4-rc.1", Less),
        ("1.4-dev.2", "1.4-dev.1", Greater),
        ("1.4-rc.1", "1.4-rc.2", Less),
        ("1.4", "1.5-dev.1", Less),
        // Build metadata never affects precedence.
        ("1.4+build9", "1.4", Equal),
        ("1.4-rc.1+meta", "1.4-rc.1", Equal),
        ("1.4-dev.1+aaa", "1.4-dev.1+bbb", Equal),
    ];
    for (a, b, want) in cases {
        assert_eq!(version_cmp(a, b), want, "{a} vs {b}");
        assert_eq!(version_cmp(b, a), want.reverse(), "{b} vs {a}");
    }
}

#[test]
fn version_syntax_is_checked() {
    assert!(valid_version("1.4"));
    assert!(valid_version("1.4-dev.20260101+build"));
    assert!(!valid_version(""));
    assert!(!valid_version("v1.4"));
    assert!(!valid_version("1.4 marked"));
    assert!(!valid_version("1.4\ninjected"));
    assert!(!valid_version("**1.4**"));
}

#[test]
fn priority_thresholds() {
    assert_eq!(priority_for(20), "low");
    assert_eq!(priority_for(100), "medium");
    assert_eq!(priority_for(110), "high");
    assert_eq!(priority_for(200), "urgent");
}

#[test]
fn growth_notifications_double() {
    assert!(!is_power_of_two_growth(3, 1));
    assert!(is_power_of_two_growth(4, 1));
    assert!(is_power_of_two_growth(4, 2));
    assert!(!is_power_of_two_growth(5, 4));
    assert!(is_power_of_two_growth(8, 4));
}

#[test]
fn evidence_is_compact_and_flat() {
    let raw = serde_json::json!({
        "notes": "it  broke\nbadly",
        "markers": [{"t":1,"kind":"panic","message":"boom\nmultiline","frames":[
            {"symbol":"clip::run","file":"clip/src/a.rs","line":4},{"module":"clip","offset":4096}]}]
    })
    .to_string();
    let e = evidence(&raw);
    assert!(e.contains("panic: boom multiline"));
    assert!(e.contains("clip::run (clip/src/a.rs:4)"));
    assert!(e.contains("clip+0x1000"));
    assert!(e.contains("user note: it broke badly"));
    assert_eq!(evidence("not json"), "");
}

#[test]
fn notice_text_names_app_version_and_stage_per_kind() {
    use crate::db::ClusterRow;
    let mut c = ClusterRow {
        id: 1,
        app: "bar".into(),
        kind: "crash".into(),
        fingerprint: None,
        title: "t".into(),
        status: "promoted".into(),
        first_seen: 0,
        last_seen: 0,
        count: 2,
        installs: 2,
        versions: Default::default(),
        os_builds: Default::default(),
        fixed_in: None,
        issue_key: None,
        issue_status: None,
        target_beta: None,
        confirmed_beta: None,
        target_stable: None,
        confirmed_stable: None,
        merged_into: None,
    };
    assert_eq!(
        super::notice_text(&c, "fixed", Some("1.3.0")),
        "A bug you follow in bar has been fixed in 1.3.0. Thanks for helping us improve it!"
    );
    assert_eq!(
        super::notice_text(&c, "beta", Some("1.4-beta1")),
        "A bug you follow in bar is available in the 1.4-beta1 beta."
    );
    assert_eq!(
        super::notice_text(&c, "stable", Some("1.4")),
        "A bug you follow in bar is available in 1.4 stable."
    );
    c.kind = "request".into();
    assert_eq!(
        super::notice_text(&c, "fixed", Some("2.0")),
        "A feature you follow in bar has been implemented in 2.0. Thanks for helping us improve it!"
    );
    assert_eq!(
        super::notice_text(&c, "stable", Some("2.0")),
        "A feature you follow in bar is available in 2.0 stable."
    );
    // Board-detected fixes carry no version: still names the app and stage.
    assert_eq!(
        super::notice_text(&c, "fixed", None),
        "A feature you follow in bar has been implemented. Thanks for helping us improve it!"
    );
    assert_eq!(
        super::notice_text(&c, "beta", None),
        "A feature you follow in bar is available in the beta channel."
    );
}
