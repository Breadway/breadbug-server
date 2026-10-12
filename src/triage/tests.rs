use super::*;
use std::collections::BTreeMap;

fn cluster(kind: &str, count: u64, installs: u64, last_seen: u64) -> ClusterRow {
    ClusterRow {
        id: 1,
        app: "clip".into(),
        kind: kind.into(),
        fingerprint: None,
        title: "t".into(),
        status: "new".into(),
        first_seen: 0,
        last_seen,
        count,
        installs,
        versions: BTreeMap::new(),
        os_builds: BTreeMap::new(),
        fixed_in: None,
        issue_key: None,
        issue_status: None,
        merged_into: None,
        board_fixed: false,
    }
}

const NOW: u64 = 100_000_000;

#[test]
fn kind_orders_crash_over_freeze_over_behavior() {
    let r = ScoreRules::default();
    let old = NOW - 30 * DAY;
    let a = score(&cluster("crash", 1, 1, old), NOW, &r).total;
    let b = score(&cluster("freeze", 1, 1, old), NOW, &r).total;
    let c = score(&cluster("behavior", 1, 1, old), NOW, &r).total;
    assert!(a > b && b > c, "{a} {b} {c}");
}

#[test]
fn volume_installs_and_recency_raise_the_score_with_caps() {
    let r = ScoreRules::default();
    let old = NOW - 30 * DAY;
    let one = score(&cluster("crash", 1, 1, old), NOW, &r).total;
    let many = score(&cluster("crash", 8, 1, old), NOW, &r).total;
    assert_eq!(many - one, 30);
    let huge = score(&cluster("crash", 1_000_000, 1, old), NOW, &r).total;
    assert_eq!(huge - one, r.volume_max);
    let spread = score(&cluster("crash", 1, 6, old), NOW, &r).total;
    assert_eq!(spread - one, 20);
    let fresh = score(&cluster("crash", 1, 1, NOW - 100), NOW, &r).total;
    assert_eq!(fresh - one, r.seen_last_day);
    let week = score(&cluster("crash", 1, 1, NOW - 3 * DAY), NOW, &r).total;
    assert_eq!(week - one, r.seen_last_week);
}

#[test]
fn every_point_is_explained() {
    let mut c = cluster("freeze", 4, 3, NOW - 10);
    c.versions = (0..3).map(|i| (format!("0.{i}"), 1)).collect();
    c.status = "regressed".into();
    let s = score(&c, NOW, &ScoreRules::default());
    assert_eq!(s.total, s.parts.iter().map(|(_, p)| p).sum::<i32>());
    let names: Vec<_> = s.parts.iter().map(|(n, _)| *n).collect();
    for expected in [
        "kind",
        "volume",
        "distinct installs",
        "seen in the last day",
        "spread across versions",
        "regression",
    ] {
        assert!(
            names.contains(&expected),
            "{expected} missing from {names:?}"
        );
    }
}

#[test]
fn rules_load_from_toml_with_defaults_for_the_rest() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("r.toml");
    std::fs::write(&p, "crash = 200\nbehavior = 1\n").unwrap();
    let r = ScoreRules::load(&p).unwrap();
    assert_eq!(r.crash, 200);
    assert_eq!(r.behavior, 1);
    assert_eq!(r.freeze, ScoreRules::default().freeze);
    std::fs::write(&p, "crash = [").unwrap();
    assert!(ScoreRules::load(&p).is_err());
}
