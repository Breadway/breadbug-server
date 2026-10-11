use super::*;

fn sample<'a>(receipt: &'a str, install: &'a str, sha: &'a str, at: u64) -> NewReport<'a> {
    NewReport {
        receipt,
        token_hash: "tokenhash",
        install_hash: install,
        payload_sha: sha,
        received_at: at,
        app: "clip",
        app_version: Some("0.3"),
        report_type: "crash",
        quarantined: false,
        rescrub_hits: "{}",
        raw: "{\"x\":1}",
    }
}

#[test]
fn insert_find_duplicate_and_status() {
    let db = Db::open_memory().unwrap();
    db.insert_report(&sample("r1", "i1", "s1", 100)).unwrap();
    assert_eq!(
        db.find_duplicate("i1", "s1").unwrap().as_deref(),
        Some("r1")
    );
    assert!(db.find_duplicate("i2", "s1").unwrap().is_none());
    assert_eq!(db.status_of("r1").unwrap().as_deref(), Some("received"));
    assert!(db.status_of("nope").unwrap().is_none());
    // same install + same payload cannot be inserted twice
    assert!(db.insert_report(&sample("r2", "i1", "s1", 101)).is_err());
}

#[test]
fn delete_needs_the_right_token_and_really_deletes() {
    let db = Db::open_memory().unwrap();
    db.insert_report(&sample("r1", "i1", "s1", 100)).unwrap();
    assert!(!db.delete_report("r1", "wrong").unwrap());
    assert!(!db.delete_report("missing", "tokenhash").unwrap());
    assert_eq!(db.report_count().unwrap(), 1);
    assert!(db.delete_report("r1", "tokenhash").unwrap());
    assert_eq!(db.report_count().unwrap(), 0);
    assert!(db.raw_of("r1").unwrap().is_none());
}

#[test]
fn purge_and_trim() {
    let db = Db::open_memory().unwrap();
    for i in 0..10u64 {
        db.insert_report(&sample(&format!("r{i}"), "i", &format!("s{i}"), 100 + i))
            .unwrap();
    }
    assert_eq!(db.purge_before(105).unwrap(), 5);
    assert_eq!(db.report_count().unwrap(), 5);
    assert_eq!(db.trim_to(2).unwrap(), 3);
    assert_eq!(db.report_count().unwrap(), 2);
    // the newest survive
    assert!(db.status_of("r9").unwrap().is_some());
    assert!(db.status_of("r5").unwrap().is_none());
    assert_eq!(db.trim_to(100).unwrap(), 0);
}

#[test]
fn migrations_are_idempotent_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("t.db");
    {
        let db = Db::open(&p).unwrap();
        db.insert_report(&sample("r1", "i1", "s1", 1)).unwrap();
    }
    let db = Db::open(&p).unwrap();
    assert_eq!(db.report_count().unwrap(), 1);
}

fn row() -> ClusterRow {
    ClusterRow {
        id: 1,
        app: "clip".into(),
        kind: "crash".into(),
        fingerprint: None,
        title: "t".into(),
        status: "new".into(),
        first_seen: 0,
        last_seen: 0,
        count: 1,
        installs: 1,
        versions: Default::default(),
        os_builds: Default::default(),
        fixed_in: None,
        issue_key: None,
        issue_status: None,
        board_fixed: false,
        target_beta: None,
        confirmed_beta: None,
        target_stable: None,
        confirmed_stable: None,
        merged_into: None,
    }
}

#[test]
fn progress_mapping_covers_every_stage() {
    // No linked issue: no progress, whatever the cluster state.
    let mut c = row();
    assert_eq!(progress_of(&c), None);
    // A pending promotion claim is not a linked issue yet.
    c.issue_key = Some("pending".into());
    c.issue_status = Some("todo".into());
    assert_eq!(progress_of(&c), None);
    // Linked issue, board states map to stages.
    c.issue_key = Some("CLIP-9".into());
    for (board, stage) in [
        ("backlog", "accepted"),
        ("todo", "accepted"),
        ("doing", "in_development"),
        ("review", "fixed"),
        ("done", "completed"),
    ] {
        c.status = "promoted".into();
        c.issue_status = Some(board.into());
        assert_eq!(progress_of(&c), Some(stage), "{board}");
    }
    // Unknown cached values stay silent rather than leaking.
    c.issue_status = Some("archived".into());
    assert_eq!(progress_of(&c), None);
    c.issue_status = None;
    assert_eq!(progress_of(&c), None);
    // Cluster verdicts win over the board state.
    c.issue_status = Some("doing".into());
    c.status = "dismissed".into();
    assert_eq!(progress_of(&c), Some("declined"));
    c.status = "deferred".into();
    assert_eq!(progress_of(&c), Some("deferred"));
    // A fixed cluster is implemented, and aims at a release once a version is
    // recorded. A done issue still reads completed.
    c.status = "fixed".into();
    c.fixed_in = None;
    assert_eq!(progress_of(&c), Some("fixed"));
    c.fixed_in = Some("0.4.0".into());
    assert_eq!(progress_of(&c), Some("targeting_release"));
    c.issue_status = Some("done".into());
    assert_eq!(progress_of(&c), Some("completed"));
}

#[test]
fn unknown_issue_statuses_are_not_cached() {
    let db = Db::open_memory().unwrap();
    let id = db
        .new_cluster(
            "clip",
            "crash",
            "t",
            &Contribution {
                report_id: 0,
                install_hash: "i1",
                version: Some("0.3"),
                os_build: None,
                at: 1,
            },
        )
        .unwrap();
    assert!(db.set_issue_status(id, "doing").unwrap());
    assert_eq!(
        db.cluster(id).unwrap().unwrap().issue_status.as_deref(),
        Some("doing")
    );
    assert!(!db.set_issue_status(id, "archived").unwrap());
    assert_eq!(
        db.cluster(id).unwrap().unwrap().issue_status.as_deref(),
        Some("doing")
    );
    assert!(!db.set_issue_status(999, "doing").unwrap());
}

fn release_cluster() -> (Db, i64) {
    let db = Db::open_memory().unwrap();
    let id = db
        .new_cluster(
            "bar",
            "manual",
            "t",
            &Contribution {
                report_id: 0,
                install_hash: "i1",
                version: Some("1.3.0"),
                os_build: None,
                at: 1,
            },
        )
        .unwrap();
    (db, id)
}

#[test]
fn release_targets_confirm_flow_and_ordering() {
    let (db, id) = release_cluster();
    // Nothing tracked yet: no releases in the public view.
    assert_eq!(releases_of(&db.cluster(id).unwrap().unwrap()), None);
    // Bad channels, bad versions, unknown clusters are refused.
    assert!(!db.set_release_target(id, "nightly", "1.4").unwrap());
    assert!(!db.set_release_target(id, "beta", "").unwrap());
    assert!(!db
        .set_release_target(id, "beta", &"x".repeat(MAX_VERSION + 1))
        .unwrap());
    assert!(!db.set_release_target(999, "beta", "1.4").unwrap());
    // Confirming needs a plan first.
    assert!(!db.mark_release_confirmed(id, "beta", "1.4-beta1").unwrap());

    assert!(db.set_release_target(id, "beta", "1.4-beta1").unwrap());
    assert!(db.set_release_target(id, "stable", "1.4").unwrap());
    // A beta newer than the stable target is rejected both ways round.
    assert!(!db.set_release_target(id, "beta", "1.5-beta1").unwrap());
    assert!(!db.set_release_target(id, "stable", "1.3").unwrap());
    // Dev and rc versions order below their release.
    assert!(db
        .set_release_target(id, "beta", "1.4-dev.20260101")
        .unwrap());
    assert!(db.set_release_target(id, "stable", "1.4").unwrap());

    let track = releases_of(&db.cluster(id).unwrap().unwrap()).unwrap();
    assert_eq!(track.beta.planned.as_deref(), Some("1.4-dev.20260101"));
    assert!(!track.beta.shipped);
    assert_eq!(track.beta.shipped_in, None);

    assert!(db.mark_release_confirmed(id, "beta", "1.4-beta2").unwrap());
    let track = releases_of(&db.cluster(id).unwrap().unwrap()).unwrap();
    assert!(track.beta.shipped);
    assert_eq!(track.beta.shipped_in.as_deref(), Some("1.4-beta2"));
    assert!(!track.stable.shipped);

    assert!(db.mark_release_confirmed(id, "stable", "1.4").unwrap());
    let track = releases_of(&db.cluster(id).unwrap().unwrap()).unwrap();
    assert!(track.stable.shipped);
    assert_eq!(track.stable.shipped_in.as_deref(), Some("1.4"));
}
