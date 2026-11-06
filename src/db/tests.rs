use super::*;
use crate::embed::{cosine, report_text, title_for, Embedder, HashEmbedder};
use crate::schema::Report;

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
    assert!(!db.delete_report("r1", "wrong", &HashEmbedder).unwrap());
    assert!(!db
        .delete_report("missing", "tokenhash", &HashEmbedder)
        .unwrap());
    assert_eq!(db.report_count().unwrap(), 1);
    assert!(db.delete_report("r1", "tokenhash", &HashEmbedder).unwrap());
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
    assert_eq!(db.purge_before(105, &HashEmbedder).unwrap(), 5);
    assert_eq!(db.report_count().unwrap(), 5);
    assert_eq!(db.trim_to(2, &HashEmbedder).unwrap(), 3);
    assert_eq!(db.report_count().unwrap(), 2);
    // the newest survive
    assert!(db.status_of("r9").unwrap().is_some());
    assert!(db.status_of("r5").unwrap().is_none());
    assert_eq!(db.trim_to(100, &HashEmbedder).unwrap(), 0);
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

fn report_json(note: &str) -> String {
    serde_json::json!({
        "schema": 1,
        "report_type": "behavior",
        "created_unix": 1,
        "app": {"id": "clip", "version": "0.3"},
        "notes": note,
    })
    .to_string()
}

fn vector_of(raw: &str) -> Vec<f32> {
    let report: Report = serde_json::from_str(raw).unwrap();
    HashEmbedder.embed(&report_text(&report)).unwrap()
}

/// Store clean reports in one fuzzy cluster, as intake would, and leave a
/// centroid covering all of them. `(receipt, install, note, at)` per report.
fn fuzzy_cluster(db: &Db, members: &[(&str, &str, &str, u64)]) -> i64 {
    let mut cid: Option<i64> = None;
    let mut vectors = Vec::new();
    for &(receipt, install, note, at) in members {
        let raw = report_json(note);
        let id = db
            .insert_report(&NewReport {
                receipt,
                token_hash: "tokenhash",
                install_hash: install,
                payload_sha: receipt,
                received_at: at,
                app: "clip",
                app_version: Some("0.3"),
                report_type: "behavior",
                quarantined: false,
                rescrub_hits: "{}",
                raw: &raw,
            })
            .unwrap();
        let report: Report = serde_json::from_str(&raw).unwrap();
        let c = Contribution {
            report_id: id,
            install_hash: install,
            version: Some("0.3"),
            os_build: None,
            at,
        };
        cid = Some(match cid {
            Some(existing) => db.assign_to(existing, &c).unwrap(),
            None => db
                .new_cluster("clip", "behavior", &title_for(&report), &c)
                .unwrap(),
        });
        vectors.push(HashEmbedder.embed(&report_text(&report)).unwrap());
    }
    let cid = cid.unwrap();
    let c = crate::embed::centroid(&vectors).unwrap();
    db.set_embedding(cid, &c, vectors.len() as u64, HashEmbedder.model())
        .unwrap();
    cid
}

fn assert_close(actual: &[f32], expected: &[f32]) {
    assert_eq!(actual.len(), expected.len());
    assert!(
        cosine(actual, expected) > 0.999_99,
        "centroid {actual:?} does not match {expected:?}"
    );
}

#[test]
fn deleting_one_report_rebuilds_title_centroid_and_installs() {
    let db = Db::open_memory().unwrap();
    let note_a = "clipboard hangs when I paste a large image";
    let note_b = "scratchpad notes vanish after closing the window";
    let cid = fuzzy_cluster(
        &db,
        &[
            ("rA", "installA", note_a, 100),
            ("rB", "installB", note_b, 200),
        ],
    );
    let before = db.cluster(cid).unwrap().unwrap();
    assert_eq!(before.title, note_a);

    assert!(db.delete_report("rA", "tokenhash", &HashEmbedder).unwrap());

    let after = db.cluster(cid).unwrap().unwrap();
    assert_eq!(after.title, note_b);
    assert!(!after.title.contains("clipboard"));
    assert_eq!((after.count, after.installs), (1, 1));
    assert_eq!(
        db.cluster_installs_for_test(cid).unwrap(),
        vec!["installB".to_string()]
    );
    let (embedding, n, model) = db.embedding_for_test(cid).unwrap().unwrap();
    assert_eq!(n, 1);
    assert_eq!(model.as_deref(), Some("hash-v1-256"));
    assert_close(&embedding.unwrap(), &vector_of(&report_json(note_b)));
    assert!(db.raw_of("rA").unwrap().is_none());
}

#[test]
fn deleting_the_last_report_removes_an_unacted_cluster() {
    let db = Db::open_memory().unwrap();
    let note = "clipboard hangs when I paste a large image";
    let cid = fuzzy_cluster(&db, &[("r1", "install1", note, 100)]);

    assert!(db.delete_report("r1", "tokenhash", &HashEmbedder).unwrap());

    assert!(db.cluster(cid).unwrap().is_none());
    assert!(db.cluster_installs_for_test(cid).unwrap().is_empty());
    assert_eq!(db.report_count().unwrap(), 0);
}

#[test]
fn last_report_deletion_keeps_a_promoted_link_without_its_note() {
    let db = Db::open_memory().unwrap();
    let note = "clipboard hangs when I paste a large image";
    let cid = fuzzy_cluster(&db, &[("r1", "install1", note, 100)]);
    assert!(db.set_issue(cid, "BUG-1").unwrap());

    assert!(db.delete_report("r1", "tokenhash", &HashEmbedder).unwrap());

    let kept = db.cluster(cid).unwrap().unwrap();
    assert_eq!(kept.issue_key.as_deref(), Some("BUG-1"));
    assert_eq!(kept.status, "promoted");
    assert_eq!(kept.title, "behavior report for clip");
    assert!(!kept.title.contains("clipboard"));
    let (embedding, n, _) = db.embedding_for_test(cid).unwrap().unwrap();
    assert!(embedding.is_none());
    assert_eq!(n, 0);
    assert!(db.cluster_installs_for_test(cid).unwrap().is_empty());
}

#[test]
fn purging_old_reports_detaches_them_and_prunes_empty_clusters() {
    let db = Db::open_memory().unwrap();
    let note_a = "clipboard hangs when I paste a large image";
    let note_b = "scratchpad notes vanish after closing the window";
    let cid = fuzzy_cluster(
        &db,
        &[
            ("rA", "installA", note_a, 100),
            ("rB", "installB", note_b, 200),
        ],
    );
    // A cluster acted on before the cutoff must keep its link, but not the
    // note. A cluster nobody acted on must disappear entirely.
    let old_note = "lock screen rejects the correct password sometimes";
    let acted = fuzzy_cluster(&db, &[("rC", "installC", old_note, 100)]);
    assert!(db.set_issue(acted, "BUG-2").unwrap());
    let gone_note = "notification banner never disappears from the panel";
    let gone = fuzzy_cluster(&db, &[("rD", "installD", gone_note, 100)]);

    assert_eq!(db.purge_before(150, &HashEmbedder).unwrap(), 3);

    let survivor = db.cluster(cid).unwrap().unwrap();
    assert_eq!(survivor.title, note_b);
    assert!(!survivor.title.contains("clipboard"));
    assert_eq!((survivor.count, survivor.installs), (1, 1));
    assert_eq!(
        db.cluster_installs_for_test(cid).unwrap(),
        vec!["installB".to_string()]
    );
    let (embedding, n, model) = db.embedding_for_test(cid).unwrap().unwrap();
    assert_eq!(n, 1);
    assert_eq!(model.as_deref(), Some("hash-v1-256"));
    assert_close(&embedding.unwrap(), &vector_of(&report_json(note_b)));

    assert!(db.raw_of("rA").unwrap().is_none());
    assert!(db.raw_of("rC").unwrap().is_none());
    assert!(db.raw_of("rD").unwrap().is_none());

    let kept = db.cluster(acted).unwrap().unwrap();
    assert_eq!(kept.issue_key.as_deref(), Some("BUG-2"));
    assert_eq!(kept.title, "behavior report for clip");
    assert!(!kept.title.contains("password"));
    let (embedding, n, _) = db.embedding_for_test(acted).unwrap().unwrap();
    assert!(embedding.is_none());
    assert_eq!(n, 0);
    assert!(db.cluster_installs_for_test(acted).unwrap().is_empty());

    assert!(db.cluster(gone).unwrap().is_none());
    assert!(db.cluster_installs_for_test(gone).unwrap().is_empty());
}

/// Assert a cluster kept only as a merge alias is neutral: no note text, no
/// vector, no install hash, and its redirect still resolves to `live`.
fn assert_neutral_alias(db: &Db, alias: i64, live: i64) {
    let row = db.cluster(alias).unwrap().unwrap();
    assert_eq!(row.merged_into, Some(live));
    assert_eq!(row.title, "behavior report for clip");
    assert!(!row.title.contains("clipboard"));
    assert!(!row.title.contains("scratchpad"));
    let (embedding, n, _) = db.embedding_for_test(alias).unwrap().unwrap();
    assert!(embedding.is_none());
    assert_eq!(n, 0);
    assert!(db.cluster_installs_for_test(alias).unwrap().is_empty());
    assert_eq!(db.resolve_cluster_id(alias).unwrap(), live);
}

#[test]
fn deleting_reports_neutralises_a_merged_away_cluster() {
    let db = Db::open_memory().unwrap();
    let note_a = "clipboard hangs when I paste a large image";
    let note_b = "scratchpad notes vanish after closing the window";
    let a = fuzzy_cluster(&db, &[("rA", "installA", note_a, 100)]);
    let b = fuzzy_cluster(&db, &[("rB", "installB", note_b, 200)]);
    assert!(db.set_issue(a, "BUG-20").unwrap());
    assert!(db.merge_clusters(a, b).unwrap());
    assert_eq!(db.cluster(a).unwrap().unwrap().merged_into, Some(b));

    // rA moved into b, so deleting it leaves the alias with no reports of its
    // own even though b still has one. The alias must lose the note anyway.
    assert!(db.delete_report("rA", "tokenhash", &HashEmbedder).unwrap());
    assert_neutral_alias(&db, a, b);
    assert_eq!(
        db.cluster(a).unwrap().unwrap().issue_key.as_deref(),
        Some("BUG-20")
    );
    let live = db.cluster(b).unwrap().unwrap();
    assert_eq!(live.title, note_b);
    assert_eq!(db.embedding_for_test(b).unwrap().unwrap().1, 1);

    // Emptying the canonical cluster must not break the redirect to it; b is
    // kept because the alias still points there.
    assert!(db.delete_report("rB", "tokenhash", &HashEmbedder).unwrap());
    assert_neutral_alias(&db, a, b);
    let live = db.cluster(b).unwrap().unwrap();
    assert_eq!(live.title, "behavior report for clip");
    let (embedding, n, _) = db.embedding_for_test(b).unwrap().unwrap();
    assert!(embedding.is_none());
    assert_eq!(n, 0);
    assert!(db.cluster_installs_for_test(b).unwrap().is_empty());
    assert!(db.raw_of("rA").unwrap().is_none());
    assert!(db.raw_of("rB").unwrap().is_none());
}

#[test]
fn purging_reports_neutralises_a_merged_away_cluster() {
    let db = Db::open_memory().unwrap();
    let note_a = "clipboard hangs when I paste a large image";
    let note_b = "scratchpad notes vanish after closing the window";
    let a = fuzzy_cluster(&db, &[("rA", "installA", note_a, 100)]);
    let b = fuzzy_cluster(&db, &[("rB", "installB", note_b, 200)]);
    assert!(db.set_issue(a, "BUG-21").unwrap());
    assert!(db.merge_clusters(a, b).unwrap());

    assert_eq!(db.purge_before(300, &HashEmbedder).unwrap(), 2);

    assert_neutral_alias(&db, a, b);
    assert_eq!(
        db.cluster(a).unwrap().unwrap().issue_key.as_deref(),
        Some("BUG-21")
    );
    let live = db.cluster(b).unwrap().unwrap();
    assert_eq!(live.title, "behavior report for clip");
    let (embedding, n, _) = db.embedding_for_test(b).unwrap().unwrap();
    assert!(embedding.is_none());
    assert_eq!(n, 0);
    assert!(db.cluster_installs_for_test(b).unwrap().is_empty());
    assert!(db.report_count().unwrap() == 0);
}

#[test]
fn maintenance_repairs_content_left_by_older_delete_paths() {
    let db = Db::open_memory().unwrap();
    let note = "clipboard hangs when I paste a large image";
    let unacted = fuzzy_cluster(&db, &[("r1", "install1", note, 100)]);
    let acted_note = "lock screen rejects the correct password sometimes";
    let acted = fuzzy_cluster(&db, &[("r2", "install2", acted_note, 100)]);
    assert!(db.set_issue(acted, "BUG-3").unwrap());

    // `detach_report` models the old delete paths: the raw row is no longer
    // in the cluster but its note-derived title and vector were never rebuilt.
    for receipt in ["r1", "r2"] {
        let id = db.report_id_for_test(receipt).unwrap().unwrap();
        let stored = db
            .clusterable_reports()
            .unwrap()
            .into_iter()
            .find(|r| r.id == id)
            .unwrap();
        db.detach_report(&stored).unwrap();
    }
    assert_eq!(db.cluster(acted).unwrap().unwrap().title, acted_note);

    db.prune_empty_clusters().unwrap();

    assert!(db.cluster(unacted).unwrap().is_none());
    let kept = db.cluster(acted).unwrap().unwrap();
    assert_eq!(kept.issue_key.as_deref(), Some("BUG-3"));
    assert_eq!(kept.title, "behavior report for clip");
    assert!(!kept.title.contains("password"));
    let (embedding, n, _) = db.embedding_for_test(acted).unwrap().unwrap();
    assert!(embedding.is_none());
    assert_eq!(n, 0);
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

#[test]
fn release_confirmation_validates_versions_and_ordering() {
    let (db, id) = release_cluster();
    assert!(db.set_release_target(id, "beta", "1.4").unwrap());
    assert!(db.set_release_target(id, "stable", "1.4").unwrap());
    // A confirmed beta newer than the planned stable is refused.
    assert!(!db.mark_release_confirmed(id, "beta", "9.0").unwrap());
    // A confirmed stable older than the planned beta is refused.
    assert!(!db.mark_release_confirmed(id, "stable", "1.0").unwrap());
    // Malformed versions are refused on both paths.
    assert!(!db
        .mark_release_confirmed(id, "beta", "not a version")
        .unwrap());
    assert!(!db
        .mark_release_confirmed(id, "beta", "**1.4**\ninjected")
        .unwrap());
    assert!(!db.set_release_target(id, "stable", "1.4 marked").unwrap());
    // Confirming inside the plan is accepted.
    assert!(db.mark_release_confirmed(id, "beta", "1.4-beta2").unwrap());
    // A planned stable below the confirmed beta is refused.
    assert!(!db.set_release_target(id, "stable", "1.0").unwrap());
    // A higher beta plan is fine: the confirmed beta dominates the check.
    assert!(db.set_release_target(id, "beta", "1.5").unwrap());
    assert!(db.mark_release_confirmed(id, "stable", "1.4").unwrap());
}

#[test]
fn release_targets_reject_inverted_plan_both_directions() {
    let (db, id) = release_cluster();
    assert!(db.set_release_target(id, "beta", "1.4").unwrap());
    assert!(db.set_release_target(id, "stable", "1.4").unwrap());
    assert!(!db.set_release_target(id, "stable", "1.3").unwrap());
    assert!(!db.set_release_target(id, "beta", "1.5").unwrap());
}
