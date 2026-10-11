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
