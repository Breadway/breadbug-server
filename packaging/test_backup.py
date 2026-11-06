import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from backup import backup

# The real migrations (src/db.rs) reduced to the tables this path touches. A
# toy report table would not catch a missing merge column or a query that
# expects the real install table.
SCHEMA = """
CREATE TABLE reports (
    id            INTEGER PRIMARY KEY,
    receipt       TEXT NOT NULL UNIQUE,
    token_hash    TEXT NOT NULL,
    install_hash  TEXT NOT NULL,
    payload_sha   TEXT NOT NULL,
    received_at   INTEGER NOT NULL,
    app           TEXT NOT NULL,
    app_version   TEXT,
    report_type   TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'received',
    quarantined   INTEGER NOT NULL DEFAULT 0,
    rescrub_hits  TEXT NOT NULL DEFAULT '{}',
    raw           TEXT NOT NULL,
    cluster_id    INTEGER
);
CREATE UNIQUE INDEX reports_dedupe ON reports(install_hash, payload_sha);
CREATE INDEX reports_cluster ON reports(cluster_id);

CREATE TABLE clusters (
    id             INTEGER PRIMARY KEY,
    app            TEXT NOT NULL,
    kind           TEXT NOT NULL,
    fingerprint    TEXT,
    title          TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'new',
    first_seen     INTEGER NOT NULL,
    last_seen      INTEGER NOT NULL,
    count          INTEGER NOT NULL DEFAULT 0,
    versions       TEXT NOT NULL DEFAULT '{}',
    os_builds      TEXT NOT NULL DEFAULT '{}',
    fixed_in       TEXT,
    issue_key      TEXT,
    merged_into    INTEGER,
    embedding      BLOB,
    emb_n          INTEGER NOT NULL DEFAULT 0,
    emb_model      TEXT,
    notified_count INTEGER NOT NULL DEFAULT 0,
    issue_priority TEXT,
    board_fixed    INTEGER NOT NULL DEFAULT 0,
    issue_status   TEXT,
    target_beta    TEXT,
    confirmed_beta TEXT,
    target_stable  TEXT,
    confirmed_stable TEXT
);
CREATE UNIQUE INDEX clusters_fp ON clusters(app, fingerprint) WHERE fingerprint IS NOT NULL;

CREATE TABLE cluster_installs (
    cluster_id   INTEGER NOT NULL,
    install_hash TEXT NOT NULL,
    PRIMARY KEY (cluster_id, install_hash)
);

CREATE TABLE follows (
    id           INTEGER PRIMARY KEY,
    cluster_id   INTEGER NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    install_hash TEXT NOT NULL,
    created_at   INTEGER NOT NULL
);

CREATE TABLE notices (
    id         INTEGER PRIMARY KEY,
    cluster_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL,
    event      TEXT NOT NULL,
    text       TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    delivered  INTEGER NOT NULL DEFAULT 0,
    UNIQUE(token_hash, event, text)
);
"""


def create_schema(connection):
    connection.executescript(SCHEMA)


def report_raw(
    note=None,
    *,
    title=None,
    logs=None,
    os_build=None,
    report_type="behavior",
    app="clip",
):
    raw = {
        "schema": 1,
        "report_type": report_type,
        "created_unix": 1,
        "app": {"id": app},
    }
    if title is not None:
        raw["title"] = title
    if note is not None:
        raw["notes"] = note
    if logs is not None:
        raw["logs"] = logs
    if os_build is not None:
        raw["system"] = {"os_build": os_build}
    return json.dumps(raw)


def insert_report(
    connection,
    report_id,
    *,
    receipt,
    install,
    received_at,
    raw,
    cluster_id,
    version="0.3",
    app="clip",
    report_type="behavior",
):
    connection.execute(
        "INSERT INTO reports (id, receipt, token_hash, install_hash, payload_sha,"
        " received_at, app, app_version, report_type, quarantined, rescrub_hits,"
        " raw, cluster_id) VALUES (?, ?, 'tokenhash', ?, ?, ?, ?, ?, ?, 0, '{}', ?, ?)",
        (
            report_id,
            receipt,
            install,
            receipt,
            received_at,
            app,
            version,
            report_type,
            raw,
            cluster_id,
        ),
    )


def insert_cluster(
    connection,
    cluster_id,
    *,
    app="clip",
    kind="behavior",
    fingerprint=None,
    title="cluster",
    status="new",
    first_seen=0,
    last_seen=0,
    count=0,
    versions="{}",
    os_builds="{}",
    issue_key=None,
    merged_into=None,
    embedding=None,
    emb_n=0,
    emb_model=None,
    installs=(),
):
    connection.execute(
        "INSERT INTO clusters (id, app, kind, fingerprint, title, status, first_seen,"
        " last_seen, count, versions, os_builds, issue_key, merged_into, embedding,"
        " emb_n, emb_model) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            cluster_id,
            app,
            kind,
            fingerprint,
            title,
            status,
            first_seen,
            last_seen,
            count,
            versions,
            os_builds,
            issue_key,
            merged_into,
            embedding,
            emb_n,
            emb_model,
        ),
    )
    for install in installs:
        connection.execute(
            "INSERT INTO cluster_installs (cluster_id, install_hash) VALUES (?, ?)",
            (cluster_id, install),
        )


def cluster_row(connection, cluster_id):
    return connection.execute(
        "SELECT title, status, count, versions, os_builds, first_seen, last_seen,"
        " issue_key, merged_into, embedding, emb_n, emb_model"
        " FROM clusters WHERE id = ?",
        (cluster_id,),
    ).fetchone()


def installs(connection, cluster_id):
    return [
        row[0]
        for row in connection.execute(
            "SELECT install_hash FROM cluster_installs WHERE cluster_id = ?"
            " ORDER BY install_hash",
            (cluster_id,),
        )
    ]


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.now = int(time.time())
        self.expired = self.now - 100 * 86400
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.source = Path(self.directory.name) / "source.db"
        self.destination = Path(self.directory.name) / "backup.db"

    def test_one_expired_report_rebuilds_title_counters_and_clears_centroid(self):
        old_note = "clipboard hangs when I paste a large image"
        new_note = "scratchpad notes vanish after closing the window"
        with sqlite3.connect(self.source) as connection:
            create_schema(connection)
            insert_cluster(
                connection,
                1,
                title=old_note,
                count=2,
                first_seen=self.expired,
                last_seen=self.now,
                versions='{"0.2":1,"0.3":1}',
                os_builds='{"old-build":1,"new-build":1}',
                embedding=b"\x00" * 8,
                emb_n=2,
                emb_model="hash-v1-256",
                installs=("installA", "installB"),
            )
            insert_report(
                connection,
                1,
                receipt="rA",
                install="installA",
                received_at=self.expired,
                version="0.2",
                raw=report_raw(old_note, os_build="old-build"),
                cluster_id=1,
            )
            insert_report(
                connection,
                2,
                receipt="rB",
                install="installB",
                received_at=self.now,
                version="0.3",
                raw=report_raw(new_note, os_build="new-build"),
                cluster_id=1,
            )

        backup(self.source, self.destination, 90)

        with sqlite3.connect(self.destination) as connection:
            row = cluster_row(connection, 1)
            self.assertIsNotNone(row)
            (
                title,
                status,
                count,
                versions,
                os_builds,
                first_seen,
                last_seen,
                issue_key,
                merged_into,
                embedding,
                emb_n,
                emb_model,
            ) = row
            self.assertEqual(title, new_note)
            self.assertEqual(status, "new")
            self.assertEqual(count, 1)
            self.assertEqual(json.loads(versions), {"0.3": 1})
            self.assertEqual(json.loads(os_builds), {"new-build": 1})
            self.assertEqual((first_seen, last_seen), (self.now, self.now))
            self.assertIsNone(embedding)
            self.assertEqual(emb_n, 0)
            self.assertIsNone(emb_model)
            self.assertIsNone(issue_key)
            self.assertIsNone(merged_into)
            self.assertEqual(installs(connection, 1), ["installB"])
            self.assertEqual(
                connection.execute("SELECT count(*) FROM reports").fetchone()[0], 1
            )
        self.assertNotIn(old_note.encode(), self.destination.read_bytes())

    def test_all_reports_expired_removes_an_unacted_cluster(self):
        note = "clipboard hangs when I paste a large image"
        with sqlite3.connect(self.source) as connection:
            create_schema(connection)
            insert_cluster(
                connection,
                1,
                title=note,
                count=1,
                first_seen=self.expired,
                last_seen=self.expired,
                embedding=b"\x00" * 8,
                emb_n=1,
                emb_model="hash-v1-256",
                installs=("install1",),
            )
            insert_report(
                connection,
                1,
                receipt="r1",
                install="install1",
                received_at=self.expired,
                raw=report_raw(note),
                cluster_id=1,
            )

        backup(self.source, self.destination, 90)

        with sqlite3.connect(self.destination) as connection:
            self.assertIsNone(cluster_row(connection, 1))
            self.assertEqual(installs(connection, 1), [])
            self.assertEqual(
                connection.execute("SELECT count(*) FROM reports").fetchone()[0], 0
            )

    def test_all_reports_expired_keeps_a_promoted_link_without_its_note(self):
        note = "lock screen rejects the correct password sometimes"
        with sqlite3.connect(self.source) as connection:
            create_schema(connection)
            insert_cluster(
                connection,
                1,
                title=note,
                status="promoted",
                issue_key="BUG-1",
                count=1,
                first_seen=self.expired,
                last_seen=self.expired,
                embedding=b"\x00" * 8,
                emb_n=1,
                emb_model="hash-v1-256",
                installs=("install1",),
            )
            insert_report(
                connection,
                1,
                receipt="r1",
                install="install1",
                received_at=self.expired,
                raw=report_raw(note),
                cluster_id=1,
            )

        backup(self.source, self.destination, 90)

        with sqlite3.connect(self.destination) as connection:
            row = cluster_row(connection, 1)
            self.assertIsNotNone(row)
            title = row[0]
            status = row[1]
            count = row[2]
            versions = row[3]
            os_builds = row[4]
            issue_key = row[7]
            merged_into = row[8]
            embedding = row[9]
            emb_n = row[10]
            emb_model = row[11]
            self.assertEqual(title, "behavior report for clip")
            self.assertEqual(status, "promoted")
            self.assertEqual(issue_key, "BUG-1")
            self.assertEqual(count, 0)
            self.assertEqual(json.loads(versions), {})
            self.assertEqual(json.loads(os_builds), {})
            self.assertIsNone(embedding)
            self.assertEqual(emb_n, 0)
            self.assertIsNone(emb_model)
            self.assertIsNone(merged_into)
            self.assertEqual(installs(connection, 1), [])
        self.assertNotIn(note.encode(), self.destination.read_bytes())

    def test_expired_reports_neutralise_a_merged_away_alias(self):
        alias_note = "clipboard hangs when I paste a large image"
        live_note = "scratchpad notes vanish after closing the window"
        with sqlite3.connect(self.source) as connection:
            create_schema(connection)
            insert_cluster(
                connection,
                1,
                title=alias_note,
                status="promoted",
                issue_key="BUG-20",
                count=0,
                merged_into=2,
                embedding=b"\x00" * 8,
                emb_n=1,
                emb_model="hash-v1-256",
                installs=("installA",),
            )
            insert_cluster(
                connection,
                2,
                title=live_note,
                count=2,
                first_seen=self.expired,
                last_seen=self.now,
                versions='{"0.2":1,"0.3":1}',
                installs=("installA", "installB"),
            )
            insert_report(
                connection,
                1,
                receipt="rA",
                install="installA",
                received_at=self.expired,
                version="0.2",
                raw=report_raw(alias_note),
                cluster_id=2,
            )
            insert_report(
                connection,
                2,
                receipt="rB",
                install="installB",
                received_at=self.now,
                raw=report_raw(live_note),
                cluster_id=2,
            )

        backup(self.source, self.destination, 90)

        with sqlite3.connect(self.destination) as connection:
            alias = cluster_row(connection, 1)
            self.assertIsNotNone(alias)
            self.assertEqual(alias[0], "behavior report for clip")
            self.assertIsNone(alias[9])
            self.assertEqual(alias[10], 0)
            self.assertIsNone(alias[11])
            self.assertEqual(installs(connection, 1), [])
            self.assertEqual(alias[8], 2)
            self.assertEqual(
                connection.execute(
                    "SELECT id FROM clusters WHERE id = (SELECT merged_into FROM clusters WHERE id = 1)"
                ).fetchone(),
                (2,),
            )
            live = cluster_row(connection, 2)
            self.assertEqual(live[0], live_note)
            self.assertEqual(installs(connection, 2), ["installB"])
        self.assertNotIn(alias_note.encode(), self.destination.read_bytes())

    def test_expired_report_with_a_missing_cluster_row_does_not_crash(self):
        note = "clipboard hangs when I paste a large image"
        with sqlite3.connect(self.source) as connection:
            create_schema(connection)
            insert_report(
                connection,
                1,
                receipt="r1",
                install="install1",
                received_at=self.expired,
                raw=report_raw(note),
                cluster_id=99,
            )

        backup(self.source, self.destination, 90)

        with sqlite3.connect(self.destination) as connection:
            self.assertEqual(
                connection.execute("SELECT count(*) FROM reports").fetchone()[0], 0
            )
            self.assertEqual(
                connection.execute("SELECT count(*) FROM clusters").fetchone()[0], 0
            )

    def test_fingerprint_cluster_keeps_its_crash_title(self):
        note = "SIGSEGV in clip::paste"
        with sqlite3.connect(self.source) as connection:
            create_schema(connection)
            insert_cluster(
                connection,
                1,
                kind="crash",
                fingerprint="cafebabe",
                title="panic in clip at paste",
                status="promoted",
                issue_key="BUG-3",
                count=1,
                first_seen=self.expired,
                last_seen=self.expired,
                installs=("install1",),
            )
            insert_report(
                connection,
                1,
                receipt="r1",
                install="install1",
                received_at=self.expired,
                report_type="crash",
                raw=report_raw(note, report_type="crash"),
                cluster_id=1,
            )

        backup(self.source, self.destination, 90)

        with sqlite3.connect(self.destination) as connection:
            row = cluster_row(connection, 1)
            self.assertIsNotNone(row)
            self.assertEqual(row[0], "panic in clip at paste")
            self.assertEqual(row[2], 0)
            self.assertEqual(installs(connection, 1), [])

    def test_retention_and_explicit_delete_rotation(self):
        with sqlite3.connect(self.source) as connection:
            create_schema(connection)
            insert_cluster(
                connection,
                1,
                title="expired-private-marker",
                count=2,
                first_seen=self.expired,
                last_seen=self.now,
            )
            insert_report(
                connection,
                1,
                receipt="r1",
                install="install1",
                received_at=self.expired,
                raw=report_raw("expired-private-marker"),
                cluster_id=1,
            )
            insert_report(
                connection,
                2,
                receipt="r2",
                install="install2",
                received_at=self.now,
                raw=report_raw("deleted-private-marker"),
                cluster_id=1,
            )

        backup(self.source, self.destination, 90)
        self.assertNotIn(b"expired-private-marker", self.destination.read_bytes())
        self.assertIn(b"deleted-private-marker", self.destination.read_bytes())

        with sqlite3.connect(self.source) as connection:
            connection.execute("DELETE FROM reports WHERE id = 2")
        backup(self.source, self.destination, 90)
        self.assertNotIn(b"deleted-private-marker", self.destination.read_bytes())
        self.assertEqual(self.destination.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
