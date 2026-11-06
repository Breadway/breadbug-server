#!/usr/bin/env python3
"""Create one sanitized backup generation; replace the previous generation."""

import argparse
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time

TITLE_CHARS = 100
MAP_KEY_CHARS = 64


def neutral_title(app, kind):
    """A title that names only machine facts, never the user's free text."""
    return f"{kind} report for {app}"


def first_line(value):
    """The first line of `value`, trimmed, capped like `embed::title_for`."""
    line = value.split("\n", 1)[0].rstrip("\r").strip()
    return line[:TITLE_CHARS]


def title_from_report(report):
    """Mirror `embed::title_for`: title, notes, first marker, last warning.

    Returns None when the report has no usable basis, so the caller can fall
    back to the neutral title.
    """
    if not isinstance(report, dict):
        return None
    basis = report.get("title")
    if not (isinstance(basis, str) and basis.strip()):
        basis = report.get("notes")
        if not (isinstance(basis, str) and basis.strip()):
            basis = _first_marker_message(report.get("markers"))
            if basis is None:
                basis = _last_warning_log(report.get("logs"))
    if basis is None:
        return None
    title = first_line(basis) if isinstance(basis, str) else None
    return title or None


def _first_marker_message(markers):
    if not isinstance(markers, list):
        return None
    for marker in markers:
        if isinstance(marker, dict) and marker.get("message") is not None:
            message = marker["message"]
            if isinstance(message, str):
                return message
            return None
    return None


def _last_warning_log(logs):
    if not isinstance(logs, list):
        return None
    for log in reversed(logs):
        if isinstance(log, dict) and log.get("level") in ("ERROR", "WARN"):
            message = log.get("msg")
            if isinstance(message, str):
                return message
            return None
    return None


def os_build(raw):
    """The `system.os_build` of a stored report, or None if it is unusable."""
    try:
        report = json.loads(raw)
    except (TypeError, ValueError):
        return None
    system = report.get("system") if isinstance(report, dict) else None
    build = system.get("os_build") if isinstance(system, dict) else None
    return build if isinstance(build, str) and build else None


def counted_key(value):
    """Versions and builds keys are capped to 64 characters by `db::bump`."""
    return value[:MAP_KEY_CHARS]


def json_map(counts):
    return json.dumps(counts, sort_keys=True, separators=(",", ":"))


def refresh_cluster(connection, cluster_id):
    """Rebuild one cluster's report-derived metadata from its survivors.

    Runs after the expired report rows are gone. The cluster row may already
    be missing (a report can point at a deleted cluster), in which case there
    is nothing to update and the expiry must still succeed.
    """
    row = connection.execute(
        "SELECT fingerprint, merged_into, app, kind, embedding, emb_n"
        " FROM clusters WHERE id = ?1",
        (cluster_id,),
    ).fetchone()
    if row is None:
        return
    fingerprint, merged_into, app, kind, embedding, emb_n = row
    survivors = connection.execute(
        "SELECT app_version, raw, received_at, quarantined FROM reports"
        " WHERE cluster_id = ?1 ORDER BY received_at, id",
        (cluster_id,),
    ).fetchall()
    versions = {}
    os_builds = {}
    for version, raw, _received_at, _quarantined in survivors:
        if version:
            key = counted_key(version)
            versions[key] = versions.get(key, 0) + 1
        build = os_build(raw)
        if build:
            key = counted_key(build)
            os_builds[key] = os_builds.get(key, 0) + 1
    if survivors:
        connection.execute(
            "UPDATE clusters SET count = ?2, versions = ?3, os_builds = ?4,"
            " first_seen = ?5, last_seen = ?6 WHERE id = ?1",
            (
                cluster_id,
                len(survivors),
                json_map(versions),
                json_map(os_builds),
                survivors[0][2],
                max(report[2] for report in survivors),
            ),
        )
    else:
        connection.execute(
            "UPDATE clusters SET count = 0, versions = '{}', os_builds = '{}'"
            " WHERE id = ?1",
            (cluster_id,),
        )
    # A fingerprint title names the crash signature, not the user's note, so
    # it survives expiry. A merged-away alias is neutralised by the prune
    # below once its last report is gone; its redirect is never changed.
    if fingerprint is not None or merged_into is not None or not survivors:
        return
    title = None
    for _version, raw, _received_at, quarantined in survivors:
        if quarantined:
            continue
        try:
            report = json.loads(raw)
        except (TypeError, ValueError):
            continue
        # The oldest surviving report decides the title, even when it has no
        # usable basis; only an unparseable row falls through to the next.
        title = title_from_report(report) or neutral_title(app, kind)
        break
    if title is None:
        title = neutral_title(app, kind)
    if embedding is not None or emb_n:
        # Per-report vectors are not stored, so a centroid that included an
        # expired report cannot be rebuilt here. Leave it and it would still
        # encode the deleted note, so drop it and let the server's re-embed
        # pass rebuild from the survivors.
        connection.execute(
            "UPDATE clusters SET title = ?2, embedding = NULL, emb_n = 0,"
            " emb_model = NULL WHERE id = ?1",
            (cluster_id, title),
        )
    else:
        connection.execute(
            "UPDATE clusters SET title = ?2 WHERE id = ?1", (cluster_id, title)
        )


def prune_empty(connection):
    """Drop or neutralise clusters that no longer have any raw reports.

    Mirrors `Db::prune_empty`: unacted clusters disappear, clusters a human
    acted on (linked issue, merge target) keep their row but lose the title
    and vector that came from free text, and install hashes with no surviving
    report behind them are removed.
    """
    connection.execute(
        "DELETE FROM cluster_installs WHERE NOT EXISTS ("
        "  SELECT 1 FROM reports r"
        "  WHERE r.cluster_id = cluster_installs.cluster_id"
        "    AND r.install_hash = cluster_installs.install_hash)"
    )
    connection.execute(
        "DELETE FROM clusters WHERE status = 'new' AND issue_key IS NULL"
        "  AND NOT EXISTS (SELECT 1 FROM reports r WHERE r.cluster_id = clusters.id)"
        "  AND NOT EXISTS (SELECT 1 FROM clusters m WHERE m.merged_into = clusters.id)"
    )
    connection.execute(
        "UPDATE clusters SET title = kind || ' report for ' || app,"
        " embedding = NULL, emb_n = 0, emb_model = NULL"
        " WHERE fingerprint IS NULL"
        "  AND NOT EXISTS (SELECT 1 FROM reports r WHERE r.cluster_id = clusters.id)"
        "  AND (title != (kind || ' report for ' || app)"
        "       OR embedding IS NOT NULL OR emb_n != 0)"
    )
    connection.execute(
        "DELETE FROM cluster_installs WHERE cluster_id NOT IN (SELECT id FROM clusters)"
    )
    connection.execute(
        "DELETE FROM follows WHERE cluster_id NOT IN (SELECT id FROM clusters)"
    )
    connection.execute(
        "DELETE FROM notices WHERE cluster_id NOT IN (SELECT id FROM clusters)"
    )
    connection.execute(
        "DELETE FROM notices WHERE token_hash NOT IN (SELECT token_hash FROM follows)"
    )


def expire_reports(connection, cutoff):
    """Delete expired reports and detach their clusters in one transaction.

    The cluster ids are recorded before the delete because the reports that
    name them are about to disappear. Everything runs inside the caller's
    transaction, before compaction, so the snapshot never exists on disk with
    raw rows gone but their note-derived metadata present.
    """
    affected = [
        row[0]
        for row in connection.execute(
            "SELECT DISTINCT cluster_id FROM reports"
            " WHERE received_at < ?1 AND cluster_id IS NOT NULL",
            (cutoff,),
        )
    ]
    connection.execute("DELETE FROM reports WHERE received_at < ?1", (cutoff,))
    for cluster_id in affected:
        refresh_cluster(connection, cluster_id)
    prune_empty(connection)


def backup(source, destination, retention_days):
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".breadbug-backup-", dir=destination.parent)
    os.close(fd)
    try:
        with sqlite3.connect(f"file:{Path(source).resolve()}?mode=ro", uri=True) as src:
            with sqlite3.connect(temporary) as dst:
                src.backup(dst)
                dst.execute("PRAGMA secure_delete=ON")
                dst.execute("BEGIN IMMEDIATE")
                try:
                    expire_reports(dst, int(time.time()) - retention_days * 86400)
                    dst.commit()
                except BaseException:
                    dst.rollback()
                    raise
                dst.execute("PRAGMA journal_mode=DELETE")
                dst.execute("VACUUM")
        os.chmod(temporary, 0o600)
        with open(temporary, "rb") as file:
            os.fsync(file.fileno())
        os.replace(temporary, destination)
        directory = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source")
    parser.add_argument("destination")
    parser.add_argument("--retention-days", type=int, default=90)
    args = parser.parse_args()
    if args.retention_days < 0:
        parser.error("retention-days must be nonnegative")
    backup(args.source, args.destination, args.retention_days)
