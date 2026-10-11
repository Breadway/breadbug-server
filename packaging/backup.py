#!/usr/bin/env python3
"""Create one sanitized backup generation; replace the previous generation."""
import argparse
import os
from pathlib import Path
import sqlite3
import tempfile
import time


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
                dst.execute("DELETE FROM reports WHERE received_at < ?", (int(time.time()) - retention_days * 86400,))
                dst.commit()
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
