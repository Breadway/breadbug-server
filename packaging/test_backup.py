import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from backup import backup


class BackupTests(unittest.TestCase):
    def test_retention_and_explicit_delete_rotation(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.db"
            destination = Path(directory) / "backup.db"
            with sqlite3.connect(source) as connection:
                connection.execute("CREATE TABLE reports (id INTEGER, received_at INTEGER, raw TEXT)")
                connection.executemany("INSERT INTO reports VALUES (?, ?, ?)", [
                    (1, 0, "expired-private-marker"),
                    (2, int(time.time()), "deleted-private-marker"),
                ])
            backup(source, destination, 90)
            self.assertNotIn(b"expired-private-marker", destination.read_bytes())
            self.assertIn(b"deleted-private-marker", destination.read_bytes())
            with sqlite3.connect(source) as connection:
                connection.execute("DELETE FROM reports WHERE id=2")
            backup(source, destination, 90)
            self.assertNotIn(b"deleted-private-marker", destination.read_bytes())
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
