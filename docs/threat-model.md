# Threat model

The public listener is unauthenticated and reachable by anyone. Treat every
byte as hostile. This is what the server defends against and how.

| Threat | Defence |
|--------|---------|
| Oversize bodies, decompression bombs | Hard `max_body_bytes` (default 1.5 MiB) enforced while streaming; no decompression is performed at all |
| Malformed or unexpected JSON | Strict versioned schema; unknown fields rejected at every level; per-field length and per-list count limits; bounded depth and width for free-form event data |
| Flooding | Per-install (10/h), per-network (40/h) and global (2000/h) sliding windows; `Retry-After` on 429; bounded in-flight requests (503); data-dir size cap |
| Tracking users | Install ids are random per install and HMAC'd with a server secret before storage; network buckets (/24, /48) are HMAC'd and held in memory only; IPs are never stored or logged; Caddy access logging is disabled for the host |
| Client scrubber failure | Every report is re-scrubbed server-side with the same rules. Any new redaction means the client missed something: only the scrubbed form is stored and the report is quarantined |
| Injection (SQL, shell, template) | All SQL is parameterised; report text is never interpolated into commands or templates; it is stored as data |
| Log injection | Report content is never written to logs; logs carry only counts and errors |
| XSS and markdown injection in the triage UI | Everything is HTML-escaped on output; the admin UI is on a separate listener that is not routed publicly |
| Prompt injection into an LLM step | Report text is data, never instructions; any LLM output is advisory, off by default, and has no tools |
| Enumeration of other people's reports | Receipts and deletion tokens are 128 and 256 bits of randomness; a wrong token and an unknown receipt are indistinguishable (404); the status endpoint returns a coarse state only |
| Follow token probing | Follow and unfollow tokens are 256 bits; unknown tokens are 404 without saying why; follow responses never name other followers |
| Notification pile-up | Notices are one row per follow per transition text; reads are a non-destructive peek and the client acks ids, delivered rows are kept for dedup, unfollowing discards pending notices |
| Replay / duplicates | An identical payload from the same install returns the original receipt |
| Re-identification via free text | Notes and logs are scrubbed client- and server-side; raw reports are deleted after 90 days and on request. Deleting or purging a report also takes it out of its cluster: a fuzzy cluster's note-derived title and embedding centroid are rebuilt from the reports that remain, its install hash is dropped once no report from that install is left, and an empty cluster nobody acted on is removed. A cluster a human acted on (linked issue or merge target) is kept, but once no reports remain its title is replaced with a neutral `"<kind> report for <app>"` and its centroid is cleared, so the link survives without the note |
| Container compromise | Own network and volume, non-root, read-only rootfs, no capabilities, no host mounts, no shared credentials |
| Stale data on disk | `secure_delete` and WAL truncation after deletes |

Out of scope for v1: screenshots, process memory, user accounts.

Promoting a cluster files a breadboard issue whose body includes already-scrubbed
evidence from the newest reports. That copy lives in breadboard: deleting a
report here later does not edit an issue that was already filed.

Backup privacy: `packaging/backup.py` removes expired raw payloads from a
consistent snapshot and compacts it before replacing the single backup
generation. Expiry runs the same cluster detach as a live delete: titles are
regenerated or neutralised and install hashes are dropped. A fuzzy centroid
that included an expired report is cleared rather than recomputed, because
per-report vectors are not stored. Explicit deletion reaches backups on the
next successful rotation, not instantly. Operators must monitor rotation and
independently expire any external snapshots. The server does not erase
unmanaged backup copies.
