# breadbug-server

The server side of [breadbug](https://git.breadway.dev/Breadway/bread/src/branch/main/docs/breadbug.md):
it receives opt-in crash, freeze and bug reports from bread apps, re-scrubs
them, stores them, and (in later releases) groups duplicates and feeds a
triage inbox.

## API (public listener, port 8120)

| Method | Path | Notes |
|--------|------|-------|
| `POST` | `/v1/reports` | Body: the report JSON, exactly as previewed by the client. Headers: `X-Breadbug-Install` (32 hex, random per install), `X-Breadbug-Sha256` (hash of the body, checked). `201 {receipt, deletion_token, status}`; an identical resend returns `200` with the original receipt. `400` invalid, `413` too large, `429` rate limited (`Retry-After`), `503` busy or full |
| `DELETE` | `/v1/reports/{receipt}` | `Authorization: Bearer <deletion_token>`. `204` on success; `404` for a wrong token and an unknown receipt alike |
| `GET` | `/v1/reports/{receipt}/status` | `{status}` only: `received`, `investigating`, `fixed`, `duplicate` |
| `GET` | `/healthz` | liveness |

The wire format is schema 1; see `src/schema.rs` and
`tests/fixtures/report_v1.json`.

## Running

```sh
cargo run   # data in ./data, public listener 127.0.0.1:8120
```

Configuration is environment variables (`src/config.rs`): `BREADBUG_DATA_DIR`,
`BREADBUG_PUBLIC_ADDR`, `BREADBUG_ADMIN_ADDR`, `BREADBUG_ADMIN_TOKEN_SHA256`,
`BREADBUG_MAX_BODY_BYTES`, `BREADBUG_RETENTION_DAYS`,
`BREADBUG_SYMBOL_DIR`, `BREADBUG_FUZZY_THRESHOLD`, `BREADBUG_EMBED_URL`, `BREADBUG_EMBED_MODEL`,
`BREADBUG_PER_INSTALL_PER_HOUR`, `BREADBUG_PER_NETWORK_PER_HOUR`,
`BREADBUG_GLOBAL_PER_HOUR`, `BREADBUG_MAX_IN_FLIGHT`, `BREADBUG_TRUST_PROXY`
(set behind Caddy), `BREADBUG_MAX_DB_BYTES`.

## Deploying

`packaging/docker-compose.yml` runs it isolated on Hestia; the public hostname
is routed by the Aegis Caddy (see the infra repo). Nothing here is deployed
by CI.

See [docs/threat-model.md](docs/threat-model.md) and
[CONTRIBUTING.md](CONTRIBUTING.md).
# Backup and deletion contract

Run `python3 packaging/backup.py data/breadbug.db /private/backup/breadbug.db
--retention-days 90` with the configured retention duration. This uses SQLite's
consistent backup API, deletes expired raw rows in the backup, securely clears
freed pages and vacuums before atomic replacement. Keep exactly one generation
at the destination. Never copy a live database or its WAL as a backup.

Explicit deletions propagate on the next successful rotation because the new
snapshot comes from the current database. Until rotation the previous backup
can still contain a deleted report. Failed rotation preserves the previous
generation, so monitor job failures and rotate before restoring. Additional
filesystem snapshots or off-site generations are outside this tool's contract
and must be expired by the operator. Back up the private install-HMAC secret
separately with restricted access.
