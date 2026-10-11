# Feedback API: reporting problems and requesting features

This is the server-side contract for the applications' feedback experience
(BOS Settings in particular): report a problem, suggest a feature, follow an
issue, check development progress, and receive fix and feature notifications.
No breadbug client code lives here; this document plus the fixtures in
`tests/fixtures/` are what a client builds against.

Base URL: `https://bugs.breadway.dev`. All request and response bodies are
JSON. Receipts are 32 hex chars (128 bits of randomness), deletion and follow
tokens are 64 hex chars (256 bits). Keep every token secret: anyone holding
one can delete or follow.

## Concepts

- A **report** is one submission: an automatic crash/freeze/behavior report,
  a **manual** bug report (`title` plus a description in `notes`), or a
  **request** (`title`, `want` for what is requested, `notes` for why).
- Reports that describe the same problem are grouped into a **cluster**
  (one underlying issue). Following happens at the cluster level, so
  duplicates never split followers.
- **Progress** is a coarse stage: `accepted`, `in_development`, `fixed`,
  `targeting_release`, `completed`, `declined` or `deferred`. For a linked
  issue it follows the breadboard status; a cluster verdict (`declined`,
  `deferred`) or a recorded fix version (`fixed`, `targeting_release`) can
  set it without a board issue. Breadboard is authoritative for the
  linked-issue stages.
- **Releases** are per application release (never per BOS release), planned
  vs confirmed, separately for `beta` and `stable`.
- There are no accounts. The receipt names the issue, the tokens prove the
  right to delete or follow.

## Endpoints

### POST /v1/reports

Submit a report. Manual reports and feature requests use the same endpoint
as automatic reports.

Headers: `X-Breadbug-Install` (32 hex, random per install, required),
`X-Breadbug-Sha256` (hex SHA-256 of the body, optional but recommended).

Manual report body:

```json
{
  "schema": 1,
  "report_type": "manual",
  "created_unix": 1720000000,
  "app": {"id": "bar", "version": "1.3.0"},
  "title": "Panel flickers on workspace switch",
  "notes": "The top panel flickers for about a second whenever I switch workspaces."
}
```

Feature request body (`tests/fixtures/feature_request.json`):

```json
{
  "schema": 1,
  "report_type": "request",
  "created_unix": 1720000000,
  "app": {"id": "bar", "version": "1.3.0"},
  "title": "Dark mode for the panel",
  "want": "A dark theme option for the top panel.",
  "notes": "I work night shifts and the bright panel hurts my eyes."
}
```

Rules: `title` is required for manual reports and requests (1 to 256
chars) and forbidden on automatic reports. Requests additionally need `want`
(what) and `notes` (why). A manual report may carry optional
`diagnostics_reference` and `screenshot_reference` (opaque ids or paths,
never the bytes) together with `consent: true`; a reference without consent
is rejected. The server re-scrubs everything and quarantines reports the
client scrubber missed.

Success: `201 {"receipt": "...", "deletion_token": "...", "status": "received"}`.
An identical resend from the same install returns `200` with the original
`receipt` and no new token.

Errors: `400` invalid body or headers, `413` too large, `429` rate limited
(with `Retry-After`), `503` busy or storage full, `403` banned install.

### DELETE /v1/reports/{receipt}

Delete a report. Header `Authorization: Bearer <deletion_token>`.
`204` on success. A wrong token and an unknown receipt are both `404`, so
tokens cannot be probed.

### POST /v1/reports/{receipt}/follow

Follow the issue behind a report. Two authorized flows:

- The reporter sends `Authorization: Bearer <deletion_token>`; no install
  id is needed.
- Any other subscriber sends `X-Breadbug-Install`. A wrong deletion token
  with no install id is `403`.

`201 {"follow_token": "...", "status": "following"}` on the first follow.
Following again from the same caller rotates the token and returns `200`
with the new `follow_token`, so a client that lost the first response can
recover by retrying; only that caller's token is ever returned. `404`
unknown receipt, `409` stored but not grouped yet (retry after triage groups
it), `403` banned, `429` rate limited. Response fixture:
`tests/fixtures/feedback_follow.json`.

### DELETE /v1/follows/{follow_token}

Stop following. `204` on success, `404` for an unknown token. Pending
notices for the follow are discarded with it.

### GET /v1/reports/{receipt}/status

Coarse state for one report. Rate limited.

```json
{
  "status": "investigating",
  "progress": "in_development",
  "releases": {
    "beta": {"planned": "1.4-beta1", "shipped": true, "shipped_in": "1.4-beta2"},
    "stable": {"planned": "1.4", "shipped": false}
  }
}
```

`status` is one of `received`, `duplicate`, `investigating`, `fixed` (plus
`fixed_in` when a fix version was recorded) or `closed`. `progress` is one
of the stages above; it appears for a linked issue, for a cluster verdict
(`declined`, `deferred`), and for a fixed cluster (`fixed`, or
`targeting_release` when a version was recorded). `releases` appears only
when something is planned or confirmed; response fixture:
`tests/fixtures/feedback_status.json`.
`shipped_in` appears only after a channel ships. Nothing about the cluster
or other followers is revealed. Unknown receipts are `404`.

### GET /v1/follows/{follow_token}/notifications

Pending notices for a follow: fixed, beta, and stable transitions, each
with a stable `id` and text naming the app and the stage:

```json
{"notices": [{"id": 1, "event": "fixed", "text": "A bug you follow in bar has been fixed in 1.3.1. Thanks for helping us improve it!", "at": 1720000000}]}
```

This is a non-destructive peek: a notice stays pending until it is acked, so
a lost response never drops it. Unknown tokens are `404`. Response fixture:
`tests/fixtures/feedback_notifications.json` (fixed, beta and stable).

### POST /v1/follows/{follow_token}/notifications/ack

Acknowledge notices by id so they stop being pending. Body
`{"ids": [1, 2]}`; `200 {"acked": 2}`. Only the ids the client has handled
are cleared, so a client that read but crashed before acking sees them
again. Unknown tokens are `404`.

### GET /v1/follows/{follow_token}/notifications/wait

The no-client-poll channel. The request is held until a notice is queued for
this follow or the wait times out (about 25 seconds), then returns the
pending notices without consuming them (the same shape as the peek, or
`{"notices": []}` on timeout). Ack the ids you showed, then reissue the
wait.

## Example client flow

1. Submit: `POST /v1/reports` with the manual body above. Store `receipt`
   and `deletion_token` on the device.
2. Follow: `POST /v1/reports/{receipt}/follow`. Store `follow_token`. A
   `409` means triage has not grouped it yet; retry later.
3. Read status: `GET /v1/reports/{receipt}/status`. Show `status` always;
   show `progress` when present (`accepted` means a developer took it,
   `in_development` means work started, `fixed` means the code is fixed,
   `targeting_release` means it is aimed at a release, `completed` means
   done, `declined`/`deferred` mean it will not happen).
4. Watch releases: when `releases.beta.shipped` turns true the fix is in
   beta; when `releases.stable.shipped` turns true it is in stable.
5. Watch notices: hold `GET /v1/follows/{token}/notifications/wait`. When it
   returns notices, show each `text` once, then
   `POST /v1/follows/{token}/notifications/ack` with the ids you showed.
6. Delete or unfollow any time with the stored tokens.

## Privacy

- Install ids are random per install and HMAC'd before storage; IPs are
  never stored or logged.
- Only include diagnostics the user agreed to send. Everything is
  re-scrubbed server side; raw reports are deleted after the retention
  window and on request.
- Follow tokens prove the right to read notices. Never log them, never put
  them in URLs outside the path, and never display them.
