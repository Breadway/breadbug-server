//! The triage inbox: a small server-rendered admin UI on its own listener.
//!
//! Everything shown here is attacker-controlled text, so every value goes
//! through [`esc`] on the way out and the pages carry a locked-down
//! Content-Security-Policy (no scripts at all). Authentication is a bearer
//! token (hash configured in `BREADBUG_ADMIN_TOKEN_SHA256`) or a session
//! cookie derived from it; cookie sessions also need a CSRF token on every
//! POST. The listener is not routed publicly.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{Form, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;
use serde_json::Value;

use crate::app::{now_unix, AppState};
use crate::crypto::{ct_eq, hmac_hex, keyed_u64, sha256_hex};
use crate::db::{ClusterRow, STATUSES};
use crate::triage::{score, Score};

const COOKIE: &str = "bb_admin";

/// HTML-escape untrusted text.
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c if c.is_control() && c != '\n' => out.push('\u{fffd}'),
            c => out.push(c),
        }
    }
    out
}

/// `2026-10-09 07:21` (UTC) from unix seconds.
pub fn fmt_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // civil-from-days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}",
        rem / 3600,
        (rem % 3600) / 60
    )
}

fn security_headers(resp: &mut Response) {
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        ),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
}

fn html(status: StatusCode, title: &str, body: &str) -> Response {
    let doc = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>{}</title><style>{CSS}</style></head><body><header><a href=\"/admin/\">breadbug triage</a> \
         <nav><a href=\"/admin/\">inbox</a> <a href=\"/admin/quarantine\">quarantine</a> <a href=\"/admin/symbols\">missing symbols</a></nav></header>\
         <main>{body}</main></body></html>",
        esc(title)
    );
    let mut r = (
        status,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        doc,
    )
        .into_response();
    security_headers(&mut r);
    r
}

const CSS: &str = "body{font:14px/1.45 system-ui,sans-serif;margin:0;color:#1b1b1f;background:#f6f6f8}\
header{background:#26262c;color:#fff;padding:.6rem 1rem;display:flex;gap:1.5rem;align-items:baseline}\
header a{color:#fff;text-decoration:none;font-weight:600}nav a{font-weight:400;margin-right:1rem;opacity:.85}\
main{max-width:1100px;margin:1rem auto;padding:0 1rem}table{border-collapse:collapse;width:100%;background:#fff}\
th,td{padding:.4rem .6rem;border-bottom:1px solid #e3e3e8;text-align:left;vertical-align:top}th{background:#ececf1}\
code,pre{font:12px/1.4 ui-monospace,monospace}pre{background:#fff;border:1px solid #e3e3e8;padding:.6rem;overflow:auto;white-space:pre-wrap}\
.tag{display:inline-block;padding:0 .4rem;border-radius:3px;background:#e3e3e8}.crash{background:#f8d7da}.freeze{background:#ffe8b3}\
form.inline{display:inline}fieldset{border:1px solid #d5d5dc;margin:.8rem 0;background:#fff}button,input,select{font:inherit}\
.muted{color:#6a6a74}.score{font-weight:700}";

/// A page for an error or notice.
fn notice(status: StatusCode, msg: &str) -> Response {
    html(status, "breadbug", &format!("<p>{}</p>", esc(msg)))
}

// ------------------------------------------------------------------- auth

struct Session {
    /// Cookie sessions need CSRF protection; bearer tokens do not.
    csrf: Option<String>,
}

fn admin_hash(s: &AppState) -> Option<&str> {
    s.cfg.admin_token_sha256.as_deref()
}

fn session_cookie_value(s: &AppState) -> Option<String> {
    admin_hash(s).map(|h| hmac_hex(s.secret(), "admin-session", h.as_bytes()))
}

fn csrf_for(s: &AppState, session_value: &str) -> String {
    hmac_hex(s.secret(), "admin-csrf", session_value.as_bytes())
}

fn cookie_value(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    raw.split(';')
        .filter_map(|p| p.trim().split_once('='))
        .find(|(k, _)| *k == COOKIE)
        .map(|(_, v)| v.to_string())
}

#[allow(clippy::result_large_err)] // the Err is a ready-made redirect response
fn authenticate(s: &AppState, headers: &HeaderMap) -> Result<Session, Response> {
    let Some(expected_hash) = admin_hash(s) else {
        return Err(StatusCode::NOT_FOUND.into_response());
    };
    if let Some(tok) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        if ct_eq(&sha256_hex(tok.as_bytes()), expected_hash) {
            return Ok(Session { csrf: None });
        }
    }
    if let (Some(cookie), Some(expected)) = (cookie_value(headers), session_cookie_value(s)) {
        if ct_eq(&cookie, &expected) {
            return Ok(Session {
                csrf: Some(csrf_for(s, &expected)),
            });
        }
    }
    Err(Redirect::to("/admin/login").into_response())
}

/// Whether a POST may proceed: bearer sessions always; cookie sessions need
/// the matching CSRF token.
fn csrf_ok(session: &Session, submitted: &str) -> bool {
    match &session.csrf {
        None => true,
        Some(expected) => ct_eq(expected, submitted),
    }
}

fn csrf_field(session: &Session) -> String {
    session.csrf.as_ref().map_or(String::new(), |t| {
        format!("<input type=\"hidden\" name=\"csrf\" value=\"{}\">", esc(t))
    })
}

#[derive(Deserialize)]
struct LoginForm {
    token: String,
}

async fn login_page(State(s): State<Arc<AppState>>) -> Response {
    if admin_hash(&s).is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    html(
        StatusCode::OK,
        "sign in",
        "<h1>Sign in</h1><form method=\"post\" action=\"/admin/login\"><label>Admin token \
         <input type=\"password\" name=\"token\" autocomplete=\"current-password\" autofocus></label> <button>Sign in</button></form>",
    )
}

async fn login_submit(State(s): State<Arc<AppState>>, Form(f): Form<LoginForm>) -> Response {
    let Some(expected_hash) = admin_hash(&s) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if s.login_limiter()
        .check(keyed_u64(s.secret(), "login", b""), Instant::now())
        .is_err()
    {
        return notice(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many attempts. Wait a few minutes.",
        );
    }
    if !ct_eq(&sha256_hex(f.token.as_bytes()), expected_hash) {
        return notice(StatusCode::UNAUTHORIZED, "Wrong token.");
    }
    let Some(value) = session_cookie_value(&s) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mut r = Redirect::to("/admin/").into_response();
    if let Ok(v) = HeaderValue::from_str(&format!(
        "{COOKIE}={value}; HttpOnly; SameSite=Strict; Path=/admin; Max-Age=28800"
    )) {
        r.headers_mut().insert(header::SET_COOKIE, v);
    }
    r
}

// ------------------------------------------------------------------ inbox

#[derive(Deserialize, Default)]
struct InboxQuery {
    status: Option<String>,
    app: Option<String>,
    kind: Option<String>,
}

fn score_of(s: &AppState, c: &ClusterRow) -> Score {
    score(c, now_unix(), s.rules())
}

async fn inbox(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<InboxQuery>,
) -> Response {
    if let Err(r) = authenticate(&s, &headers) {
        return r;
    }
    let db = s.db.clone();
    let Ok(Ok(clusters)) = tokio::task::spawn_blocking(move || db.clusters()).await else {
        return notice(StatusCode::INTERNAL_SERVER_ERROR, "could not load clusters");
    };
    let filter = q.status.as_deref().unwrap_or("open");
    let mut rows: Vec<(Score, ClusterRow)> = clusters
        .into_iter()
        .filter(|c| match filter {
            "all" => true,
            "open" => matches!(c.status.as_str(), "new" | "investigating" | "regressed"),
            other => c.status == other,
        })
        .filter(|c| q.app.as_deref().is_none_or(|a| a.is_empty() || c.app == a))
        .filter(|c| {
            q.kind
                .as_deref()
                .is_none_or(|k| k.is_empty() || c.kind == k)
        })
        .map(|c| (score_of(&s, &c), c))
        .collect();
    rows.sort_by(|a, b| {
        b.0.total
            .cmp(&a.0.total)
            .then(b.1.last_seen.cmp(&a.1.last_seen))
    });

    let mut body = String::from("<h1>Inbox</h1><p>");
    for f in ["open", "all", "promoted", "fixed", "dismissed"] {
        let _ = write!(
            body,
            "<a href=\"/admin/?status={f}\" class=\"tag\">{f}</a> "
        );
    }
    body.push_str("</p><p>kind:");
    for k in ["crash", "freeze", "behavior", "manual", "request"] {
        let _ = write!(body, "<a href=\"/admin/?kind={k}\" class=\"tag\">{k}</a> ");
    }
    body.push_str("</p><table><tr><th>score</th><th>problem</th><th>app</th><th>kind</th><th>reports</th><th>installs</th><th>versions</th><th>last seen</th><th>status</th></tr>");
    if rows.is_empty() {
        body.push_str("<tr><td colspan=\"9\" class=\"muted\">Nothing here.</td></tr>");
    }
    for (sc, c) in &rows {
        let _ = write!(
            body,
            "<tr><td class=\"score\">{}</td><td><a href=\"/admin/clusters/{}\">{}</a></td><td>{}</td>\
             <td><span class=\"tag {}\">{}</span></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            sc.total,
            c.id,
            esc(&c.title),
            esc(&c.app),
            esc(&c.kind),
            esc(&c.kind),
            c.count,
            c.installs,
            c.versions.len(),
            fmt_utc(c.last_seen),
            esc(&c.status)
        );
    }
    body.push_str("</table>");
    html(StatusCode::OK, "inbox", &body)
}

// ----------------------------------------------------------------- detail

fn frames_html(frames: &[Value]) -> String {
    let mut out = String::new();
    for f in frames.iter().take(12) {
        let sym = f["symbol"].as_str();
        let module = f["module"].as_str();
        let off = f["offset"].as_u64();
        let label = match (sym, module, off) {
            (Some(s), _, _) => s.to_string(),
            (None, Some(m), Some(o)) => format!("{m}+{o:#x}"),
            (None, None, Some(o)) => format!("{o:#x}"),
            _ => "?".to_string(),
        };
        let at = match (f["file"].as_str(), f["line"].as_u64()) {
            (Some(file), Some(line)) => format!("  at {file}:{line}"),
            (Some(file), None) => format!("  at {file}"),
            _ => String::new(),
        };
        let _ = writeln!(out, "{}{}", esc(&label), esc(&at));
    }
    out
}

fn sample_html(raw: &str) -> String {
    let Ok(v) = serde_json::from_str::<Value>(raw) else {
        return "<p class=\"muted\">unreadable report</p>".to_string();
    };
    let mut out = String::new();
    if let Some(t) = v["title"].as_str().filter(|t| !t.is_empty()) {
        let _ = write!(out, "<p><b>Title:</b> {}</p>", esc(t));
    }
    if let Some(w) = v["want"].as_str().filter(|w| !w.is_empty()) {
        let _ = write!(out, "<p><b>Wants:</b> {}</p>", esc(w));
    }
    if let Some(n) = v["notes"].as_str().filter(|n| !n.is_empty()) {
        let label = if v["report_type"].as_str() == Some("request") {
            "Why"
        } else {
            "Notes"
        };
        let _ = write!(out, "<p><b>{label}:</b> {}</p>", esc(n));
    }
    if let Some(m) = v["markers"].as_array().and_then(|m| m.last()) {
        if let Some(msg) = m["message"].as_str() {
            let _ = write!(
                out,
                "<p><b>{}:</b> {}</p>",
                esc(m["kind"].as_str().unwrap_or("marker")),
                esc(msg)
            );
        }
        if let Some(fr) = m["frames"].as_array().filter(|f| !f.is_empty()) {
            let _ = write!(out, "<pre>{}</pre>", frames_html(fr));
        }
    }
    if let Some(fr) = v["live_stack"].as_array().filter(|f| !f.is_empty()) {
        let _ = write!(
            out,
            "<p><b>Live stack:</b></p><pre>{}</pre>",
            frames_html(fr)
        );
    }
    let important: Vec<String> = v["logs"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(v["daemon_logs"].as_array().into_iter().flatten())
        .filter(|l| matches!(l["level"].as_str(), Some("WARN" | "ERROR")))
        .rev()
        .take(5)
        .map(|l| {
            format!(
                "{} {}",
                l["level"].as_str().unwrap_or(""),
                l["msg"].as_str().unwrap_or("")
            )
        })
        .collect();
    if !important.is_empty() {
        let _ = write!(out, "<pre>{}</pre>", esc(&important.join("\n")));
    }
    out
}

fn kv_table(m: &BTreeMap<String, u64>) -> String {
    if m.is_empty() {
        return "<span class=\"muted\">none</span>".into();
    }
    let mut s = String::from("<table>");
    for (k, n) in m {
        let _ = write!(s, "<tr><td>{}</td><td>{n}</td></tr>", esc(k));
    }
    s.push_str("</table>");
    s
}

async fn detail(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    let session = match authenticate(&s, &headers) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let db = s.db.clone();
    let Ok(Ok(Some(c))) = tokio::task::spawn_blocking({
        let db = db.clone();
        move || db.cluster(id)
    })
    .await
    else {
        return notice(StatusCode::NOT_FOUND, "No such cluster.");
    };
    let samples = tokio::task::spawn_blocking(move || db.cluster_samples(id, 5))
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default();
    let followers = tokio::task::spawn_blocking({
        let db = s.db.clone();
        move || db.follow_count(id)
    })
    .await
    .ok()
    .and_then(Result::ok)
    .unwrap_or(0);
    if let Some(target) = c.merged_into {
        return html(
            StatusCode::OK,
            "merged",
            &format!("<p>This cluster was merged into <a href=\"/admin/clusters/{target}\">#{target}</a>.</p>"),
        );
    }
    let sc = score_of(&s, &c);
    let mut b = String::new();
    let _ = write!(
        b,
        "<h1>{}</h1><p><span class=\"tag {k}\">{k}</span> app <b>{}</b> status <b>{}</b> \
         score <span class=\"score\">{}</span></p>",
        esc(&c.title),
        esc(&c.app),
        esc(&c.status),
        sc.total,
        k = esc(&c.kind)
    );
    b.push_str("<p class=\"muted\">score: ");
    b.push_str(
        &sc.parts
            .iter()
            .map(|(n, p)| format!("{} {p:+}", esc(n)))
            .collect::<Vec<_>>()
            .join(", "),
    );
    b.push_str("</p>");
    let _ = write!(
        b,
        "<p>{} report(s) from {} install(s), {} follower(s), first {} last {}{}{}</p>",
        c.count,
        c.installs,
        followers,
        fmt_utc(c.first_seen),
        fmt_utc(c.last_seen),
        c.fixed_in
            .as_deref()
            .map_or(String::new(), |v| format!(", fixed in {}", esc(v))),
        c.issue_key.as_deref().map_or(String::new(), |k| format!(
            ", issue {} ({})",
            esc(k),
            esc(c.issue_status.as_deref().unwrap_or("status unknown"))
        ))
    );
    let _ = write!(
        b,
        "<h2>Versions</h2>{}<h2>OS builds</h2>{}",
        kv_table(&c.versions),
        kv_table(&c.os_builds)
    );
    let csrf = csrf_field(&session);
    let mut status_opts = String::new();
    for st in STATUSES {
        let sel = if *st == c.status { " selected" } else { "" };
        let _ = write!(status_opts, "<option{sel}>{st}</option>");
    }
    let _ = write!(
        b,
        "<fieldset><legend>Actions</legend>\
         <form class=\"inline\" method=\"post\" action=\"/admin/clusters/{id}/status\">{csrf}<select name=\"status\">{status_opts}</select> <button>Set status</button></form> \
         <form class=\"inline\" method=\"post\" action=\"/admin/clusters/{id}/fixed\">{csrf}<input name=\"version\" placeholder=\"fixed in version\" size=\"14\"> <button>Mark fixed</button></form> \
         <form class=\"inline\" method=\"post\" action=\"/admin/clusters/{id}/merge\">{csrf}<input name=\"into\" placeholder=\"merge into #\" size=\"10\"> <button>Merge</button></form>{promote}\
         </fieldset>",
        id = c.id,
        promote = if s.board().is_some() && c.issue_key.is_none() && c.status != "dismissed" {
            format!(
                " <form class=\"inline\" method=\"post\" action=\"/admin/clusters/{}/promote\">{csrf}<button>Promote to breadboard issue</button></form>",
                c.id
            )
        } else {
            String::new()
        }
    );
    fn channel_line(name: &str, planned: &Option<String>, confirmed: &Option<String>) -> String {
        match (planned, confirmed) {
            (None, None) => format!("{name}: not planned"),
            (p, c) => format!(
                "{name}: planned {}{}",
                esc(p.as_deref().unwrap_or("?")),
                c.as_deref()
                    .map_or(String::from(" (not shipped)"), |v| format!(
                        " (shipped {})",
                        esc(v)
                    ))
            ),
        }
    }
    let _ = write!(
        b,
        "<h2>Releases</h2><p>{} &middot; {}</p>\
         <fieldset><legend>Plan</legend>\
         <form class=\"inline\" method=\"post\" action=\"/admin/clusters/{id}/release-target\">{csrf}<input type=\"hidden\" name=\"channel\" value=\"beta\"><input name=\"version\" placeholder=\"target beta\" size=\"12\"> <button>Set beta target</button></form> \
         <form class=\"inline\" method=\"post\" action=\"/admin/clusters/{id}/release-target\">{csrf}<input type=\"hidden\" name=\"channel\" value=\"stable\"><input name=\"version\" placeholder=\"target stable\" size=\"12\"> <button>Set stable target</button></form>\
         </fieldset> \
         <fieldset><legend>Confirm shipped</legend>\
         <form class=\"inline\" method=\"post\" action=\"/admin/clusters/{id}/release-confirmed\">{csrf}<input type=\"hidden\" name=\"channel\" value=\"beta\"><input name=\"version\" placeholder=\"shipped beta\" size=\"12\"> <button>Confirm beta</button></form> \
         <form class=\"inline\" method=\"post\" action=\"/admin/clusters/{id}/release-confirmed\">{csrf}<input type=\"hidden\" name=\"channel\" value=\"stable\"><input name=\"version\" placeholder=\"shipped stable\" size=\"12\"> <button>Confirm stable</button></form>\
         </fieldset>",
        channel_line("beta", &c.target_beta, &c.confirmed_beta),
        channel_line("stable", &c.target_stable, &c.confirmed_stable),
    );
    let _ = write!(b, "<h2>Latest reports</h2>");
    for sm in &samples {
        let _ = write!(
            b,
            "<fieldset><legend>{} &middot; {} &middot; v{} &middot; <code>{}</code></legend>{}</fieldset>",
            esc(&fmt_utc(sm.received_at)),
            esc(&c.app),
            esc(sm.app_version.as_deref().unwrap_or("?")),
            esc(&sm.receipt[..8.min(sm.receipt.len())]),
            sample_html(&sm.raw)
        );
    }
    html(StatusCode::OK, &c.title, &b)
}

#[derive(Deserialize)]
struct StatusForm {
    csrf: Option<String>,
    status: String,
}

#[derive(Deserialize)]
struct FixedForm {
    csrf: Option<String>,
    version: String,
}

#[derive(Deserialize)]
struct MergeForm {
    csrf: Option<String>,
    into: String,
}

#[derive(Deserialize)]
struct ReleaseForm {
    csrf: Option<String>,
    channel: String,
    version: String,
}

fn back_to(id: i64) -> Response {
    Redirect::to(&format!("/admin/clusters/{id}")).into_response()
}

async fn set_status(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Form(f): Form<StatusForm>,
) -> Response {
    let session = match authenticate(&s, &headers) {
        Ok(x) => x,
        Err(r) => return r,
    };
    if !csrf_ok(&session, f.csrf.as_deref().unwrap_or("")) {
        return notice(StatusCode::FORBIDDEN, "Bad CSRF token.");
    }
    let db = s.db.clone();
    match tokio::task::spawn_blocking(move || db.set_status(id, &f.status)).await {
        Ok(Ok(true)) => back_to(id),
        Ok(Ok(false)) => notice(StatusCode::BAD_REQUEST, "Unknown cluster or status."),
        _ => notice(StatusCode::INTERNAL_SERVER_ERROR, "Could not update."),
    }
}

async fn mark_fixed(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Form(f): Form<FixedForm>,
) -> Response {
    let session = match authenticate(&s, &headers) {
        Ok(x) => x,
        Err(r) => return r,
    };
    if !csrf_ok(&session, f.csrf.as_deref().unwrap_or("")) {
        return notice(StatusCode::FORBIDDEN, "Bad CSRF token.");
    }
    let version = f.version.trim().to_string();
    if version.is_empty() || version.len() > 64 {
        return notice(
            StatusCode::BAD_REQUEST,
            "Enter the version the fix shipped in.",
        );
    }
    let db = s.db.clone();
    let wake = s.notice_wake().clone();
    match tokio::task::spawn_blocking(move || {
        let Some(c) = db.cluster(id)? else {
            return anyhow::Ok(false);
        };
        let text = crate::lifecycle::notice_text(&c, "fixed", Some(&version));
        let changed =
            db.mark_fixed_and_notify(id, Some(&version), "fixed", &text, crate::app::now_unix())?;
        if changed {
            let _ = wake.send(());
        }
        anyhow::Ok(changed)
    })
    .await
    {
        Ok(Ok(true)) => back_to(id),
        Ok(Ok(false)) => notice(StatusCode::BAD_REQUEST, "Unknown cluster."),
        _ => notice(StatusCode::INTERNAL_SERVER_ERROR, "Could not update."),
    }
}

async fn merge(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Form(f): Form<MergeForm>,
) -> Response {
    let session = match authenticate(&s, &headers) {
        Ok(x) => x,
        Err(r) => return r,
    };
    if !csrf_ok(&session, f.csrf.as_deref().unwrap_or("")) {
        return notice(StatusCode::FORBIDDEN, "Bad CSRF token.");
    }
    let Ok(into) = f.into.trim().trim_start_matches('#').parse::<i64>() else {
        return notice(StatusCode::BAD_REQUEST, "Enter a cluster number.");
    };
    let state = s.clone();
    match tokio::task::spawn_blocking(move || {
        let merged = state.db.merge_clusters(id, into)?;
        if !merged {
            return Ok::<Option<i64>, anyhow::Error>(None);
        }
        let target = state.db.resolve_cluster_id(into)?;
        // Fold the moved reports into the survivor's vector. Without this,
        // the wording that was just merged in still matches nothing and the
        // same duplicate starts a fresh cluster next time.
        if let Err(e) = crate::cluster::reembed_cluster(&state.db, state.fuzzy().embedder, target)
        {
            tracing::error!(error = %e, "reembed after merge failed");
        }
        Ok(Some(target))
    })
    .await
    {
        Ok(Ok(Some(target))) => Redirect::to(&format!("/admin/clusters/{target}")).into_response(),
        Ok(Ok(None)) => notice(
            StatusCode::BAD_REQUEST,
            "Cannot merge (unknown, same cluster, or different app).",
        ),
        _ => notice(StatusCode::INTERNAL_SERVER_ERROR, "Could not merge."),
    }
}

fn release_version(raw: &str) -> Option<String> {
    let v = raw.trim().to_string();
    (!v.is_empty()).then_some(v)
}

async fn set_release_target(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Form(f): Form<ReleaseForm>,
) -> Response {
    let session = match authenticate(&s, &headers) {
        Ok(x) => x,
        Err(r) => return r,
    };
    if !csrf_ok(&session, f.csrf.as_deref().unwrap_or("")) {
        return notice(StatusCode::FORBIDDEN, "Bad CSRF token.");
    }
    let (channel, version) = (f.channel.trim().to_string(), release_version(&f.version));
    let Some(version) = version else {
        return notice(StatusCode::BAD_REQUEST, "Enter a target release version.");
    };
    let db = s.db.clone();
    match tokio::task::spawn_blocking(move || db.set_release_target(id, &channel, &version)).await {
        Ok(Ok(true)) => back_to(id),
        Ok(Ok(false)) => notice(
            StatusCode::BAD_REQUEST,
            "Unknown cluster, channel, or version (beta must not be newer than stable).",
        ),
        _ => notice(StatusCode::INTERNAL_SERVER_ERROR, "Could not update."),
    }
}

async fn mark_release_confirmed(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Form(f): Form<ReleaseForm>,
) -> Response {
    let session = match authenticate(&s, &headers) {
        Ok(x) => x,
        Err(r) => return r,
    };
    if !csrf_ok(&session, f.csrf.as_deref().unwrap_or("")) {
        return notice(StatusCode::FORBIDDEN, "Bad CSRF token.");
    }
    let (channel, version) = (f.channel.trim().to_string(), release_version(&f.version));
    let Some(version) = version else {
        return notice(
            StatusCode::BAD_REQUEST,
            "Enter the release version that shipped.",
        );
    };
    let db = s.db.clone();
    let wake = s.notice_wake().clone();
    match tokio::task::spawn_blocking(move || {
        let Some(c) = db.cluster(id)? else {
            return anyhow::Ok(false);
        };
        let text = crate::lifecycle::notice_text(&c, &channel, Some(&version));
        let changed = db.confirm_and_notify(
            id,
            &channel,
            &version,
            &channel,
            &text,
            crate::app::now_unix(),
        )?;
        if changed {
            let _ = wake.send(());
        }
        anyhow::Ok(changed)
    })
    .await
    {
        Ok(Ok(true)) => back_to(id),
        Ok(Ok(false)) => notice(
            StatusCode::BAD_REQUEST,
            "Unknown cluster or channel, or no planned target to confirm.",
        ),
        _ => notice(StatusCode::INTERNAL_SERVER_ERROR, "Could not update."),
    }
}

async fn promote(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Form(f): Form<CsrfOnly>,
) -> Response {
    let session = match authenticate(&s, &headers) {
        Ok(x) => x,
        Err(r) => return r,
    };
    if !csrf_ok(&session, f.csrf.as_deref().unwrap_or("")) {
        return notice(StatusCode::FORBIDDEN, "Bad CSRF token.");
    }
    let st = s.clone();
    match tokio::task::spawn_blocking(move || crate::lifecycle::promote(&st, id)).await {
        Ok(Ok(_key)) => back_to(id),
        Ok(Err(e)) => notice(StatusCode::BAD_REQUEST, &format!("Could not promote: {e}")),
        Err(_) => notice(StatusCode::INTERNAL_SERVER_ERROR, "Could not promote."),
    }
}

// ------------------------------------------------------- quarantine & symbols

async fn quarantine(State(s): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let session = match authenticate(&s, &headers) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let db = s.db.clone();
    let rows = tokio::task::spawn_blocking(move || db.quarantined(50))
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default();
    let csrf = csrf_field(&session);
    let mut b = String::from(
        "<h1>Quarantine</h1><p class=\"muted\">Reports where the server's scrub found something the client's did not. \
         They are stored scrubbed and kept out of clusters until released.</p>",
    );
    if rows.is_empty() {
        b.push_str("<p>Empty.</p>");
    }
    for r in rows {
        let _ = write!(
            b,
            "<fieldset><legend>{} &middot; {} &middot; <code>{}</code> &middot; scrub hits {}</legend>{}\
             <form class=\"inline\" method=\"post\" action=\"/admin/quarantine/{id}/release\">{csrf}<button>Release</button></form> \
             <form class=\"inline\" method=\"post\" action=\"/admin/quarantine/{id}/delete\">{csrf}<button>Delete</button></form> \
             <form class=\"inline\" method=\"post\" action=\"/admin/quarantine/{id}/ban\">{csrf}<button>Delete + ban install</button></form></fieldset>",
            esc(&fmt_utc(r.received_at)),
            esc(&r.app),
            esc(&r.receipt[..8.min(r.receipt.len())]),
            esc(&r.hits),
            sample_html(&r.raw),
            id = r.id
        );
    }
    html(StatusCode::OK, "quarantine", &b)
}

#[derive(Deserialize)]
struct CsrfOnly {
    csrf: Option<String>,
}

async fn quarantine_action(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, action)): Path<(i64, String)>,
    Form(f): Form<CsrfOnly>,
) -> Response {
    let session = match authenticate(&s, &headers) {
        Ok(x) => x,
        Err(r) => return r,
    };
    if !csrf_ok(&session, f.csrf.as_deref().unwrap_or("")) {
        return notice(StatusCode::FORBIDDEN, "Bad CSRF token.");
    }
    let state = s.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<bool> {
        match action.as_str() {
            "release" => {
                let Some(stored) = state.db.release_quarantine(id)? else {
                    return Ok(false);
                };
                if let Ok(report) = serde_json::from_str::<crate::schema::Report>(&stored.raw) {
                    crate::cluster::assign(
                        &state.db,
                        stored.id,
                        &report,
                        &stored.install_hash,
                        Some(&state.fuzzy()),
                    )?;
                }
                Ok(true)
            }
            "delete" => state.db.delete_report_by_id(id),
            "ban" => {
                let banned = state
                    .db
                    .ban_install_of_report(id, "quarantine review", now_unix())?;
                let deleted = state.db.delete_report_by_id(id)?;
                Ok(banned && deleted)
            }
            _ => Ok(false),
        }
    })
    .await;
    match result {
        Ok(Ok(true)) => Redirect::to("/admin/quarantine").into_response(),
        Ok(Ok(false)) => notice(StatusCode::BAD_REQUEST, "Nothing to do."),
        _ => notice(StatusCode::INTERNAL_SERVER_ERROR, "Action failed."),
    }
}

async fn symbols_page(State(s): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(r) = authenticate(&s, &headers) {
        return r;
    }
    let db = s.db.clone();
    let rows = tokio::task::spawn_blocking(move || db.missing_symbols())
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default();
    let mut b = String::from(
        "<h1>Missing symbols</h1><p class=\"muted\">Build-ids reports asked about that the symbol store does not have.</p>\
         <table><tr><th>build-id</th><th>app</th><th>version</th><th>requests</th></tr>",
    );
    if rows.is_empty() {
        b.push_str("<tr><td colspan=\"4\" class=\"muted\">None.</td></tr>");
    }
    for (id, app, ver, n) in rows {
        let _ = write!(
            b,
            "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{n}</td></tr>",
            esc(&id),
            esc(&app),
            esc(ver.as_deref().unwrap_or("?"))
        );
    }
    b.push_str("</table>");
    html(StatusCode::OK, "missing symbols", &b)
}

/// The admin router. Without a configured token every route is a 404.
pub fn admin_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/admin/login", get(login_page).post(login_submit))
        .route("/admin/", get(inbox))
        .route("/admin/clusters/{id}", get(detail))
        .route("/admin/clusters/{id}/status", post(set_status))
        .route("/admin/clusters/{id}/fixed", post(mark_fixed))
        .route("/admin/clusters/{id}/merge", post(merge))
        .route("/admin/clusters/{id}/promote", post(promote))
        .route(
            "/admin/clusters/{id}/release-target",
            post(set_release_target),
        )
        .route(
            "/admin/clusters/{id}/release-confirmed",
            post(mark_release_confirmed),
        )
        .route("/admin/quarantine", get(quarantine))
        .route("/admin/quarantine/{id}/{action}", post(quarantine_action))
        .route("/admin/symbols", get(symbols_page))
        .route("/healthz", get(|| async { "ok" }))
        .layer(axum::extract::DefaultBodyLimit::max(16 * 1024))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping_covers_markup_quotes_and_controls() {
        assert_eq!(
            esc("<script>alert('x')</script>"),
            "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;"
        );
        assert_eq!(esc("a\"b&c"), "a&quot;b&amp;c");
        assert_eq!(esc("a\u{1b}[31mb"), "a\u{fffd}[31mb");
        assert_eq!(esc("line1\nline2"), "line1\nline2");
    }

    #[test]
    fn utc_formatting() {
        assert_eq!(fmt_utc(0), "1970-01-01 00:00");
        assert_eq!(fmt_utc(1_791_510_900), "2026-10-09 01:55");
        assert_eq!(fmt_utc(951_782_400 + 3600 + 60), "2000-02-29 01:01");
    }
}
