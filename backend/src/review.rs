use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

use crate::AppState;

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// GET /internal/review?token=... — RFI-IRFOS-only, everything a human
/// needs to decide whether a hit is worth acting on. Token-gated instead
/// of open, deliberately not linked from anywhere public.
pub async fn show(State(state): State<AppState>, Query(params): Query<HashMap<String, String>>) -> Response {
    let token = params.get("token").cloned().unwrap_or_default();
    if state.review_token.is_empty() || token != state.review_token {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }

    let hits: Vec<(String, String, String, String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT kit_id, ip, user_agent, referrer, created_at FROM beacon_hits ORDER BY created_at DESC LIMIT 500",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let rows = hits
        .iter()
        .map(|(kit, ip, ua, referrer, t)| {
            format!(
                "<tr><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>",
                t.format("%Y-%m-%d %H:%M UTC"),
                esc(kit),
                esc(ip),
                esc(ua),
                esc(referrer)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    Html(format!(
        "<!DOCTYPE html><html lang=\"de\"><head><meta charset=\"utf-8\"><title>LAURA — internal review</title>\
        <style>body{{background:#0b0b0b;color:#ddd;font-family:monospace;font-size:13px;margin:24px}}\
        table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #333;padding:6px 10px;text-align:left}}\
        code{{color:#7fdbff}}</style></head><body>\
        <p>{} treffer insgesamt (max. 500 angezeigt) &mdash; menschliche prüfung, kein automatismus dahinter.</p>\
        <table><tr><th>zeit</th><th>kit</th><th>ip</th><th>user-agent</th><th>referrer</th></tr>{}</table>\
        </body></html>",
        hits.len(),
        rows
    ))
    .into_response()
}
