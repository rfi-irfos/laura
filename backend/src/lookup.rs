use axum::{
    extract::{Path, State},
    response::Html,
};
use chrono::{DateTime, Utc};

use crate::AppState;

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// GET /lookup/:code — the woman's own private view of her kit. Shows
/// only whether/when it triggered, never the raw IP/user-agent recorded
/// for a hit — that stays inside /internal/review for a human to relay
/// if it's ever actually needed for a report.
pub async fn show(State(state): State<AppState>, Path(code): Path<String>) -> Html<String> {
    let hits: Vec<(DateTime<Utc>,)> = sqlx::query_as(
        "SELECT created_at FROM beacon_hits WHERE kit_id = ?1 ORDER BY created_at DESC",
    )
    .bind(&code)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let body = if hits.is_empty() {
        "<p>noch nicht ausgelöst. das heißt entweder: alles ruhig, oder der köder wurde noch nicht geöffnet.</p>".to_string()
    } else {
        let rows = hits
            .iter()
            .map(|(t,)| format!("<li>{}</li>", t.format("%Y-%m-%d %H:%M UTC")))
            .collect::<Vec<_>>()
            .join("\n");
        format!(
            "<p><strong>{} mal ausgelöst.</strong> ein mensch bei RFI-IRFOS prüft jeden treffer, es passiert nichts automatisch.</p><ul>{}</ul>",
            hits.len(),
            rows
        )
    };

    Html(format!(
        "<!DOCTYPE html><html lang=\"de\"><head><meta charset=\"utf-8\"><title>LAURA — lookup</title>\
        <style>body{{background:#0f172a;color:#f1f5f9;font-family:Georgia,serif;max-width:560px;margin:60px auto;padding:0 20px;line-height:1.7}}</style></head><body>\
        code{{background:#243348;padding:2px 6px;border-radius:3px}}</style></head><body>\
        <p>code: <code>{}</code></p>{}</body></html>",
        esc(&code), body
    ))
}
