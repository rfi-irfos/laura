use axum::{
    body::Body,
    extract::{Query, State},
    http::{header, HeaderMap},
    response::{IntoResponse, Response},
};
use std::collections::HashMap;

use crate::AppState;

fn client_ip(headers: &HeaderMap) -> String {
    headers
        .get("fly-client-ip")
        .or_else(|| headers.get("x-forwarded-for"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// GET /beacon/pixel.gif?kit=<id> — fires when a copied kit is opened
/// anywhere, from any browser. Same mechanism as any website's own
/// visitor log: the opener's browser made a normal image request, we
/// record what it sent. No code runs on their device beyond that request.
pub async fn pixel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let kit_id = params.get("kit").cloned().unwrap_or_default();
    let ip = client_ip(&headers);
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let referrer = headers
        .get(header::REFERER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    if !kit_id.is_empty() {
        let _ = sqlx::query(
            "INSERT INTO beacon_hits (kit_id, ip, user_agent, referrer) VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(&kit_id)
        .bind(&ip)
        .bind(&user_agent)
        .bind(&referrer)
        .execute(&state.db)
        .await;
        tracing::info!(kit = %kit_id, ip = %ip, "beacon hit recorded");
    }

    const GIF: [u8; 43] = [
        0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xff, 0xff, 0xff, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
    ];
    (
        [
            (header::CONTENT_TYPE, "image/gif"),
            (header::CACHE_CONTROL, "no-store, max-age=0"),
            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
        ],
        Body::from(GIF.to_vec()),
    )
        .into_response()
}
