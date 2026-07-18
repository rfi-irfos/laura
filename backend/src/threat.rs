use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::Value;

use crate::AppState;

/// A passive *sighting*: one detection module reporting something it
/// observed on the operator's own machine/network. Same spirit as the
/// beacon hits — it is a record of what WAS seen, never an action taken.
#[derive(Debug, Deserialize)]
pub struct Sighting {
    /// Which sense produced it: lumen | umbra | relay | aegis
    pub sense: String,
    /// Specific finding kind: evil_twin, open_ap, arp_spoof, captive_portal, …
    pub kind: String,
    /// low | medium | high
    #[serde(default = "default_severity")]
    pub severity: String,
    /// Human-readable one-liner (already localized by the caller if desired).
    #[serde(default)]
    pub summary: String,
    /// Sense-specific structured evidence (JSON object).
    #[serde(default)]
    pub evidence: Value,
    /// Opaque operator-side tag for the device that ran the scan.
    #[serde(default)]
    pub host: String,
}

fn default_severity() -> String {
    "low".into()
}

const ALLOWED_SENSES: &[&str] = &["lumen", "umbra", "relay", "aegis"];
const ALLOWED_SEVERITIES: &[&str] = &["low", "medium", "high"];

/// POST /threat — accept one passive sighting from a host-side scanner.
///
/// Open by design (like /beacon): the scanner runs on the operator's own
/// machine and only reports what it observed. Nothing here triggers any
/// network action, probe, or attack. What happens with the record is
/// gated behind /internal/review (human review) exactly like beacon hits.
pub async fn report(
    State(state): State<AppState>,
    Json(payload): Json<Sighting>,
) -> impl IntoResponse {
    let sense = if ALLOWED_SENSES.contains(&payload.sense.as_str()) {
        payload.sense
    } else {
        "unknown".to_string()
    };
    let severity = if ALLOWED_SEVERITIES.contains(&payload.severity.as_str()) {
        payload.severity
    } else {
        "low".to_string()
    };
    let evidence =
        serde_json::to_string(&payload.evidence).unwrap_or_else(|_| "{}".to_string());

    let _ = sqlx::query(
        "INSERT INTO threat_sightings (sense, kind, severity, summary, evidence_json, host) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )
    .bind(&sense)
    .bind(&payload.kind)
    .bind(&severity)
    .bind(&payload.summary)
    .bind(&evidence)
    .bind(&payload.host)
    .execute(&state.db)
    .await;

    tracing::info!(
        sense = %sense,
        kind = %payload.kind,
        severity = %severity,
        "threat sighting recorded"
    );
    (StatusCode::ACCEPTED, "recorded").into_response()
}
