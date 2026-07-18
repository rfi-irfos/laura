mod beacon;
mod lookup;
mod review;
mod threat;

use axum::{routing::{get, post}, Router};
use sqlx::SqlitePool;
use tower_http::cors::CorsLayer;

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
    pub review_token: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    dotenvy::dotenv().ok();

    let db_path = std::env::var("DB_PATH").unwrap_or("laura.db".into());
    let db = SqlitePool::connect(&format!("sqlite://{}?mode=rwc", db_path))
        .await
        .expect("open laura.db");

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS beacon_hits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kit_id TEXT NOT NULL,
            ip TEXT NOT NULL DEFAULT '',
            user_agent TEXT NOT NULL DEFAULT '',
            referrer TEXT NOT NULL DEFAULT '',
            created_at DATETIME NOT NULL DEFAULT (datetime('now'))
        )",
    )
    .execute(&db)
    .await
    .expect("create beacon_hits");
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_bh_kit ON beacon_hits(kit_id, created_at)")
        .execute(&db)
        .await
        .ok();

    // Passive threat sightings from host-side detection modules (lumen/umbra/relay).
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS threat_sightings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sense TEXT NOT NULL DEFAULT 'unknown',
            kind TEXT NOT NULL DEFAULT '',
            severity TEXT NOT NULL DEFAULT 'low',
            summary TEXT NOT NULL DEFAULT '',
            evidence_json TEXT NOT NULL DEFAULT '{}',
            host TEXT NOT NULL DEFAULT '',
            created_at DATETIME NOT NULL DEFAULT (datetime('now'))
        )",
    )
    .execute(&db)
    .await
    .expect("create threat_sightings");
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_ts_sense ON threat_sightings(sense, created_at)",
    )
    .execute(&db)
    .await
    .ok();

    let review_token = std::env::var("REVIEW_TOKEN").unwrap_or_else(|_| {
        tracing::warn!("REVIEW_TOKEN not set — /internal/review is unreachable until it is");
        "".into()
    });

    let state = AppState { db, review_token };

    let app = Router::new()
        .route("/", get(|| async { "LAURA backend — see /beacon, /lookup/:code" }))
        .route("/beacon/pixel.gif", get(beacon::pixel))
        .route("/lookup/:code", get(lookup::show))
        .route("/threat", post(threat::report))
        .route("/internal/review", get(review::show))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let port: u16 = std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(3000);
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await.unwrap();
    tracing::info!("LAURA backend listening on :{}", port);
    axum::serve(listener, app).await.unwrap();
}
