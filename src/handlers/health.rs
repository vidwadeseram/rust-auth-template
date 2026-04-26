use axum::Json;
use serde_json::{json, Value};

#[utoipa::path(get, path = "/health", responses((status = 200, description = "Health check OK")), tag = "health")]
pub async fn health_check() -> Json<Value> {
    Json(json!({"status": "ok"}))
}
