use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};

struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

pub struct RateLimiter {
    buckets: Mutex<HashMap<String, Bucket>>,
    rate: f64,
    burst: f64,
}

impl RateLimiter {
    pub fn new(rate: f64, burst: f64) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            rate,
            burst,
        }
    }

    pub async fn middleware(request: Request, next: Next) -> Response {
        let limiter = request
            .extensions()
            .get::<std::sync::Arc<Self>>()
            .cloned();

        if let Some(limiter) = limiter {
            let ip = request
                .headers()
                .get("x-forwarded-for")
                .or_else(|| request.headers().get("x-real-ip"))
                .and_then(|v| v.to_str().ok())
                .unwrap_or("unknown")
                .split(',')
                .next()
                .unwrap_or("unknown")
                .trim()
                .to_string();

            if !limiter.allow(&ip) {
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(serde_json::json!({
                        "error": {
                            "code": "RATE_LIMITED",
                            "message": "Too many requests. Please try again later."
                        }
                    })),
                )
                    .into_response();
            }
        }

        next.run(request).await
    }

    fn allow(&self, key: &str) -> bool {
        let mut buckets = self.buckets.lock().unwrap();
        let now = Instant::now();
        let bucket = buckets.entry(key.to_string()).or_insert(Bucket {
            tokens: self.burst,
            last_refill: now,
        });

        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rate).min(self.burst);
        bucket.last_refill = now;

        if bucket.tokens < 1.0 {
            return false;
        }
        bucket.tokens -= 1.0;
        true
    }
}
