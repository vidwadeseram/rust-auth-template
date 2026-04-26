use std::net::SocketAddr;

use anyhow::Context;
use axum::{routing::get, Router};
use sqlx::PgPool;
use tokio::signal;
use tracing::info;

mod config;
mod db;
mod errors;
mod handlers;
mod mailer;
mod middleware;
mod models;
mod schema;
mod services;

use config::AppConfig;
use handlers::{auth::router as auth_router, health::health_check};
use mailer::Mailer;
use services::token::TokenService;

#[derive(Clone)]
pub struct AppState {
    pub config: AppConfig,
    pub pool: PgPool,
    pub token_service: TokenService,
    pub mailer: Mailer,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing()?;

    let config = AppConfig::from_env()?;
    let pool = db::create_pool(&config.database).await?;
    db::run_migrations(&pool).await?;

    let state = AppState {
        token_service: TokenService::new(config.jwt.clone()),
        mailer: Mailer::new(config.smtp.clone()),
        pool,
        config: config.clone(),
    };

    let app = Router::new()
        .route("/health", get(health_check))
        .nest("/api/v1/auth", auth_router())
        .with_state(state);

    let bind_port = if config.app.port == 8003 {
        8000
    } else {
        config.app.port
    };
    let address = SocketAddr::from(([0, 0, 0, 0], bind_port));
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .with_context(|| format!("failed to bind server on {address}"))?;

    info!(address = %address, "starting server");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server exited unexpectedly")?;

    Ok(())
}

fn init_tracing() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,sqlx=warn".into()),
        )
        .try_init()
        .map_err(|error| anyhow::anyhow!("failed to initialize tracing: {error}"))?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = signal::ctrl_c().await {
            tracing::error!(error = %error, "failed to install ctrl+c handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                tracing::error!(error = %error, "failed to install terminate handler");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("shutdown signal received");
}
