use anyhow::{Context, Result};
use sqlx::{migrate::Migrator, postgres::PgPoolOptions, PgPool};

use crate::config::DatabaseConfig;

static MIGRATOR: Migrator = sqlx::migrate!();

pub async fn create_pool(config: &DatabaseConfig) -> Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.url)
        .await
        .with_context(|| format!("failed to connect to database {}", config.url))
}

pub async fn run_migrations(pool: &PgPool) -> Result<()> {
    MIGRATOR
        .run(pool)
        .await
        .context("failed to run migrations")?;
    Ok(())
}
