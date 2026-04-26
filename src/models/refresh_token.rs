use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[allow(dead_code)]
#[derive(Clone, Debug, sqlx::FromRow)]
pub struct RefreshToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl RefreshToken {
    pub async fn create(
        pool: &PgPool,
        user_id: Uuid,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r#"
            INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
            VALUES ($1, $2, $3)
            RETURNING id, user_id, token_hash, expires_at, revoked_at, created_at
            "#,
        )
        .bind(user_id)
        .bind(token_hash)
        .bind(expires_at)
        .fetch_one(pool)
        .await
    }

    pub async fn find_active(
        pool: &PgPool,
        user_id: Uuid,
        token_hash: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r#"
            SELECT id, user_id, token_hash, expires_at, revoked_at, created_at
            FROM refresh_tokens
            WHERE user_id = $1 AND token_hash = $2 AND revoked_at IS NULL
            "#,
        )
        .bind(user_id)
        .bind(token_hash)
        .fetch_optional(pool)
        .await
    }

    pub async fn revoke(pool: &PgPool, token_id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE refresh_tokens SET revoked_at = NOW() WHERE id = $1")
            .bind(token_id)
            .execute(pool)
            .await?;
        Ok(())
    }
}
