use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone, Debug, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub first_name: String,
    pub last_name: String,
    pub is_active: bool,
    pub is_verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl User {
    pub async fn count_all(pool: &PgPool) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users")
            .fetch_one(pool)
            .await
    }

    pub async fn create(
        pool: &PgPool,
        email: &str,
        password_hash: &str,
        first_name: &str,
        last_name: &str,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r#"
            INSERT INTO users (email, password_hash, first_name, last_name)
            VALUES ($1, $2, $3, $4)
            RETURNING id, email, password_hash, first_name, last_name, is_active, is_verified, created_at, updated_at
            "#,
        )
        .bind(email)
        .bind(password_hash)
        .bind(first_name)
        .bind(last_name)
        .fetch_one(pool)
        .await
    }

    pub async fn find_by_email(pool: &PgPool, email: &str) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r#"
            SELECT id, email, password_hash, first_name, last_name, is_active, is_verified, created_at, updated_at
            FROM users
            WHERE email = $1
            "#,
        )
        .bind(email)
        .fetch_optional(pool)
        .await
    }

    pub async fn find_active_by_id(
        pool: &PgPool,
        user_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r#"
            SELECT id, email, password_hash, first_name, last_name, is_active, is_verified, created_at, updated_at
            FROM users
            WHERE id = $1 AND is_active = true
            "#,
        )
        .bind(user_id)
        .fetch_optional(pool)
        .await
    }

    pub async fn find_by_id(pool: &PgPool, user_id: Uuid) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r#"
            SELECT id, email, password_hash, first_name, last_name, is_active, is_verified, created_at, updated_at
            FROM users
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .fetch_optional(pool)
        .await
    }

    pub async fn list(pool: &PgPool) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r#"
            SELECT id, email, password_hash, first_name, last_name, is_active, is_verified, created_at, updated_at
            FROM users
            ORDER BY created_at DESC
            "#,
        )
        .fetch_all(pool)
        .await
    }

    pub async fn update(
        pool: &PgPool,
        user_id: Uuid,
        first_name: &str,
        last_name: &str,
        is_active: bool,
        is_verified: bool,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r#"
            UPDATE users
            SET first_name = $1,
                last_name = $2,
                is_active = $3,
                is_verified = $4,
                updated_at = NOW()
            WHERE id = $5
            RETURNING id, email, password_hash, first_name, last_name, is_active, is_verified, created_at, updated_at
            "#,
        )
        .bind(first_name)
        .bind(last_name)
        .bind(is_active)
        .bind(is_verified)
        .bind(user_id)
        .fetch_one(pool)
        .await
    }

    pub async fn delete(pool: &PgPool, user_id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(pool)
            .await?;

        Ok(())
    }
}
