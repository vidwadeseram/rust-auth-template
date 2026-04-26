use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone, Debug, sqlx::FromRow)]
pub struct Role {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

impl Role {
    pub async fn all(pool: &PgPool) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>("SELECT id, name, created_at FROM roles ORDER BY name")
            .fetch_all(pool)
            .await
    }

    pub async fn create(pool: &PgPool, name: &str) -> Result<Self, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            "INSERT INTO roles (name) VALUES ($1) RETURNING id, name, created_at",
        )
        .bind(name)
        .fetch_one(pool)
        .await
    }

    pub async fn find_by_id(pool: &PgPool, role_id: Uuid) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>("SELECT id, name, created_at FROM roles WHERE id = $1")
            .bind(role_id)
            .fetch_optional(pool)
            .await
    }

    pub async fn find_by_name(pool: &PgPool, name: &str) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>("SELECT id, name, created_at FROM roles WHERE name = $1")
            .bind(name)
            .fetch_optional(pool)
            .await
    }

    pub async fn update(pool: &PgPool, role_id: Uuid, name: &str) -> Result<Self, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            "UPDATE roles SET name = $1 WHERE id = $2 RETURNING id, name, created_at",
        )
        .bind(name)
        .bind(role_id)
        .fetch_one(pool)
        .await
    }

    pub async fn delete(pool: &PgPool, role_id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM roles WHERE id = $1")
            .bind(role_id)
            .execute(pool)
            .await?;

        Ok(())
    }

    pub async fn find_by_user_id(pool: &PgPool, user_id: Uuid) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r#"
            SELECT r.id, r.name, r.created_at
            FROM roles r
            INNER JOIN user_roles ur ON ur.role_id = r.id
            WHERE ur.user_id = $1
            ORDER BY r.name
            "#,
        )
        .bind(user_id)
        .fetch_all(pool)
        .await
    }
}
