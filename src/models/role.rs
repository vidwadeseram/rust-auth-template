use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[allow(dead_code)]
#[derive(Clone, Debug, sqlx::FromRow)]
pub struct Role {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

#[allow(dead_code)]
impl Role {
    pub async fn all(pool: &PgPool) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>("SELECT id, name, created_at FROM roles ORDER BY name")
            .fetch_all(pool)
            .await
    }
}
