use axum::{
    extract::{Path, State},
    routing::{get, patch, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{
    errors::AppError,
    middleware::auth::CurrentUser,
    models::{
        permission::Permission,
        role::Role,
        user::User,
        user_role::UserRole as UserRoleModel,
    },
    schema::{
        MessageData, MessageResponse, PermissionResponse, RolePermissionRequest,
        UserResponse, UserRoleRequest, UserUpdateRequest,
    },
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/roles", get(list_roles))
        .route("/permissions", get(list_permissions))
        .route("/roles/{role_id}/permissions", get(get_role_permissions))
        .route("/roles/permissions", post(assign_permission).delete(remove_permission))
        .route("/users", get(list_users))
        .route("/users/{user_id}", get(get_user).delete(delete_user))
        .route("/users/{user_id}/patch", patch(update_user))
        .route("/users/{user_id}/permissions", get(get_user_permissions))
        .route("/users/roles", post(assign_role).delete(remove_role))
}

async fn require_perm(state: &AppState, user_id: Uuid, perm: &str) -> Result<(), AppError> {
    let has = Permission::user_has_permission(&state.pool, user_id, perm)
        .await
        .map_err(|_| AppError::Internal("Permission check failed.".to_string()))?;
    if !has {
        return Err(AppError::Forbidden(format!("Permission '{}' is required.", perm)));
    }
    Ok(())
}

#[utoipa::path(get, path = "/api/v1/admin/roles", responses((status = 200, description = "List roles")), tag = "admin")]
pub async fn list_roles(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Json<Vec<RoleResponse>>, AppError> {
    require_perm(&state, user.0.id, "roles.manage").await?;
    let roles = Role::all(&state.pool).await?;
    Ok(Json(roles.into_iter().map(|r| RoleResponse {
        id: r.id,
        name: r.name,
        created_at: r.created_at,
    }).collect()))
}

#[utoipa::path(get, path = "/api/v1/admin/permissions", responses((status = 200, description = "List permissions")), tag = "admin")]
pub async fn list_permissions(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Json<Vec<PermissionResponse>>, AppError> {
    require_perm(&state, user.0.id, "roles.manage").await?;
    let perms = Permission::all(&state.pool).await?;
    Ok(Json(perms.into_iter().map(|p| PermissionResponse {
        id: p.id, name: p.name, description: p.description, created_at: p.created_at,
    }).collect()))
}

#[utoipa::path(get, path = "/api/v1/admin/roles/{role_id}/permissions", responses((status = 200, description = "Role permissions")), tag = "admin")]
pub async fn get_role_permissions(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(role_id): Path<Uuid>,
) -> Result<Json<Vec<PermissionResponse>>, AppError> {
    require_perm(&state, user.0.id, "roles.manage").await?;
    let perms = Permission::find_by_role_id(&state.pool, role_id).await?;
    Ok(Json(perms.into_iter().map(|p| PermissionResponse {
        id: p.id, name: p.name, description: p.description, created_at: p.created_at,
    }).collect()))
}

#[utoipa::path(post, path = "/api/v1/admin/roles/permissions", request_body = RolePermissionRequest, responses((status = 200, description = "Permission assigned")), tag = "admin")]
pub async fn assign_permission(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(payload): Json<RolePermissionRequest>,
) -> Result<Json<MessageResponse>, AppError> {
    require_perm(&state, user.0.id, "roles.manage").await?;
    Permission::assign_to_role(&state.pool, payload.role_id, payload.permission_id).await?;
    Ok(Json(MessageResponse { data: MessageData { message: "Permission assigned to role.".to_string() } }))
}

#[utoipa::path(delete, path = "/api/v1/admin/roles/permissions", request_body = RolePermissionRequest, responses((status = 200, description = "Permission removed")), tag = "admin")]
pub async fn remove_permission(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(payload): Json<RolePermissionRequest>,
) -> Result<Json<MessageResponse>, AppError> {
    require_perm(&state, user.0.id, "roles.manage").await?;
    Permission::remove_from_role(&state.pool, payload.role_id, payload.permission_id).await?;
    Ok(Json(MessageResponse { data: MessageData { message: "Permission removed from role.".to_string() } }))
}

#[utoipa::path(get, path = "/api/v1/admin/users", responses((status = 200, description = "List users")), tag = "admin")]
pub async fn list_users(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Json<Vec<UserResponse>>, AppError> {
    require_perm(&state, user.0.id, "users.read").await?;
    let users = sqlx::query_as::<_, User>(
        "SELECT id, email, password_hash, first_name, last_name, is_active, is_verified, created_at, updated_at FROM users ORDER BY created_at DESC"
    ).fetch_all(&state.pool).await?;
    Ok(Json(users.iter().map(|u| crate::schema::UserResponseData::from(u).into()).collect()))
}

#[utoipa::path(get, path = "/api/v1/admin/users/{user_id}", responses((status = 200, description = "User details")), tag = "admin")]
pub async fn get_user(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(user_id): Path<Uuid>,
) -> Result<Json<UserResponse>, AppError> {
    require_perm(&state, user.0.id, "users.read").await?;
    let found = User::find_active_by_id(&state.pool, user_id).await?.ok_or_else(|| AppError::NotFound("User not found.".to_string()))?;
    Ok(Json(UserResponse { data: crate::schema::UserResponseData::from(&found) }))
}

#[utoipa::path(patch, path = "/api/v1/admin/users/{user_id}/patch", request_body = UserUpdateRequest, responses((status = 200, description = "User updated")), tag = "admin")]
pub async fn update_user(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(user_id): Path<Uuid>,
    Json(payload): Json<UserUpdateRequest>,
) -> Result<Json<UserResponse>, AppError> {
    require_perm(&state, user.0.id, "users.write").await?;
    let mut found = User::find_active_by_id(&state.pool, user_id).await?.ok_or_else(|| AppError::NotFound("User not found.".to_string()))?;
    if let Some(ref first_name) = payload.first_name { found.first_name = first_name.clone(); }
    if let Some(ref last_name) = payload.last_name { found.last_name = last_name.clone(); }
    if let Some(is_active) = payload.is_active {
        sqlx::query("UPDATE users SET is_active = $1, updated_at = NOW() WHERE id = $2")
            .bind(is_active).bind(user_id).execute(&state.pool).await?;
    }
    sqlx::query("UPDATE users SET first_name = $1, last_name = $2, updated_at = NOW() WHERE id = $3")
        .bind(&found.first_name).bind(&found.last_name).bind(user_id)
        .execute(&state.pool).await?;
    let updated = User::find_active_by_id(&state.pool, user_id).await?.ok_or_else(|| AppError::NotFound("User not found.".to_string()))?;
    Ok(Json(UserResponse { data: crate::schema::UserResponseData::from(&updated) }))
}

#[utoipa::path(delete, path = "/api/v1/admin/users/{user_id}", responses((status = 200, description = "User deleted")), tag = "admin")]
pub async fn delete_user(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(user_id): Path<Uuid>,
) -> Result<Json<MessageResponse>, AppError> {
    require_perm(&state, user.0.id, "users.delete").await?;
    let _ = User::find_active_by_id(&state.pool, user_id).await?.ok_or_else(|| AppError::NotFound("User not found.".to_string()))?;
    sqlx::query("DELETE FROM users WHERE id = $1").bind(user_id).execute(&state.pool).await?;
    Ok(Json(MessageResponse { data: MessageData { message: "User deleted.".to_string() } }))
}

#[utoipa::path(get, path = "/api/v1/admin/users/{user_id}/permissions", responses((status = 200, description = "User permissions")), tag = "admin")]
pub async fn get_user_permissions(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(target_user_id): Path<Uuid>,
) -> Result<Json<Vec<PermissionResponse>>, AppError> {
    require_perm(&state, user.0.id, "users.read").await?;
    let perms = Permission::find_by_user_id(&state.pool, target_user_id).await?;
    Ok(Json(perms.into_iter().map(|p| PermissionResponse {
        id: p.id, name: p.name, description: p.description, created_at: p.created_at,
    }).collect()))
}

#[utoipa::path(post, path = "/api/v1/admin/users/roles", request_body = UserRoleRequest, responses((status = 200, description = "Role assigned")), tag = "admin")]
pub async fn assign_role(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(payload): Json<UserRoleRequest>,
) -> Result<Json<MessageResponse>, AppError> {
    require_perm(&state, user.0.id, "roles.manage").await?;
    UserRoleModel::assign(&state.pool, payload.user_id, payload.role_id).await?;
    Ok(Json(MessageResponse { data: MessageData { message: "Role assigned to user.".to_string() } }))
}

#[utoipa::path(delete, path = "/api/v1/admin/users/roles", request_body = UserRoleRequest, responses((status = 200, description = "Role removed")), tag = "admin")]
pub async fn remove_role(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(payload): Json<UserRoleRequest>,
) -> Result<Json<MessageResponse>, AppError> {
    require_perm(&state, user.0.id, "roles.manage").await?;
    UserRoleModel::remove(&state.pool, payload.user_id, payload.role_id).await?;
    Ok(Json(MessageResponse { data: MessageData { message: "Role removed from user.".to_string() } }))
}

impl From<crate::schema::UserResponseData> for UserResponse {
    fn from(data: crate::schema::UserResponseData) -> Self {
        Self { data }
    }
}

#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct RoleResponse {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
}
