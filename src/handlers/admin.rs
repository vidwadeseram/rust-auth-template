use axum::{
    extract::{Path, State},
    routing::{delete, get},
    Json, Router,
};
use uuid::Uuid;
use validator::Validate;

use crate::{
    errors::AppError,
    middleware::auth::CurrentUser,
    models::{permission::Permission, role::Role, user::User, user_role::UserRole},
    schema::{
        ApiResponse, AssignPermissionRequest, AssignRoleRequest, CreatePermissionRequest,
        CreateRoleRequest, CreateUserRequest, MessageData, PermissionResponseData,
        RoleResponseData, UpdatePermissionRequest, UpdateRoleRequest, UpdateUserRequest,
        UserResponseData,
    },
    services::auth::AuthService,
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/roles", get(list_roles).post(create_role))
        .route("/api/v1/roles/{role_id}", get(get_role).patch(update_role).delete(delete_role))
        .route(
            "/api/v1/roles/{role_id}/permissions",
            get(list_role_permissions).post(assign_permission),
        )
        .route(
            "/api/v1/roles/{role_id}/permissions/{permission_id}",
            delete(remove_permission),
        )
        .route("/api/v1/permissions", get(list_permissions).post(create_permission))
        .route(
            "/api/v1/permissions/{permission_id}",
            get(get_permission).patch(update_permission).delete(delete_permission),
        )
        .route("/api/v1/users", get(list_users).post(create_user))
        .route(
            "/api/v1/users/{user_id}",
            get(get_user).patch(update_user).delete(delete_user),
        )
        .route("/api/v1/users/{user_id}/roles", get(list_user_roles).post(assign_role))
        .route("/api/v1/users/{user_id}/roles/{role_id}", delete(remove_role))
        .route("/api/v1/users/{user_id}/permissions", get(get_user_permissions))
}

async fn list_roles(
    State(state): State<AppState>,
    current_user: CurrentUser,
) -> Result<Json<ApiResponse<Vec<RoleResponseData>>>, AppError> {
    current_user.require("roles:read")?;
    let roles = Role::all(&state.pool).await?;
    let mut response = Vec::with_capacity(roles.len());

    for role in roles {
        let permissions = Permission::find_by_role_id(&state.pool, role.id).await?;
        response.push(RoleResponseData::from_role(role, permissions));
    }

    Ok(Json(ApiResponse { data: response }))
}

async fn create_role(
    State(state): State<AppState>,
    current_user: CurrentUser,
    Json(payload): Json<CreateRoleRequest>,
) -> Result<(axum::http::StatusCode, Json<ApiResponse<RoleResponseData>>), AppError> {
    current_user.require("roles:write")?;
    payload.validate()?;
    let normalized_name = payload.name.trim().to_lowercase();

    if Role::find_by_name(&state.pool, &normalized_name).await?.is_some() {
        return Err(AppError::Conflict("A role with this name already exists.".to_string()));
    }

    let role = Role::create(&state.pool, &normalized_name).await?;
    Ok((
        axum::http::StatusCode::CREATED,
        Json(ApiResponse {
            data: RoleResponseData::from_role(role, Vec::new()),
        }),
    ))
}

async fn get_role(
    State(state): State<AppState>,
    current_user: CurrentUser,
    Path(role_id): Path<Uuid>,
) -> Result<Json<ApiResponse<RoleResponseData>>, AppError> {
    current_user.require("roles:read")?;
    let role = Role::find_by_id(&state.pool, role_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Role not found.".to_string()))?;
    let permissions = Permission::find_by_role_id(&state.pool, role_id).await?;

    Ok(Json(ApiResponse {
        data: RoleResponseData::from_role(role, permissions),
    }))
}

async fn update_role(
    State(state): State<AppState>,
    current_user: CurrentUser,
    Path(role_id): Path<Uuid>,
    Json(payload): Json<UpdateRoleRequest>,
) -> Result<Json<ApiResponse<RoleResponseData>>, AppError> {
    current_user.require("roles:write")?;
    payload.validate()?;
    let normalized_name = payload.name.trim().to_lowercase();
    let existing = Role::find_by_name(&state.pool, &normalized_name).await?;
    if let Some(existing_role) = existing {
        if existing_role.id != role_id {
            return Err(AppError::Conflict("A role with this name already exists.".to_string()));
        }
    }

    let _ = Role::find_by_id(&state.pool, role_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Role not found.".to_string()))?;
    let role = Role::update(&state.pool, role_id, &normalized_name).await?;
    let permissions = Permission::find_by_role_id(&state.pool, role_id).await?;

    Ok(Json(ApiResponse {
        data: RoleResponseData::from_role(role, permissions),
    }))
}

async fn delete_role(
    State(state): State<AppState>,
    current_user: CurrentUser,
    Path(role_id): Path<Uuid>,
) -> Result<Json<ApiResponse<MessageData>>, AppError> {
    current_user.require("roles:delete")?;
    let _ = Role::find_by_id(&state.pool, role_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Role not found.".to_string()))?;
    Role::delete(&state.pool, role_id).await?;

    Ok(Json(ApiResponse {
        data: MessageData {
            message: "Role deleted successfully.".to_string(),
        },
    }))
}

async fn list_role_permissions(
    State(state): State<AppState>,
    current_user: CurrentUser,
    Path(role_id): Path<Uuid>,
) -> Result<Json<ApiResponse<Vec<PermissionResponseData>>>, AppError> {
    current_user.require("roles:read")?;
    let _ = Role::find_by_id(&state.pool, role_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Role not found.".to_string()))?;
    let permissions = Permission::find_by_role_id(&state.pool, role_id).await?;

    Ok(Json(ApiResponse {
        data: permissions
            .iter()
            .map(PermissionResponseData::from)
            .collect(),
    }))
}

async fn assign_permission(
    State(state): State<AppState>,
    current_user: CurrentUser,
    Path(role_id): Path<Uuid>,
    Json(payload): Json<AssignPermissionRequest>,
) -> Result<Json<ApiResponse<RoleResponseData>>, AppError> {
    current_user.require("roles:write")?;
    let role = Role::find_by_id(&state.pool, role_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Role not found.".to_string()))?;
    let _ = Permission::find_by_id(&state.pool, payload.permission_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Permission not found.".to_string()))?;
    Permission::assign_to_role(&state.pool, role_id, payload.permission_id).await?;
    let permissions = Permission::find_by_role_id(&state.pool, role_id).await?;

    Ok(Json(ApiResponse {
        data: RoleResponseData::from_role(role, permissions),
    }))
}

async fn remove_permission(
    State(state): State<AppState>,
    current_user: CurrentUser,
    Path((role_id, permission_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<ApiResponse<RoleResponseData>>, AppError> {
    current_user.require("roles:write")?;
    let role = Role::find_by_id(&state.pool, role_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Role not found.".to_string()))?;
    let _ = Permission::find_by_id(&state.pool, permission_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Permission not found.".to_string()))?;
    Permission::remove_from_role(&state.pool, role_id, permission_id).await?;
    let permissions = Permission::find_by_role_id(&state.pool, role_id).await?;

    Ok(Json(ApiResponse {
        data: RoleResponseData::from_role(role, permissions),
    }))
}

async fn list_permissions(
    State(state): State<AppState>,
    current_user: CurrentUser,
) -> Result<Json<ApiResponse<Vec<PermissionResponseData>>>, AppError> {
    current_user.require("permissions:read")?;
    let permissions = Permission::all(&state.pool).await?;

    Ok(Json(ApiResponse {
        data: permissions
            .iter()
            .map(PermissionResponseData::from)
            .collect(),
    }))
}

async fn create_permission(
    State(state): State<AppState>,
    current_user: CurrentUser,
    Json(payload): Json<CreatePermissionRequest>,
) -> Result<(axum::http::StatusCode, Json<ApiResponse<PermissionResponseData>>), AppError> {
    current_user.require("permissions:write")?;
    payload.validate()?;
    let normalized_name = payload.name.trim().to_lowercase();

    if Permission::find_by_name(&state.pool, &normalized_name)
        .await?
        .is_some()
    {
        return Err(AppError::Conflict(
            "A permission with this name already exists.".to_string(),
        ));
    }

    let permission = Permission::create(
        &state.pool,
        &normalized_name,
        payload.description.trim(),
    )
    .await?;

    Ok((
        axum::http::StatusCode::CREATED,
        Json(ApiResponse {
            data: PermissionResponseData::from(permission),
        }),
    ))
}

async fn get_permission(
    State(state): State<AppState>,
    current_user: CurrentUser,
    Path(permission_id): Path<Uuid>,
) -> Result<Json<ApiResponse<PermissionResponseData>>, AppError> {
    current_user.require("permissions:read")?;
    let permission = Permission::find_by_id(&state.pool, permission_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Permission not found.".to_string()))?;

    Ok(Json(ApiResponse {
        data: PermissionResponseData::from(permission),
    }))
}

async fn update_permission(
    State(state): State<AppState>,
    current_user: CurrentUser,
    Path(permission_id): Path<Uuid>,
    Json(payload): Json<UpdatePermissionRequest>,
) -> Result<Json<ApiResponse<PermissionResponseData>>, AppError> {
    current_user.require("permissions:write")?;
    payload.validate()?;
    let normalized_name = payload.name.trim().to_lowercase();
    let existing = Permission::find_by_name(&state.pool, &normalized_name).await?;
    if let Some(existing_permission) = existing {
        if existing_permission.id != permission_id {
            return Err(AppError::Conflict(
                "A permission with this name already exists.".to_string(),
            ));
        }
    }

    let _ = Permission::find_by_id(&state.pool, permission_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Permission not found.".to_string()))?;
    let permission = Permission::update(
        &state.pool,
        permission_id,
        &normalized_name,
        payload.description.trim(),
    )
    .await?;

    Ok(Json(ApiResponse {
        data: PermissionResponseData::from(permission),
    }))
}

async fn delete_permission(
    State(state): State<AppState>,
    current_user: CurrentUser,
    Path(permission_id): Path<Uuid>,
) -> Result<Json<ApiResponse<MessageData>>, AppError> {
    current_user.require("permissions:write")?;
    let _ = Permission::find_by_id(&state.pool, permission_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Permission not found.".to_string()))?;
    Permission::delete(&state.pool, permission_id).await?;

    Ok(Json(ApiResponse {
        data: MessageData {
            message: "Permission deleted successfully.".to_string(),
        },
    }))
}

async fn list_users(
    State(state): State<AppState>,
    current_user: CurrentUser,
) -> Result<Json<ApiResponse<Vec<UserResponseData>>>, AppError> {
    current_user.require("users:read")?;
    let users = User::list(&state.pool).await?;
    let service = AuthService::new(state);
    let mut response = Vec::with_capacity(users.len());

    for user in users {
        response.push(service.build_user_response(user.id).await?);
    }

    Ok(Json(ApiResponse { data: response }))
}

async fn create_user(
    State(state): State<AppState>,
    current_user: CurrentUser,
    Json(payload): Json<CreateUserRequest>,
) -> Result<(axum::http::StatusCode, Json<ApiResponse<UserResponseData>>), AppError> {
    current_user.require("users:write")?;
    payload.validate()?;
    let user = AuthService::new(state).create_user(payload).await?;

    Ok((axum::http::StatusCode::CREATED, Json(ApiResponse { data: user })))
}

async fn get_user(
    State(state): State<AppState>,
    current_user: CurrentUser,
    Path(user_id): Path<Uuid>,
) -> Result<Json<ApiResponse<UserResponseData>>, AppError> {
    current_user.require("users:read")?;
    let user = AuthService::new(state).build_user_response(user_id).await?;
    Ok(Json(ApiResponse { data: user }))
}

async fn update_user(
    State(state): State<AppState>,
    current_user: CurrentUser,
    Path(user_id): Path<Uuid>,
    Json(payload): Json<UpdateUserRequest>,
) -> Result<Json<ApiResponse<UserResponseData>>, AppError> {
    current_user.require("users:write")?;
    payload.validate()?;
    let existing = User::find_by_id(&state.pool, user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found.".to_string()))?;
    let updated = User::update(
        &state.pool,
        user_id,
        payload
            .first_name
            .as_deref()
            .unwrap_or(existing.first_name.as_str())
            .trim(),
        payload
            .last_name
            .as_deref()
            .unwrap_or(existing.last_name.as_str())
            .trim(),
        payload.is_active.unwrap_or(existing.is_active),
        payload.is_verified.unwrap_or(existing.is_verified),
    )
    .await?;

    let user = AuthService::new(state).build_user_response(updated.id).await?;
    Ok(Json(ApiResponse { data: user }))
}

async fn delete_user(
    State(state): State<AppState>,
    current_user: CurrentUser,
    Path(user_id): Path<Uuid>,
) -> Result<Json<ApiResponse<MessageData>>, AppError> {
    current_user.require("users:delete")?;
    let _ = User::find_by_id(&state.pool, user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found.".to_string()))?;
    User::delete(&state.pool, user_id).await?;

    Ok(Json(ApiResponse {
        data: MessageData {
            message: "User deleted successfully.".to_string(),
        },
    }))
}

async fn list_user_roles(
    State(state): State<AppState>,
    current_user: CurrentUser,
    Path(user_id): Path<Uuid>,
) -> Result<Json<ApiResponse<Vec<RoleResponseData>>>, AppError> {
    current_user.require("users:read")?;
    let _ = User::find_by_id(&state.pool, user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found.".to_string()))?;
    let roles = UserRole::list_by_user_id(&state.pool, user_id).await?;
    let mut response = Vec::with_capacity(roles.len());

    for role in roles {
        let permissions = Permission::find_by_role_id(&state.pool, role.id).await?;
        response.push(RoleResponseData::from_role(role, permissions));
    }

    Ok(Json(ApiResponse { data: response }))
}

async fn assign_role(
    State(state): State<AppState>,
    current_user: CurrentUser,
    Path(user_id): Path<Uuid>,
    Json(payload): Json<AssignRoleRequest>,
) -> Result<Json<ApiResponse<UserResponseData>>, AppError> {
    current_user.require("users:write")?;
    let _ = User::find_by_id(&state.pool, user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found.".to_string()))?;
    let _ = Role::find_by_id(&state.pool, payload.role_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Role not found.".to_string()))?;
    UserRole::assign(&state.pool, user_id, payload.role_id).await?;

    let user = AuthService::new(state).build_user_response(user_id).await?;
    Ok(Json(ApiResponse { data: user }))
}

async fn remove_role(
    State(state): State<AppState>,
    current_user: CurrentUser,
    Path((user_id, role_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<ApiResponse<UserResponseData>>, AppError> {
    current_user.require("users:write")?;
    let _ = User::find_by_id(&state.pool, user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found.".to_string()))?;
    let _ = Role::find_by_id(&state.pool, role_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Role not found.".to_string()))?;
    UserRole::remove(&state.pool, user_id, role_id).await?;

    let user = AuthService::new(state).build_user_response(user_id).await?;
    Ok(Json(ApiResponse { data: user }))
}

async fn get_user_permissions(
    State(state): State<AppState>,
    current_user: CurrentUser,
    Path(user_id): Path<Uuid>,
) -> Result<Json<ApiResponse<Vec<PermissionResponseData>>>, AppError> {
    current_user.require("users:read")?;
    let _ = User::find_by_id(&state.pool, user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found.".to_string()))?;
    let permissions = Permission::find_by_user_id(&state.pool, user_id).await?;

    Ok(Json(ApiResponse {
        data: permissions
            .iter()
            .map(PermissionResponseData::from)
            .collect(),
    }))
}
