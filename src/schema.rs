use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::{Validate, ValidationError};

use crate::models::{permission::Permission, role::Role, user::User};

#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    pub data: T,
}

#[derive(Debug, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(email(message = "Email must be valid."))]
    pub email: String,
    #[validate(length(
        min = 8,
        max = 128,
        message = "Password must be between 8 and 128 characters."
    ))]
    pub password: String,
    #[validate(length(min = 1, max = 100, message = "First name is required."))]
    pub first_name: String,
    #[validate(length(min = 1, max = 100, message = "Last name is required."))]
    pub last_name: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email(message = "Email must be valid."))]
    pub email: String,
    #[validate(length(
        min = 8,
        max = 128,
        message = "Password must be between 8 and 128 characters."
    ))]
    pub password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct RefreshTokenRequest {
    #[validate(length(min = 1, message = "Refresh token is required."))]
    pub refresh_token: String,
}

pub type LogoutRequest = RefreshTokenRequest;

#[derive(Debug, Serialize)]
pub struct TokenData {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

#[derive(Debug, Serialize)]
pub struct MessageData {
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct AuthUserEnvelope {
    pub user: UserResponseData,
    pub message: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct PermissionResponseData {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub created_at: DateTime<Utc>,
}

impl From<Permission> for PermissionResponseData {
    fn from(permission: Permission) -> Self {
        Self {
            id: permission.id,
            name: permission.name,
            description: permission.description,
            created_at: permission.created_at,
        }
    }
}

impl From<&Permission> for PermissionResponseData {
    fn from(permission: &Permission) -> Self {
        Self {
            id: permission.id,
            name: permission.name.clone(),
            description: permission.description.clone(),
            created_at: permission.created_at,
        }
    }
}

#[derive(Debug, Serialize, Clone)]
pub struct RoleResponseData {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub permissions: Vec<PermissionResponseData>,
}

impl RoleResponseData {
    pub fn from_role(role: Role, permissions: Vec<Permission>) -> Self {
        Self {
            id: role.id,
            name: role.name,
            created_at: role.created_at,
            permissions: permissions.iter().map(PermissionResponseData::from).collect(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct UserResponseData {
    pub id: Uuid,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub is_active: bool,
    pub is_verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub roles: Vec<RoleResponseData>,
    pub permissions: Vec<PermissionResponseData>,
}

impl UserResponseData {
    pub fn from_parts(user: User, roles: Vec<Role>, permissions: Vec<Permission>) -> Self {
        let role_items = roles
            .into_iter()
            .map(|role| RoleResponseData {
                id: role.id,
                name: role.name,
                created_at: role.created_at,
                permissions: Vec::new(),
            })
            .collect();

        let permission_items = permissions
            .iter()
            .map(PermissionResponseData::from)
            .collect();

        Self {
            id: user.id,
            email: user.email,
            first_name: user.first_name,
            last_name: user.last_name,
            is_active: user.is_active,
            is_verified: user.is_verified,
            created_at: user.created_at,
            updated_at: user.updated_at,
            roles: role_items,
            permissions: permission_items,
        }
    }
}

#[derive(Debug, Deserialize, Validate)]
pub struct VerifyEmailRequest {
    #[validate(length(min = 1, message = "Token is required."))]
    pub token: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct ForgotPasswordRequest {
    #[validate(email(message = "Email must be valid."))]
    pub email: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct ResetPasswordRequest {
    #[validate(length(min = 1, message = "Token is required."))]
    pub token: String,
    #[validate(length(
        min = 8,
        max = 128,
        message = "Password must be between 8 and 128 characters."
    ))]
    pub new_password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateRoleRequest {
    #[validate(length(min = 1, max = 50, message = "Role name is required."))]
    pub name: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateRoleRequest {
    #[validate(length(min = 1, max = 50, message = "Role name is required."))]
    pub name: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreatePermissionRequest {
    #[validate(custom(function = "validate_permission_name"))]
    pub name: String,
    #[validate(length(min = 1, max = 255, message = "Description is required."))]
    pub description: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdatePermissionRequest {
    #[validate(custom(function = "validate_permission_name"))]
    pub name: String,
    #[validate(length(min = 1, max = 255, message = "Description is required."))]
    pub description: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct AssignPermissionRequest {
    pub permission_id: Uuid,
}

#[derive(Debug, Deserialize, Validate)]
pub struct AssignRoleRequest {
    pub role_id: Uuid,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateUserRequest {
    #[validate(email(message = "Email must be valid."))]
    pub email: String,
    #[validate(length(
        min = 8,
        max = 128,
        message = "Password must be between 8 and 128 characters."
    ))]
    pub password: String,
    #[validate(length(min = 1, max = 100, message = "First name is required."))]
    pub first_name: String,
    #[validate(length(min = 1, max = 100, message = "Last name is required."))]
    pub last_name: String,
    pub is_active: Option<bool>,
    pub is_verified: Option<bool>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateUserRequest {
    #[validate(length(min = 1, max = 100, message = "First name is required."))]
    pub first_name: Option<String>,
    #[validate(length(min = 1, max = 100, message = "Last name is required."))]
    pub last_name: Option<String>,
    pub is_active: Option<bool>,
    pub is_verified: Option<bool>,
}

fn validate_permission_name(name: &str) -> Result<(), ValidationError> {
    let is_valid = name
        .split_once(':')
        .map(|(resource, action)| {
            !resource.is_empty()
                && !action.is_empty()
                && resource
                    .chars()
                    .all(|character| character.is_ascii_lowercase() || character == '_')
                && action
                    .chars()
                    .all(|character| character.is_ascii_lowercase() || character == '_')
        })
        .unwrap_or(false);

    if is_valid {
        Ok(())
    } else {
        Err(ValidationError::new("permission_format"))
    }
}
