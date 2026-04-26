use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts},
};
use uuid::Uuid;

use crate::{
    errors::AppError,
    models::{permission::Permission, role::Role, user::User},
    schema::UserResponseData,
    AppState,
};

#[derive(Clone, Debug)]
pub struct CurrentUser {
    pub user: User,
    pub roles: Vec<Role>,
    pub permissions: Vec<Permission>,
}

impl CurrentUser {
    pub fn require(&self, permission_name: &str) -> Result<(), AppError> {
        if self
            .permissions
            .iter()
            .any(|permission| permission.name == permission_name)
        {
            Ok(())
        } else {
            Err(AppError::Forbidden(format!(
                "Permission '{}' is required.",
                permission_name
            )))
        }
    }

    pub fn into_response(self) -> UserResponseData {
        UserResponseData::from_parts(self.user, self.roles, self.permissions)
    }
}

impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let header_value = parts.headers.get(header::AUTHORIZATION).ok_or_else(|| {
            AppError::Unauthorized("Authentication credentials were not provided.".to_string())
        })?;

        let header_value = header_value
            .to_str()
            .map_err(|_| AppError::Unauthorized("Authorization header is invalid.".to_string()))?;

        let token = header_value
            .strip_prefix("Bearer ")
            .or_else(|| header_value.strip_prefix("bearer "))
            .ok_or_else(|| {
                AppError::Unauthorized("Authentication credentials were not provided.".to_string())
            })?;

        let claims = state.token_service.decode_token(token, "access")?;
        let user_id = Uuid::parse_str(&claims.sub)
            .map_err(|_| AppError::Unauthorized("Invalid token subject.".to_string()))?;
        let user = User::find_active_by_id(&state.pool, user_id)
            .await?
            .ok_or_else(|| {
                AppError::Unauthorized("Authenticated user was not found.".to_string())
            })?;
        let roles = Role::find_by_user_id(&state.pool, user_id).await?;
        let permissions = Permission::find_by_user_id(&state.pool, user_id).await?;

        Ok(Self {
            user,
            roles,
            permissions,
        })
    }
}
