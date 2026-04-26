use std::ops::Deref;

use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts},
};
use uuid::Uuid;

use crate::{errors::AppError, models::user::User, AppState};

pub struct CurrentUser(pub User);

impl Deref for CurrentUser {
    type Target = User;

    fn deref(&self) -> &Self::Target {
        &self.0
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

        Ok(Self(user))
    }
}
