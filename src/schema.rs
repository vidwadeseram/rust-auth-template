use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

use crate::models::user::User;

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
pub struct TokenResponse {
    pub data: TokenData,
}

#[derive(Debug, Serialize)]
pub struct MessageData {
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub data: MessageData,
}

#[derive(Debug, Serialize)]
pub struct AuthUserResponse {
    pub data: AuthUserEnvelope,
}

#[derive(Debug, Serialize)]
pub struct AuthUserEnvelope {
    pub user: UserResponseData,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub data: UserResponseData,
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
}

impl From<User> for UserResponseData {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            email: user.email,
            first_name: user.first_name,
            last_name: user.last_name,
            is_active: user.is_active,
            is_verified: user.is_verified,
            created_at: user.created_at,
            updated_at: user.updated_at,
        }
    }
}

impl From<&User> for UserResponseData {
    fn from(user: &User) -> Self {
        Self {
            id: user.id,
            email: user.email.clone(),
            first_name: user.first_name.clone(),
            last_name: user.last_name.clone(),
            is_active: user.is_active,
            is_verified: user.is_verified,
            created_at: user.created_at,
            updated_at: user.updated_at,
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
    #[validate(length(min = 8, max = 128, message = "Password must be between 8 and 128 characters."))]
    pub new_password: String,
}
