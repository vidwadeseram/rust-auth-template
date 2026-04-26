use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use validator::Validate;

use crate::{
    errors::AppError,
    middleware::auth::CurrentUser,
    schema::{
        AuthUserEnvelope, AuthUserResponse, ForgotPasswordRequest, LoginRequest, LogoutRequest,
        MessageData, MessageResponse, RefreshTokenRequest, RegisterRequest, ResetPasswordRequest,
        TokenResponse, UserResponse, UserResponseData, VerifyEmailRequest,
    },
    services::auth::AuthService,
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/refresh", post(refresh))
        .route("/me", get(me))
        .route("/verify-email", post(verify_email))
        .route("/forgot-password", post(forgot_password))
        .route("/reset-password", post(reset_password))
}

pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<(axum::http::StatusCode, Json<AuthUserResponse>), AppError> {
    payload.validate()?;

    let user = AuthService::new(state).register(payload).await?;
    Ok((
        axum::http::StatusCode::CREATED,
        Json(AuthUserResponse {
            data: AuthUserEnvelope {
                user: UserResponseData::from(user),
                message: "Registration successful. Verification email sent.".to_string(),
            },
        }),
    ))
}

pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    payload.validate()?;
    let data = AuthService::new(state).login(payload).await?;
    Ok(Json(TokenResponse { data }))
}

pub async fn logout(
    State(state): State<AppState>,
    Json(payload): Json<LogoutRequest>,
) -> Result<Json<MessageResponse>, AppError> {
    payload.validate()?;
    AuthService::new(state)
        .logout(&payload.refresh_token)
        .await?;
    Ok(Json(MessageResponse {
        data: MessageData {
            message: "Logout successful.".to_string(),
        },
    }))
}

pub async fn refresh(
    State(state): State<AppState>,
    Json(payload): Json<RefreshTokenRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    payload.validate()?;
    let data = AuthService::new(state)
        .refresh(&payload.refresh_token)
        .await?;
    Ok(Json(TokenResponse { data }))
}

pub async fn me(current_user: CurrentUser) -> Result<Json<UserResponse>, AppError> {
    Ok(Json(UserResponse {
        data: UserResponseData::from(current_user.0),
    }))
}

pub async fn verify_email(
    State(state): State<AppState>,
    Json(payload): Json<VerifyEmailRequest>,
) -> Result<Json<MessageResponse>, AppError> {
    payload.validate()?;
    AuthService::new(state)
        .verify_email(&payload.token)
        .await?;
    Ok(Json(MessageResponse {
        data: MessageData {
            message: "Email verified successfully.".to_string(),
        },
    }))
}

pub async fn forgot_password(
    State(state): State<AppState>,
    Json(payload): Json<ForgotPasswordRequest>,
) -> Result<Json<MessageResponse>, AppError> {
    payload.validate()?;
    AuthService::new(state)
        .forgot_password(&payload.email)
        .await?;
    Ok(Json(MessageResponse {
        data: MessageData {
            message: "If an account with that email exists, a reset link has been sent.".to_string(),
        },
    }))
}

pub async fn reset_password(
    State(state): State<AppState>,
    Json(payload): Json<ResetPasswordRequest>,
) -> Result<Json<MessageResponse>, AppError> {
    payload.validate()?;
    AuthService::new(state)
        .reset_password(&payload.token, &payload.new_password)
        .await?;
    Ok(Json(MessageResponse {
        data: MessageData {
            message: "Password reset successfully.".to_string(),
        },
    }))
}
