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
        ApiResponse, AuthUserEnvelope, ForgotPasswordRequest, LoginRequest, LogoutRequest,
        MessageData, RefreshTokenRequest, RegisterRequest, ResetPasswordRequest, TokenData,
        UserResponseData, VerifyEmailRequest,
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
) -> Result<(axum::http::StatusCode, Json<ApiResponse<AuthUserEnvelope>>), AppError> {
    payload.validate()?;

    let user = AuthService::new(state).register(payload).await?;
    Ok((
        axum::http::StatusCode::CREATED,
        Json(ApiResponse {
            data: AuthUserEnvelope {
                user,
                message: "Registration successful. Verification email sent.".to_string(),
            },
        }),
    ))
}

pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<ApiResponse<TokenData>>, AppError> {
    payload.validate()?;
    let data = AuthService::new(state).login(payload).await?;
    Ok(Json(ApiResponse { data }))
}

pub async fn logout(
    State(state): State<AppState>,
    Json(payload): Json<LogoutRequest>,
) -> Result<Json<ApiResponse<MessageData>>, AppError> {
    payload.validate()?;
    AuthService::new(state)
        .logout(&payload.refresh_token)
        .await?;
    Ok(Json(ApiResponse {
        data: MessageData {
            message: "Logout successful.".to_string(),
        },
    }))
}

pub async fn refresh(
    State(state): State<AppState>,
    Json(payload): Json<RefreshTokenRequest>,
) -> Result<Json<ApiResponse<TokenData>>, AppError> {
    payload.validate()?;
    let data = AuthService::new(state)
        .refresh(&payload.refresh_token)
        .await?;
    Ok(Json(ApiResponse { data }))
}

pub async fn me(current_user: CurrentUser) -> Result<Json<ApiResponse<UserResponseData>>, AppError> {
    Ok(Json(ApiResponse {
        data: current_user.into_response(),
    }))
}

pub async fn verify_email(
    State(state): State<AppState>,
    Json(payload): Json<VerifyEmailRequest>,
) -> Result<Json<ApiResponse<MessageData>>, AppError> {
    payload.validate()?;
    AuthService::new(state).verify_email(&payload.token).await?;
    Ok(Json(ApiResponse {
        data: MessageData {
            message: "Email verified successfully.".to_string(),
        },
    }))
}

pub async fn forgot_password(
    State(state): State<AppState>,
    Json(payload): Json<ForgotPasswordRequest>,
) -> Result<Json<ApiResponse<MessageData>>, AppError> {
    payload.validate()?;
    AuthService::new(state)
        .forgot_password(&payload.email)
        .await?;
    Ok(Json(ApiResponse {
        data: MessageData {
            message: "If an account with that email exists, a reset link has been sent.".to_string(),
        },
    }))
}

pub async fn reset_password(
    State(state): State<AppState>,
    Json(payload): Json<ResetPasswordRequest>,
) -> Result<Json<ApiResponse<MessageData>>, AppError> {
    payload.validate()?;
    AuthService::new(state)
        .reset_password(&payload.token, &payload.new_password)
        .await?;
    Ok(Json(ApiResponse {
        data: MessageData {
            message: "Password reset successfully.".to_string(),
        },
    }))
}
