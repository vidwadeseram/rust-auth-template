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
        AuthUserEnvelope, AuthUserResponse, LoginRequest, LogoutRequest, MessageData,
        MessageResponse, RefreshTokenRequest, RegisterRequest, TokenResponse, UserResponse,
        UserResponseData,
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
