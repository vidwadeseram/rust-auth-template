use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Unauthorized(String),
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    Validation(String),
    #[error("{0}")]
    Internal(String),
}

#[derive(Serialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Serialize)]
struct ErrorBody {
    code: String,
    message: String,
}

impl AppError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::Validation(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "BAD_REQUEST",
            Self::Unauthorized(_) => "UNAUTHORIZED",
            Self::Forbidden(_) => "FORBIDDEN",
            Self::NotFound(_) => "NOT_FOUND",
            Self::Conflict(_) => "CONFLICT",
            Self::Validation(_) => "VALIDATION_ERROR",
            Self::Internal(_) => "INTERNAL_SERVER_ERROR",
        }
    }

    fn message(&self) -> String {
        self.to_string()
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let body = Json(ErrorEnvelope {
            error: ErrorBody {
                code: self.code().to_string(),
                message: self.message(),
            },
        });

        (status, body).into_response()
    }
}

impl From<sqlx::Error> for AppError {
    fn from(error: sqlx::Error) -> Self {
        tracing::error!(error = %error, "database error");
        Self::Internal("A database error occurred.".to_string())
    }
}

impl From<validator::ValidationErrors> for AppError {
    fn from(error: validator::ValidationErrors) -> Self {
        let message = error
            .field_errors()
            .values()
            .next()
            .and_then(|errors| errors.first())
            .and_then(|err| err.message.as_ref())
            .map(ToString::to_string)
            .unwrap_or_else(|| "Invalid request payload.".to_string());

        Self::Validation(message)
    }
}

impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(_: jsonwebtoken::errors::Error) -> Self {
        Self::Unauthorized("Invalid or expired token.".to_string())
    }
}

impl From<lettre::transport::smtp::Error> for AppError {
    fn from(error: lettre::transport::smtp::Error) -> Self {
        tracing::error!(error = %error, "mailer error");
        Self::Internal("Failed to deliver email.".to_string())
    }
}

impl From<lettre::error::Error> for AppError {
    fn from(error: lettre::error::Error) -> Self {
        tracing::error!(error = %error, "message build error");
        Self::Internal("Failed to build email message.".to_string())
    }
}

impl From<lettre::address::AddressError> for AppError {
    fn from(error: lettre::address::AddressError) -> Self {
        tracing::error!(error = %error, "email address error");
        Self::BadRequest("Email address is invalid.".to_string())
    }
}

impl From<anyhow::Error> for AppError {
    fn from(error: anyhow::Error) -> Self {
        tracing::error!(error = %error, "internal application error");
        Self::Internal("An unexpected error occurred.".to_string())
    }
}
