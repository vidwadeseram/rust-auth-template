use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use uuid::Uuid;

use crate::{
    errors::AppError,
    models::{refresh_token::RefreshToken, user::User},
    schema::{LoginRequest, RegisterRequest, TokenData},
    AppState,
};

pub struct AuthService {
    state: AppState,
}

impl AuthService {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    pub async fn register(&self, payload: RegisterRequest) -> Result<User, AppError> {
        let email = payload.email.trim().to_lowercase();
        if User::find_by_email(&self.state.pool, &email)
            .await?
            .is_some()
        {
            return Err(AppError::Conflict(
                "A user with this email already exists.".to_string(),
            ));
        }

        let password_hash = self.hash_password(&payload.password)?;
        let user = User::create(
            &self.state.pool,
            &email,
            &password_hash,
            payload.first_name.trim(),
            payload.last_name.trim(),
        )
        .await?;

        let verification_token = self
            .state
            .token_service
            .create_verification_token(user.id, &user.email)?;

        self.state
            .mailer
            .send_email(
                &user.email,
                "Verify your account",
                &format!(
                    "Welcome {}, your verification token is: {}",
                    user.first_name, verification_token
                ),
            )
            .await?;

        Ok(user)
    }

    pub async fn login(&self, payload: LoginRequest) -> Result<TokenData, AppError> {
        let email = payload.email.trim().to_lowercase();
        let user = User::find_by_email(&self.state.pool, &email)
            .await?
            .ok_or_else(|| AppError::Unauthorized("Invalid email or password.".to_string()))?;

        self.verify_password(&payload.password, &user.password_hash)?;

        if !user.is_active {
            return Err(AppError::Forbidden("User account is inactive.".to_string()));
        }

        self.issue_and_store_tokens(user.id).await
    }

    pub async fn logout(&self, refresh_token: &str) -> Result<(), AppError> {
        let claims = self
            .state
            .token_service
            .decode_token(refresh_token, "refresh")?;
        let user_id = parse_uuid(&claims.sub)?;
        let token_hash = self.state.token_service.hash_token(refresh_token);
        let stored = RefreshToken::find_active(&self.state.pool, user_id, &token_hash)
            .await?
            .ok_or_else(|| AppError::Unauthorized("Refresh token is invalid.".to_string()))?;

        RefreshToken::revoke(&self.state.pool, stored.id).await?;
        Ok(())
    }

    pub async fn refresh(&self, refresh_token: &str) -> Result<TokenData, AppError> {
        let claims = self
            .state
            .token_service
            .decode_token(refresh_token, "refresh")?;
        let user_id = parse_uuid(&claims.sub)?;
        let token_hash = self.state.token_service.hash_token(refresh_token);
        let stored = RefreshToken::find_active(&self.state.pool, user_id, &token_hash)
            .await?
            .ok_or_else(|| {
                AppError::Unauthorized("Refresh token is invalid or expired.".to_string())
            })?;

        if stored.expires_at <= chrono::Utc::now() {
            return Err(AppError::Unauthorized(
                "Refresh token is invalid or expired.".to_string(),
            ));
        }

        RefreshToken::revoke(&self.state.pool, stored.id).await?;
        self.issue_and_store_tokens(user_id).await
    }

    async fn issue_and_store_tokens(&self, user_id: Uuid) -> Result<TokenData, AppError> {
        let tokens = self.state.token_service.issue_token_pair(user_id)?;
        let token_hash = self.state.token_service.hash_token(&tokens.refresh_token);
        RefreshToken::create(
            &self.state.pool,
            user_id,
            &token_hash,
            self.state.token_service.refresh_expires_at(),
        )
        .await?;

        Ok(tokens)
    }

    fn hash_password(&self, password: &str) -> Result<String, AppError> {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|_| AppError::Internal("Failed to hash password.".to_string()))
    }

    fn verify_password(&self, password: &str, password_hash: &str) -> Result<(), AppError> {
        let parsed_hash = PasswordHash::new(password_hash)
            .map_err(|_| AppError::Unauthorized("Invalid email or password.".to_string()))?;

        Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .map_err(|_| AppError::Unauthorized("Invalid email or password.".to_string()))
    }
}

fn parse_uuid(value: &str) -> Result<Uuid, AppError> {
    Uuid::parse_str(value).map_err(|_| AppError::Unauthorized("Invalid token subject.".to_string()))
}
