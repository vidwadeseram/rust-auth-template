use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use uuid::Uuid;

use crate::{
    errors::AppError,
    models::{
        email_verification_token::EmailVerificationToken, password_reset_token::PasswordResetToken,
        permission::Permission, refresh_token::RefreshToken, role::Role, user::User,
        user_role::UserRole,
    },
    schema::{CreateUserRequest, LoginRequest, RegisterRequest, TokenData, UserResponseData},
    AppState,
};

pub struct AuthService {
    state: AppState,
}

impl AuthService {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    pub async fn register(&self, payload: RegisterRequest) -> Result<UserResponseData, AppError> {
        let email = payload.email.trim().to_lowercase();
        if User::find_by_email(&self.state.pool, &email).await?.is_some() {
            return Err(AppError::Conflict(
                "A user with this email already exists.".to_string(),
            ));
        }

        let existing_user_count = User::count_all(&self.state.pool).await?;
        let password_hash = self.hash_password(&payload.password)?;
        let user = User::create(
            &self.state.pool,
            &email,
            &password_hash,
            payload.first_name.trim(),
            payload.last_name.trim(),
        )
        .await?;

        let default_role_name = if existing_user_count == 0 {
            "super_admin"
        } else {
            "user"
        };
        self.assign_role_by_name(user.id, default_role_name).await?;
        self.issue_email_verification(&user).await?;

        self.build_user_response(user.id).await
    }

    pub async fn create_user(
        &self,
        payload: CreateUserRequest,
    ) -> Result<UserResponseData, AppError> {
        let email = payload.email.trim().to_lowercase();
        if User::find_by_email(&self.state.pool, &email).await?.is_some() {
            return Err(AppError::Conflict(
                "A user with this email already exists.".to_string(),
            ));
        }

        let password_hash = self.hash_password(&payload.password)?;
        let mut user = User::create(
            &self.state.pool,
            &email,
            &password_hash,
            payload.first_name.trim(),
            payload.last_name.trim(),
        )
        .await?;

        let updated_user = User::update(
            &self.state.pool,
            user.id,
            &user.first_name,
            &user.last_name,
            payload.is_active.unwrap_or(true),
            payload.is_verified.unwrap_or(false),
        )
        .await?;
        user = updated_user;

        self.assign_role_by_name(user.id, "user").await?;
        if !user.is_verified {
            self.issue_email_verification(&user).await?;
        }

        self.build_user_response(user.id).await
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

        if !user.is_verified {
            return Err(AppError::Forbidden(
                "Email address must be verified before login.".to_string(),
            ));
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

    pub async fn verify_email(&self, token: &str) -> Result<(), AppError> {
        let token_hash = self.state.token_service.hash_token(token);
        let stored = EmailVerificationToken::find_active_by_hash(&self.state.pool, &token_hash)
            .await?
            .ok_or_else(|| AppError::Unauthorized("Verification token is invalid or expired.".to_string()))?;
        let user = User::find_by_id(&self.state.pool, stored.user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found.".to_string()))?;

        if user.is_verified {
            return Err(AppError::BadRequest("Email is already verified.".to_string()));
        }

        sqlx::query("UPDATE users SET is_verified = true, updated_at = NOW() WHERE id = $1")
            .bind(user.id)
            .execute(&self.state.pool)
            .await?;
        EmailVerificationToken::mark_used(&self.state.pool, stored.id).await?;

        Ok(())
    }

    pub async fn forgot_password(&self, email: &str) -> Result<(), AppError> {
        let email = email.trim().to_lowercase();
        let user = match User::find_by_email(&self.state.pool, &email).await? {
            Some(user) if user.is_active => user,
            Some(_) | None => return Ok(()),
        };

        PasswordResetToken::invalidate_unused_for_user(&self.state.pool, user.id).await?;
        let raw_token = self.state.token_service.generate_one_time_token();
        let token_hash = self.state.token_service.hash_token(&raw_token);
        PasswordResetToken::create(
            &self.state.pool,
            user.id,
            &token_hash,
            self.state.token_service.password_reset_token_expires_at(),
        )
        .await?;

        self.state
            .mailer
            .send_email(
                &user.email,
                "Password reset",
                &format!("Hi {}, use this reset token: {}", user.first_name, raw_token),
            )
            .await?;

        Ok(())
    }

    pub async fn reset_password(&self, token: &str, new_password: &str) -> Result<(), AppError> {
        let token_hash = self.state.token_service.hash_token(token);
        let stored = PasswordResetToken::find_active_by_hash(&self.state.pool, &token_hash)
            .await?
            .ok_or_else(|| AppError::Unauthorized("Password reset token is invalid or expired.".to_string()))?;
        let user = User::find_by_id(&self.state.pool, stored.user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found.".to_string()))?;
        let password_hash = self.hash_password(new_password)?;

        sqlx::query("UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2")
            .bind(&password_hash)
            .bind(user.id)
            .execute(&self.state.pool)
            .await?;
        PasswordResetToken::mark_used(&self.state.pool, stored.id).await?;
        RefreshToken::revoke_all_for_user(&self.state.pool, user.id).await?;

        Ok(())
    }

    pub async fn build_user_response(&self, user_id: Uuid) -> Result<UserResponseData, AppError> {
        let user = User::find_by_id(&self.state.pool, user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found.".to_string()))?;
        let roles = Role::find_by_user_id(&self.state.pool, user_id).await?;
        let permissions = Permission::find_by_user_id(&self.state.pool, user_id).await?;

        Ok(UserResponseData::from_parts(user, roles, permissions))
    }

    pub fn hash_password(&self, password: &str) -> Result<String, AppError> {
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

    async fn issue_email_verification(&self, user: &User) -> Result<(), AppError> {
        EmailVerificationToken::invalidate_unused_for_user(&self.state.pool, user.id).await?;
        let raw_token = self.state.token_service.generate_one_time_token();
        let token_hash = self.state.token_service.hash_token(&raw_token);
        EmailVerificationToken::create(
            &self.state.pool,
            user.id,
            &token_hash,
            self.state.token_service.verification_token_expires_at(),
        )
        .await?;

        self.state
            .mailer
            .send_email(
                &user.email,
                "Verify your account",
                &format!("Welcome {}, use this verification token: {}", user.first_name, raw_token),
            )
            .await?;

        Ok(())
    }

    async fn assign_role_by_name(&self, user_id: Uuid, role_name: &str) -> Result<(), AppError> {
        let role = Role::find_by_name(&self.state.pool, role_name)
            .await?
            .ok_or_else(|| AppError::Internal(format!("Default role '{}' was not found.", role_name)))?;
        UserRole::assign(&self.state.pool, user_id, role.id).await?;

        Ok(())
    }
}

fn parse_uuid(value: &str) -> Result<Uuid, AppError> {
    Uuid::parse_str(value).map_err(|_| AppError::Unauthorized("Invalid token subject.".to_string()))
}
