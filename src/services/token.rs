use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{config::JwtConfig, errors::AppError, schema::TokenData};

#[derive(Clone)]
pub struct TokenService {
    config: JwtConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    pub exp: usize,
    pub jti: String,
    #[serde(rename = "type")]
    pub token_type: String,
    pub email: Option<String>,
}

impl TokenService {
    pub fn new(config: JwtConfig) -> Self {
        Self { config }
    }

    pub fn issue_token_pair(&self, user_id: Uuid) -> Result<TokenData, AppError> {
        let access_expiry = Utc::now() + Duration::minutes(self.config.access_expire_minutes);
        let refresh_expiry = Utc::now() + Duration::days(self.config.refresh_expire_days);

        let access_token = self.encode(TokenClaims {
            sub: user_id.to_string(),
            exp: access_expiry.timestamp() as usize,
            jti: Uuid::new_v4().to_string(),
            token_type: "access".to_string(),
            email: None,
        })?;

        let refresh_token = self.encode(TokenClaims {
            sub: user_id.to_string(),
            exp: refresh_expiry.timestamp() as usize,
            jti: Uuid::new_v4().to_string(),
            token_type: "refresh".to_string(),
            email: None,
        })?;

        Ok(TokenData {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: self.config.access_expire_minutes * 60,
        })
    }

    pub fn create_verification_token(
        &self,
        user_id: Uuid,
        email: &str,
    ) -> Result<String, AppError> {
        let expiry = Utc::now() + Duration::days(1);
        self.encode(TokenClaims {
            sub: user_id.to_string(),
            exp: expiry.timestamp() as usize,
            jti: Uuid::new_v4().to_string(),
            token_type: "verification".to_string(),
            email: Some(email.to_string()),
        })
    }

    pub fn decode_token(&self, token: &str, expected_type: &str) -> Result<TokenClaims, AppError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        let data = decode::<TokenClaims>(
            token,
            &DecodingKey::from_secret(self.config.secret.as_bytes()),
            &validation,
        )?;

        if data.claims.token_type != expected_type {
            return Err(AppError::Unauthorized("Invalid token type.".to_string()));
        }

        Ok(data.claims)
    }

    pub fn hash_token(&self, token: &str) -> String {
        format!("{:x}", Sha256::digest(token.as_bytes()))
    }

    pub fn refresh_expires_at(&self) -> chrono::DateTime<Utc> {
        Utc::now() + Duration::days(self.config.refresh_expire_days)
    }

    fn encode(&self, claims: TokenClaims) -> Result<String, AppError> {
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.config.secret.as_bytes()),
        )
        .map_err(AppError::from)
    }
}
