use anyhow::{anyhow, Context, Result};
use dotenvy::dotenv;

#[derive(Clone, Debug)]
pub struct DatabaseConfig {
    pub url: String,
}

#[derive(Clone, Debug)]
pub struct JwtConfig {
    pub secret: String,
    pub access_expire_minutes: i64,
    pub refresh_expire_days: i64,
}

#[derive(Clone, Debug)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub port: u16,
}

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub database: DatabaseConfig,
    pub jwt: JwtConfig,
    pub smtp: SmtpConfig,
    pub app: ServerConfig,
}

impl AppConfig {
    pub fn from_env() -> Result<Self> {
        let _ = dotenv();
        let _ = dotenvy::from_filename_override(".env.example");

        Ok(Self {
            database: DatabaseConfig {
                url: env_var("DATABASE_URL")?,
            },
            jwt: JwtConfig {
                secret: env_var("JWT_SECRET")?,
                access_expire_minutes: env_parse("JWT_ACCESS_EXPIRE_MINUTES")?,
                refresh_expire_days: env_parse("JWT_REFRESH_EXPIRE_DAYS")?,
            },
            smtp: SmtpConfig {
                host: env_var("SMTP_HOST")?,
                port: env_parse("SMTP_PORT")?,
            },
            app: ServerConfig {
                port: env_parse("APP_PORT")?,
            },
        })
    }
}

fn env_var(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("missing environment variable {key}"))
}

fn env_parse<T>(key: &str) -> Result<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let value = env_var(key)?;
    value
        .parse::<T>()
        .map_err(|error| anyhow!("invalid environment variable {key}: {value} ({error})"))
}
