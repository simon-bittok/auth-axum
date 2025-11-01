pub mod auth;
pub mod db;
pub mod log;

use serde::Deserialize;

use crate::Result;

pub use self::{
    auth::{AuthConfig, RsaJwtConfig},
    db::{DatabaseConfig, RedisConfig},
    log::Logger,
};

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    protocol: String,
    host: String,
    port: u16,
}

impl ServerConfig {
    pub fn address(&self) -> String {
        format!("{}:{}", &self.host, &self.port)
    }

    pub fn url(&self) -> String {
        format!("{}://{}", &self.protocol, self.address())
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    server: ServerConfig,
    logger: Logger,
    database: DatabaseConfig,
    redis: RedisConfig,
    auth: AuthConfig,
}

impl Config {
    pub fn load() -> Result<Self> {
        let env = Environment::current();
        Self::from_env(&env)
    }

    /// Load configuration for a specific environment
    ///
    /// If environment variables are set with prefix APP_, it will also read them
    /// e.g. APP_CONFIG__PORT=5000
    pub fn from_env(env: &Environment) -> Result<Self> {
        let base_dir = std::env::current_dir()?;
        let config_dir = base_dir.join("config");

        let file_name = format!("{}.yaml", env);

        let settings = config::Config::builder()
            .add_source(config::File::from(config_dir.join(file_name)))
            .add_source(
                config::Environment::with_prefix("APP")
                    .separator("__")
                    .prefix_separator("_"),
            )
            .build()?;

        settings.try_deserialize::<Self>().map_err(Into::into)
    }

    pub fn server(&self) -> &ServerConfig {
        &self.server
    }

    pub fn logger(&self) -> &Logger {
        &self.logger
    }

    pub fn redis(&self) -> &RedisConfig {
        &self.redis
    }

    pub fn database(&self) -> &DatabaseConfig {
        &self.database
    }

    pub fn auth(&self) -> &AuthConfig {
        &self.auth
    }
}

#[derive(Debug, Deserialize, Clone, Default)]
pub enum Environment {
    #[default]
    Development,
    Production,
    Testing,
    Other(String),
}

impl Environment {
    /// Get the current environment from environment variables
    ///
    /// Checks `APP_ENVIRONMENT` then `APP_ENV`, defaults to Development
    pub fn current() -> Self {
        std::env::var("APP_ENVIRONMENT")
            .or_else(|_| std::env::var("APP_ENV"))
            .map(|s| Self::from(s.as_str()))
            .unwrap_or_default()
    }
}

impl From<&str> for Environment {
    fn from(s: &str) -> Self {
        match s.to_lowercase().trim() {
            "development" | "dev" => Environment::Development,
            "production" | "prod" => Environment::Production,
            "testing" | "test" => Environment::Testing,
            other => Environment::Other(other.into()),
        }
    }
}

impl std::fmt::Display for Environment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Development => "development",
                Self::Production => "production",
                Self::Testing => "testing",
                Self::Other(other) => other.as_str(),
            }
        )
    }
}
