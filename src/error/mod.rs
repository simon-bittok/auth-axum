use std::{
    env::VarError,
    fmt::{self, Display},
};

use tracing_subscriber::filter::FromEnvError;

#[derive(Debug)]
pub struct Report(pub color_eyre::Report);

impl<E> From<E> for Report
where
    E: Into<color_eyre::Report>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

impl Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

pub type Result<T, E = Report> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Axum(#[from] axum::Error),
    #[error(transparent)]
    Config(#[from] config::ConfigError),
    #[error(transparent)]
    DirectiveParseError(#[from] tracing_subscriber::filter::ParseError),
    #[error(transparent)]
    EnvFilter(#[from] VarError),
    #[error(transparent)]
    FromEnv(#[from] FromEnvError),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    TryInit(#[from] tracing_subscriber::util::TryInitError),
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error(transparent)]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error(transparent)]
    Redis(#[from] redis::RedisError),
    #[error(transparent)]
    JsonWebToken(#[from] jsonwebtoken::errors::Error),
}
