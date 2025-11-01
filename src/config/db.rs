use redis::{Client, aio::MultiplexedConnection};
use serde::{Deserialize, Serialize};
use sqlx::{
    ConnectOptions, PgPool,
    postgres::{PgConnectOptions, PgSslMode},
};
use tracing::log::LevelFilter;

use crate::Result;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DatabaseConfig {
    uri: String,
    username: String,
    host: String,
    password: String,
    database: String,
    port: u16,
    ssl: bool,
}

impl DatabaseConfig {
    pub async fn pool(&self) -> PgPool {
        let ssl_mode = if self.ssl {
            PgSslMode::Require
        } else {
            PgSslMode::Prefer
        };

        let mut options = PgConnectOptions::new()
            .host(&self.host)
            .username(&self.username)
            .password(&self.password)
            .port(self.port)
            .ssl_mode(ssl_mode)
            .database(&self.database);

        options = options.log_statements(LevelFilter::Debug);

        PgPool::connect_lazy_with(options)
    }

    pub fn url(&self) -> &str {
        &self.uri
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RedisConfig {
    uri: String,
}

impl RedisConfig {
    pub fn client(&self) -> Result<Client> {
        Client::open(self.uri()).map_err(Into::into)
    }

    pub async fn multiplexed_connection(&self) -> Result<MultiplexedConnection> {
        self.client()?
            .get_multiplexed_async_connection()
            .await
            .map_err(Into::into)
    }

    pub fn uri(&self) -> &str {
        &self.uri
    }
}
