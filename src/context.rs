use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use redis::{AsyncTypedCommands, aio::MultiplexedConnection};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    config::{Config, RsaJwtConfig},
    error::Report,
    models::token::{TokenClaims, TokenDetails},
};

#[derive(Clone)]
pub struct AppContext {
    pub config: Config,
    pub auth: AuthContext,
    pub db: PgPool,
    pub redis: MultiplexedConnection,
}

impl AppContext {
    pub async fn store_refresh_token(&self, token_details: &TokenDetails) -> Result<(), Report> {
        let mut conn = self.redis.clone();
        let key = format!("refresh_token:{}", token_details.token_id);
        let value = serde_json::to_string(token_details)?;

        if let Some(expires_in) = token_details.expires_in {
            let ttl = (expires_in - chrono::Utc::now().timestamp()) as u64;
            conn.set_ex(&key, &value, ttl).await?;
        } else {
            conn.set(&key, &value).await?;
        }

        Ok(())
    }

    pub async fn revoke_refresh_token(&self, token_id: Uuid) -> Result<(), Report> {
        let mut conn = self.redis.clone();
        let key = format!("refresh_token:{}", token_id);

        conn.del(&key).await?;

        Ok(())
    }
}

impl TryFrom<&Config> for AppContext {
    type Error = Report;

    fn try_from(config: &Config) -> Result<Self, Self::Error> {
        let db =
            tokio::runtime::Handle::current().block_on(async { config.database().pool().await });

        let auth = AuthContext {
            access: config.auth().access().try_into()?,
            refresh: config.auth().refresh().try_into()?,
        };
        let redis = tokio::runtime::Handle::current()
            .block_on(async { config.redis().multiplexed_connection().await })?;

        Ok(Self {
            config: config.clone(),
            db,
            auth,
            redis,
        })
    }
}

#[derive(Clone)]
pub struct AuthContext {
    pub access: JwtContext,
    pub refresh: JwtContext,
}

#[derive(Clone)]
pub struct JwtContext {
    pub encoding_key: EncodingKey,
    pub decoding_key: DecodingKey,
    pub exp: i64,
}

impl JwtContext {
    pub fn generate_token(&self, sub: Uuid) -> Result<TokenDetails, Report> {
        let now = chrono::Utc::now();

        let mut token_details = TokenDetails {
            user_pid: sub,
            token_id: Uuid::new_v4(),
            expires_in: Some((now + chrono::Duration::seconds(self.exp)).timestamp()),
            token: None,
        };

        let claims = TokenClaims {
            sub: token_details.user_pid.to_string(),
            id: token_details.token_id.to_string(),
            exp: token_details.expires_in.ok_or(crate::Error::TokenError)?,
            iat: now.timestamp(),
            nbf: now.timestamp(),
        };

        let header = Header::new(Algorithm::RS256);

        let token = jsonwebtoken::encode(&header, &claims, &self.encoding_key)?;

        token_details.token = Some(token);

        Ok(token_details)
    }

    pub fn verify_token(&self, token: &str) -> Result<TokenDetails, Report> {
        let validation = Validation::new(Algorithm::RS256);

        let token_data =
            jsonwebtoken::decode::<TokenClaims>(token, &self.decoding_key, &validation)?;

        let user_pid = Uuid::parse_str(&token_data.claims.sub)?;
        let token_id = Uuid::parse_str(&token_data.claims.id)?;

        Ok(TokenDetails {
            token: None,
            token_id,
            user_pid,
            expires_in: None,
        })
    }
}

impl TryFrom<&RsaJwtConfig> for JwtContext {
    type Error = Report;

    fn try_from(config: &RsaJwtConfig) -> Result<Self, Self::Error> {
        let encoding_key = config.encoding_key()?;
        let decoding_key = config.decoding_key()?;

        let exp = config.exp();

        Ok(Self {
            encoding_key,
            decoding_key,
            exp,
        })
    }
}
