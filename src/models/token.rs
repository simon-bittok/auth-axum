use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The token string deserialises to this struct
/// The `sub` field will be the user's pid
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TokenClaims {
    pub sub: String,
    pub id: String,
    pub exp: i64,
    pub iat: i64,
    pub nbf: i64,
}

/// This struct will let us store our token in Redis
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TokenDetails {
    pub token: Option<String>,
    pub token_id: Uuid,
    pub user_pid: Uuid,
    pub expires_in: Option<i64>,
}
