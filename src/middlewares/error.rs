use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Invalid token")]
    InvalidToken,
    #[error("Credentials missing from request")]
    MissingCredentials,
    #[error("Token creation failed")]
    TokenCreation,
    #[error("Wrong credentials")]
    WrongCredentials,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        self.response()
    }
}

impl AuthError {
    pub fn response(&self) -> Response {
        let (status, message) = match self {
            Self::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token"),
            Self::MissingCredentials => {
                (StatusCode::BAD_REQUEST, "Credentials missing from request")
            }
            Self::TokenCreation => (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error"),
            Self::WrongCredentials => (StatusCode::UNAUTHORIZED, "Wrong credentials"),
        };

        let body = Json(json!({
            "error": message
        }));

        (status, body).into_response()
    }
}
