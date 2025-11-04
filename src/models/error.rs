use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum ModelError {
    #[error("Model Already exists")]
    EntityAlreadyExists,
    #[error("Model not found")]
    EntityNotFound,
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error(transparent)]
    Uuid(#[from] uuid::Error),
}

pub type ModelResult<T, E = ModelError> = Result<T, E>;

impl ModelError {
    pub fn response(&self) -> Response {
        let (status, message) = match self {
            Self::EntityAlreadyExists => (StatusCode::CONFLICT, "Entity already exists"),
            Self::EntityNotFound => (StatusCode::NOT_FOUND, "Entity not found"),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error"),
        };

        let body = Json(json!({
            "error": message
        }));

        (status, body).into_response()
    }
}
