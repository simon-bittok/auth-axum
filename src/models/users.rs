use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use chrono::{DateTime, FixedOffset};
use serde::Deserialize;
use sqlx::{Encode, Executor, Postgres, prelude::FromRow};
use uuid::Uuid;

use crate::Result;

pub struct NewUser {
    email: String,
    name: String,
    password: String,
}

#[derive(Debug, Deserialize, Clone, FromRow, Encode)]
pub struct User {
    id: i32,
    pid: Uuid,
    email: String,
    name: String,
    password: String,
    created_at: DateTime<FixedOffset>,
    updated_at: DateTime<FixedOffset>,
}

impl User {
    pub async fn create_user<'e, C>(db: &C, new_user: &NewUser) -> Result<Self>
    where
        for<'a> &'a C: Executor<'e, Database = Postgres>,
    {
        let user = sqlx::query_as::<_, Self>(
            r"
           INSERT INTO users (email, name, password)
           VALUES ($1, $2, $3)
           RETURNING *
           ",
        )
        .bind(new_user.email.trim())
        .bind(new_user.name.trim())
        .bind(password_hash(&new_user.password)?)
        .fetch_one(db)
        .await?;

        Ok(user)
    }
}

fn password_hash(plain_password: &str) -> Result<String> {
    let argon2 = Argon2::default();
    let salt = SaltString::generate(&mut OsRng);

    let hash = argon2
        .hash_password(plain_password.as_bytes(), &salt)
        .map_err(crate::Error::PasswordHash)?;

    Ok(hash.to_string())
}
