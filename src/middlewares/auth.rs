#![allow(unused)]
use std::{
    convert::Infallible,
    task::{Context, Poll},
};

use axum::{
    RequestPartsExt,
    body::Body,
    http::{
        HeaderValue, Request, Response,
        header::{AUTHORIZATION, SET_COOKIE},
    },
    response::IntoResponse,
};
use axum_extra::{
    TypedHeader,
    extract::cookie::SameSite,
    headers::{Authorization, Cookie, authorization::Bearer},
    typed_header::TypedHeaderRejectionReason,
};
use futures_util::future::BoxFuture;
use redis::AsyncCommands;
use tower::{Layer, Service};

use crate::{context::AppContext, middlewares::AuthError, models::token::TokenDetails};

#[derive(Clone)]
pub struct AuthLayer {
    ctx: AppContext,
}

impl AuthLayer {
    pub fn new(ctx: AppContext) -> Self {
        Self { ctx }
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = AuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Self::Service {
            inner,
            ctx: self.ctx.clone(),
        }
    }
}

#[derive(Clone)]
pub struct AuthService<S> {
    inner: S,
    ctx: AppContext,
}

impl<S, B> Service<Request<B>> for AuthService<S>
where
    S: Service<Request<B>, Response = Response<Body>, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let ctx = self.ctx.clone();
        let clone = self.inner.clone();

        // Take the service that is ready
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            let (mut parts, body) = req.into_parts();

            let access_token = match parts.extract::<TypedHeader<Authorization<Bearer>>>().await {
                Ok(TypedHeader(Authorization(bearer))) => Some(bearer.token().to_string()),
                Err(err) => {
                    // If token is missing in bearer header we look in the cookies
                    if matches!(err.reason(), TypedHeaderRejectionReason::Missing) {
                        parts.extract::<TypedHeader<Cookie>>().await.ok().and_then(
                            |TypedHeader(cookies)| {
                                cookies.get("access_token").map(|s| s.to_string())
                            },
                        )
                    } else {
                        // Investigate why we need to specify return type here
                        return Ok::<Response<Body>, Self::Error>(
                            AuthError::InvalidToken.into_response(),
                        );
                    }
                }
            };

            let Some(access_token) = access_token else {
                return Ok(AuthError::MissingCredentials.into_response());
            };

            let access_token_details = match ctx.auth.access.verify_token(&access_token) {
                Ok(details) => details,
                Err(_) => {
                    // Access token is invalid or expired, try to refresh
                    // Extract refresh token from cookies
                    let refresh_token = match parts.extract::<TypedHeader<Cookie>>().await {
                        Ok(cookie) => cookie.get("refresh_token").map(ToString::to_string),
                        Err(e) => {
                            return Ok::<Response<Body>, Self::Error>(
                                AuthError::InvalidToken.into_response(),
                            );
                        }
                    };

                    let Some(refresh_token) = refresh_token else {
                        return Ok(AuthError::MissingCredentials.into_response());
                    };

                    // Verify the refresh token
                    let refresh_token_details = match ctx.auth.refresh.verify_token(&refresh_token)
                    {
                        Ok(details) => details,
                        Err(e) => return Ok(e.into_response()),
                    };

                    // Check if the Refresh Token is in cache
                    let mut redis_con = ctx.redis.clone();
                    let redis_key = format!("refresh_token:{}", refresh_token_details.token_id);

                    let stored_token: Result<String, crate::Error> =
                        redis_con.get(&redis_key).await.map_err(crate::Error::Redis);

                    if let Err(error) = stored_token {
                        return Ok(error.response());
                    }

                    let stored_data = stored_token.unwrap();

                    let stored_details = serde_json::from_str::<TokenDetails>(&stored_data)
                        .map_err(crate::Error::SerdeJson);

                    if let Err(error) = stored_details {
                        return Ok(error.response());
                    }

                    let stored_details = stored_details.unwrap();

                    match ctx
                        .auth
                        .access
                        .generate_token(refresh_token_details.user_pid)
                    {
                        Ok(new_access_token) => new_access_token,

                        Err(e) => return Ok(e.into_response()),
                    }
                }
            };

            // insert the access token into the cookies
            parts.extensions.insert(access_token_details.user_pid);
            parts.headers.append(
                AUTHORIZATION,
                HeaderValue::from_str(
                    format!("Bearer {}", &access_token_details.token.unwrap()).as_str(),
                )
                .unwrap(),
            );

            let mut req = Request::from_parts(parts, body);

            let access_cookie = axum_extra::extract::cookie::Cookie::build((
                "access_token",
                &access_token_details.token.unwrap(),
            ))
            .path("/")
            .max_age(time::Duration::seconds(ctx.auth.access.exp))
            .same_site(SameSite::Lax)
            .http_only(true);

            req.headers_mut().append(
                SET_COOKIE,
                HeaderValue::from_str(access_cookie.to_string().parse().unwrap()).unwrap(),
            );

            todo!()
        });

        todo!()
    }
}
