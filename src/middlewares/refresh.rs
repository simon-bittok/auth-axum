/// This module contains middleware code to refresh a user's expired access token.
/// It uses `tower::Service` and `tower::Layer` to create Request middleware.
use std::{
    convert::Infallible,
    sync::Arc,
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
    extract::cookie,
    headers::{Authorization, Cookie, authorization::Bearer},
    typed_header::TypedHeaderRejectionReason,
};
use futures_util::future::BoxFuture;
use redis::AsyncCommands as _;
use tower::{Layer, Service};

use crate::{context::AppContext, middlewares::AuthError, models::token::TokenDetails};

#[derive(Clone)]
pub struct RefreshLayer {
    ctx: Arc<AppContext>,
}

impl RefreshLayer {
    pub fn new(ctx: &Arc<AppContext>) -> Self {
        Self { ctx: ctx.clone() }
    }
}

impl<S> Layer<S> for RefreshLayer {
    type Service = RefreshService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Self::Service {
            inner,
            ctx: self.ctx.clone(),
        }
    }
}

#[derive(Clone)]
pub struct RefreshService<S> {
    inner: S,
    ctx: Arc<AppContext>,
}

impl<S, B> Service<Request<B>> for RefreshService<S>
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

        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            let (mut parts, body) = req.into_parts();

            let refresh_token = match parts.extract::<TypedHeader<Cookie>>().await {
                Ok(cookies) => cookies.get("refresh_token").map(ToString::to_string),
                Err(_) => return Ok(AuthError::MissingCredentials.into_response()),
            };

            let Some(refresh_token) = refresh_token else {
                return Ok(AuthError::MissingCredentials.into_response());
            };

            let access_token = match parts.extract::<TypedHeader<Authorization<Bearer>>>().await {
                Ok(header) => Some(header.token().to_string()),
                Err(err) => {
                    // extract from the cookie object
                    if matches!(err.reason(), TypedHeaderRejectionReason::Missing) {
                        parts.extract::<TypedHeader<Cookie>>().await.ok().and_then(
                            |TypedHeader(cookies)| {
                                cookies.get("access_token").map(ToString::to_string)
                            },
                        )
                    } else {
                        // The reason why we wrap the return value in Ok despite it being an error
                        // is beacause middlewares in Axum cannot return Errors i.e `Error =
                        // Infallible`
                        return Ok::<Response<Body>, Self::Error>(
                            AuthError::InvalidToken.into_response(),
                        );
                    }
                }
            };

            // Verify the refresh token and get the user's pid
            let refresh_token_details = match ctx.auth.refresh.verify_token(&refresh_token) {
                Ok(details) => details,
                Err(err) => return Ok(err.into_response()),
            };

            // Check if the Refresh Token is in cache
            let mut redis_conn = ctx.redis.clone();
            let redis_key = format!("refresh_token:{}", refresh_token_details.token_id);

            let stored_token: Result<String, crate::Error> = redis_conn
                .get(&redis_key)
                .await
                .map_err(crate::Error::Redis);

            let stored_details = match stored_token {
                Ok(token) => match serde_json::from_str::<TokenDetails>(&token)
                    .map_err(crate::Error::SerdeJson)
                {
                    Ok(details) => details,
                    Err(err) => return Ok(err.response()),
                },
                Err(err) => return Ok(err.response()),
            };

            // if access token is missing we issue a new one.
            let new_access_token: String;
            if let Some(token) = access_token {
                // Verify if the existing access token is still valid
                match ctx.auth.access.verify_token(&token) {
                    Ok(_) => new_access_token = token,
                    Err(_) => {
                        // Token is invalid for whatever reason
                        match ctx.auth.access.generate_token(stored_details.user_pid) {
                            Ok(details) => new_access_token = details.token.unwrap(),
                            Err(e) => return Ok(e.into_response()),
                        }
                    }
                }
            } else {
                // No access token present; probably expired and got expelled from cookies
                match ctx.auth.access.generate_token(stored_details.user_pid) {
                    Ok(details) => {
                        new_access_token = details.token.unwrap();
                    }
                    Err(e) => return Ok(e.into_response()),
                }
            }

            let access_cookie = cookie::Cookie::build(("access_token", &new_access_token))
                .path("/")
                .max_age(time::Duration::seconds(ctx.auth.access.exp))
                .same_site(cookie::SameSite::Lax)
                .http_only(true)
                .to_string();

            let mut req = Request::from_parts(parts, body);
            req.headers_mut().append(
                AUTHORIZATION,
                HeaderValue::from_str(format!("Bearer {}", &new_access_token).as_str()).unwrap(),
            );
            req.headers_mut().append(
                SET_COOKIE,
                HeaderValue::from_str(access_cookie.as_str()).unwrap(),
            );

            inner.call(req).await
        })
    }
}
