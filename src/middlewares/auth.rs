/// This module contains middleware code to check if a user is authenticated.
/// It uses `tower::Service` and `tower::Layer` to create Request middleware.
use std::{
    convert::Infallible,
    sync::Arc,
    task::{Context, Poll},
};

use axum::{
    RequestPartsExt,
    body::Body,
    http::{Request, Response},
    response::IntoResponse,
};
use axum_extra::{
    TypedHeader,
    headers::{Authorization, Cookie, authorization::Bearer},
    typed_header::TypedHeaderRejectionReason,
};
use futures_util::future::BoxFuture;
use tower::{Layer, Service};

use crate::{context::AppContext, middlewares::AuthError};

#[derive(Clone)]
pub struct AuthLayer {
    ctx: Arc<AppContext>,
}

impl AuthLayer {
    pub fn new(ctx: &Arc<AppContext>) -> Self {
        Self { ctx: ctx.clone() }
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
    ctx: Arc<AppContext>,
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
                Ok(header) => Some(header.token().to_string()),
                Err(err) => {
                    // Access Token not in authorisation header; so check cookies
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

            let Some(access_token) = access_token else {
                return Ok(AuthError::MissingCredentials.into_response());
            };

            // verify the access token
            let token_details = match ctx.auth.access.verify_token(&access_token) {
                Ok(details) => details,
                Err(err) => return Ok(err.into_response()),
            };

            // Reconstuct the Request and insert the token details into it.

            let mut req = Request::from_parts(parts, body);
            req.extensions_mut().insert(token_details);

            inner.call(req).await
        })
    }
}
