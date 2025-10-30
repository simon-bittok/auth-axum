use std::io::IsTerminal;

use axum::{Router, routing::get};
use color_eyre::config::{HookBuilder, Theme};
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;

use crate::{Result, config::Config, middlewares};

pub struct App;

impl App {
    pub async fn run() -> Result<()> {
        HookBuilder::new().theme(if std::io::stderr().is_terminal() {
            Theme::dark()
        } else {
            Theme::new()
        });

        let config = Config::load()?;

        config.logger().setup()?;

        let router = Router::new()
            .route("/hello", get(|| async { "Hello from axum!" }))
            .layer(
                TraceLayer::new_for_http()
                    .make_span_with(middlewares::make_span_with)
                    .on_request(middlewares::on_request)
                    .on_response(middlewares::on_response)
                    .on_failure(middlewares::on_failure),
            );

        let listener = TcpListener::bind(config.server().address()).await?;

        tracing::info!("Listening on {}", config.server().url());

        axum::serve(listener, router).await.map_err(Into::into)
    }
}
