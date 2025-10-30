use auth::{App, Result};

#[tokio::main]
async fn main() -> Result<()> {
    App::run().await
}
