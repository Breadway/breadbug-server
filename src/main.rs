use std::sync::Arc;

use anyhow::{Context, Result};
use breadbug_server::app::{public_router, spawn_maintenance, AppState};
use breadbug_server::config::Config;
use breadbug_server::crypto::load_or_create_secret;
use breadbug_server::db::Db;
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    if breadbug_server::symbolicate::worker_main() {
        return Ok(());
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(server_main())
}

async fn server_main() -> Result<()> {
    // No request logging: addresses and payloads never reach the logs.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cfg = Config::from_env()?;
    std::fs::create_dir_all(&cfg.data_dir).context("create data dir")?;
    let secret = load_or_create_secret(&cfg.data_dir)?;
    let db = Db::open(&cfg.data_dir.join("breadbug.db"))?;
    let state = AppState::new(cfg.clone(), db, secret);
    spawn_maintenance(Arc::clone(&state));

    let public = tokio::net::TcpListener::bind(cfg.public_addr)
        .await
        .with_context(|| format!("bind {}", cfg.public_addr))?;
    tracing::info!(addr = %cfg.public_addr, "public intake listening");
    axum::serve(public, public_router(state)).await?;
    Ok(())
}
