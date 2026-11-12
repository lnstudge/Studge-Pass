//! Entry point for the `studge-relay` binary.
//!
//! All application code lives in the library target (`src/lib.rs`). This file
//! only handles startup: loading config, opening the database, running the
//! background sweeper, and binding the socket.

use std::net::SocketAddr;
use std::path::PathBuf;
use studge_core::crypto::signing::Timestamp;
use studge_relay::{app, RelayConfig, RelayState, RelayStore};

fn config_path(args: &[String]) -> Option<PathBuf> {
    if let Some(path) = args.get(1) {
        return Some(PathBuf::from(path));
    }
    std::env::var("STUDGE_RELAY_CONFIG").ok().map(PathBuf::from)
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let config = match RelayConfig::load(config_path(&args).as_deref()) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("studge-relay: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    if config.log_json {
        let _ = tracing_subscriber::fmt()
            .json()
            .with_env_filter(env_filter)
            .try_init();
    } else {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .try_init();
    }

    let store = match RelayStore::open(&config.database_path).await {
        Ok(store) => store,
        Err(_) => {
            eprintln!("studge-relay: the database could not be opened");
            return std::process::ExitCode::FAILURE;
        }
    };
    let setup = match RelayState::load_or_create_setup(&config.server_setup_path).await {
        Ok(setup) => setup,
        Err(_) => {
            eprintln!("studge-relay: the OPAQUE server-setup key could not be loaded");
            return std::process::ExitCode::FAILURE;
        }
    };
    let state = RelayState::new(config.clone(), store, setup);

    // Background sweeper: expired sessions and old tombstones, every 10 minutes.
    let sweeper_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(600));
        loop {
            interval.tick().await;
            let now = match Timestamp::now() {
                Ok(now) => now,
                Err(_) => continue,
            };
            let cutoff = match Timestamp::from_unix_seconds(now.unix_seconds() - 24 * 3600) {
                Ok(cutoff) => cutoff,
                Err(_) => continue,
            };
            let _ = sweeper_state
                .store()
                .delete_expired_sessions(now.as_str())
                .await;
            let _ = sweeper_state
                .store()
                .purge_tombstones_before(cutoff.as_str())
                .await;
        }
    });

    let address: SocketAddr = config.listen;
    let router = app(state);
    let listener = match tokio::net::TcpListener::bind(address).await {
        Ok(listener) => listener,
        Err(_) => {
            tracing::error!("listener could not bind");
            return std::process::ExitCode::FAILURE;
        }
    };
    tracing::info!(%address, "studge-relay listening");

    if axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .is_err()
    {
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}
