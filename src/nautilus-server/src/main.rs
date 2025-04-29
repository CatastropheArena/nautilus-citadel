// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use axum::{routing::get, routing::post, Router};
use fastcrypto::{ed25519::Ed25519KeyPair, traits::KeyPair};
use nautilus_server::app::process_data;
use nautilus_server::common::{get_attestation, health_check};
use nautilus_server::metrics::start_basic_prometheus_server;
use nautilus_server::metrics::Metrics;
use nautilus_server::AppState;
use rand::SeedableRng;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, Level};
use tracing_subscriber::{fmt, EnvFilter};
use rand::rngs::StdRng;

#[tokio::main]
async fn main() -> Result<()> {
    // Configure tracing logs
    let env_filter = EnvFilter::from_default_env()
        .add_directive(Level::INFO.into())
        .add_directive("nautilus_server=debug".parse().unwrap());

    fmt::fmt()
        .with_env_filter(env_filter)
        .with_target(true)
        .init();
    
    info!("Logging system initialized");
    
    // let seed = 42u64; 
    // let mut rand = StdRng::seed_from_u64(seed);
    // let eph_kp = Ed25519KeyPair::generate(&mut rand);
    let eph_kp = Ed25519KeyPair::generate(&mut rand::thread_rng());

    // Start the metrics server
    let registry_service = start_basic_prometheus_server();
    let metrics = Metrics::new(&registry_service.default_registry());

    // This is the twitter bearer token you stored with secret manager.
    let api_key = std::env::var("API_KEY").expect("API_KEY must be set");
    info!("API key length: {}", api_key.len());

    let state = Arc::new(AppState {
        eph_kp,
        api_key,
        metrics,
    });

    // Define your own restricted CORS policy here if needed.
    let cors = CorsLayer::new().allow_methods(Any).allow_headers(Any);

    let app = Router::new()
        .route("/", get(ping))
        .route("/get_attestation", get(get_attestation))
        .route("/process_data", post(process_data))
        .route("/health_check", get(health_check))
        .with_state(state)
        .layer(cors);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    info!("Server started, listening on: {}", listener.local_addr().unwrap());
    axum::serve(listener, app.into_make_service())
        .await
        .map_err(|e| anyhow::anyhow!("Server error: {}", e))
}

async fn ping() -> &'static str {
    "Pong!"
}
