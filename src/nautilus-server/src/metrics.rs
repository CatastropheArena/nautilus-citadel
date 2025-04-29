// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use axum::{extract::Extension, http::StatusCode, routing::get, Router};
use dashmap::DashMap;
use prometheus::{register_int_counter_with_registry, IntCounter, Registry, TextEncoder};
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use uuid::Uuid;

pub const METRICS_HOST_PORT: u16 = 9184;
pub const METRICS_ROUTE: &str = "/metrics";

pub async fn metrics(
    Extension(registry_service): Extension<RegistryService>,
) -> (StatusCode, String) {
    let metrics_families = registry_service.gather_all();
    match TextEncoder.encode_to_string(&metrics_families) {
        Ok(metrics) => (StatusCode::OK, metrics),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("unable to encode metrics: {error}"),
        ),
    }
}

pub fn start_basic_prometheus_server() -> RegistryService {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), METRICS_HOST_PORT);
    let registry = Registry::new();
    let registry_service = RegistryService::new(registry);
    let app = Router::new()
        .route(METRICS_ROUTE, get(metrics))
        .layer(Extension(registry_service.clone()));

    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });
    registry_service
}

/// A service to manage the prometheus registries. This service allow us to create
/// a new Registry on demand and keep it accessible for processing/polling.
/// The service can be freely cloned/shared across threads.
#[derive(Clone)]
pub struct RegistryService {
    // Holds a Registry that is supposed to be used
    default_registry: Registry,
    registries_by_id: Arc<DashMap<Uuid, Registry>>,
}

impl RegistryService {
    // Creates a new registry service and also adds the main/default registry that is supposed to
    // be preserved and never get removed
    pub fn new(default_registry: Registry) -> Self {
        Self {
            default_registry,
            registries_by_id: Arc::new(DashMap::new()),
        }
    }

    // Returns the default registry for the service that someone can use
    // if they don't want to create a new one.
    pub fn default_registry(&self) -> Registry {
        self.default_registry.clone()
    }

    // Returns all the registries of the service
    pub fn get_all(&self) -> Vec<Registry> {
        let mut registries: Vec<Registry> = self
            .registries_by_id
            .iter()
            .map(|r| r.value().clone())
            .collect();
        registries.push(self.default_registry.clone());

        registries
    }

    // Returns all the metric families from the registries that a service holds.
    pub fn gather_all(&self) -> Vec<prometheus::proto::MetricFamily> {
        self.get_all().iter().flat_map(|r| r.gather()).collect()
    }
}

#[derive(Clone, Debug)]
pub struct Metrics {
    pub requests: IntCounter,
    pub get_attestation_requests: IntCounter,
    pub process_data_requests: IntCounter,
}

impl Metrics {
    pub fn new(registry: &Registry) -> Self {
        Self {
            requests: register_int_counter_with_registry!(
                "total_requests",
                "Total number of requests received by my service",
                registry
            )
            .expect("Failed to register requests counter"),
            get_attestation_requests: register_int_counter_with_registry!(
                "total_get_attestation_requests",
                "Total number of get_attestation requests received",
                registry,
            )
            .expect("Failed to register get_attestation_requests counter"),
            process_data_requests: register_int_counter_with_registry!(
                "total_process_data_requests",
                "Total number of process_data requests received",
                registry,
            )
            .expect("Failed to register process_data_requests counter"),
        }
    }
}
