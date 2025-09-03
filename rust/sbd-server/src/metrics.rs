//! Metrics setup and configuration.

use opentelemetry::global;
use opentelemetry_otlp::WithExportConfig;
use std::io::Error;

/// Enable OpenTelemetry metrics export if enabled in the given config.
pub fn enable_otlp_metrics_if_configured(
    config: &crate::Config,
) -> std::io::Result<()> {
    let Some(endpoint) = &config.otlp_endpoint else {
        tracing::info!("OTLP metrics export not configured");
        return Ok(());
    };

    tracing::info!("Enabling OpenTelemetry metrics export to {endpoint}");

    // Initialize OTLP exporter using HTTP binary protocol
    let exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_http()
        .with_protocol(opentelemetry_otlp::Protocol::HttpBinary)
        .with_endpoint(endpoint)
        .build()
        .map_err(|e| {
            Error::other(format!("failed to create OTLP exporter: {e}"))
        })?;

    // Create a meter provider with the OTLP Metric exporter
    let meter_provider =
        opentelemetry_sdk::metrics::SdkMeterProvider::builder()
            .with_periodic_exporter(exporter)
            .build();

    global::set_meter_provider(meter_provider.clone());

    Ok(())
}
