use sbd_server::*;
use std::sync::Arc;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing::Level::WARN.into())
                .from_env_lossy(),
        )
        .with_file(true)
        .with_line_number(true)
        .try_init();

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let config = <Config as clap::Parser>::parse();
    println!("#sbd-serverd#note# {config:?}");
    enable_otlp_metrics_if_configured(&config)
        .expect("Failed to initialize OTLP metrics");
    let server = SbdServer::new(Arc::new(config)).await.unwrap();
    for addr in server.bind_addrs() {
        println!("#sbd-serverd#listening# {addr:?}");
    }
    println!("#sbd-serverd#ready#");
    std::future::pending::<()>().await;
}
