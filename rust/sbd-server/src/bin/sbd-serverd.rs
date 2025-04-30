use sbd_server::*;
use std::sync::Arc;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let config = <Config as clap::Parser>::parse();
    println!("#sbd-serverd#note# {config:?}");
    let server = SbdServer::new(Arc::new(config)).await.unwrap();
    for addr in server.bind_addrs() {
        println!("#sbd-serverd#listening# {addr:?}");
    }
    println!("#sbd-serverd#ready#");
    std::future::pending::<()>().await;
}
