use sbd_server::*;
use std::sync::Arc;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let config = <Config as clap::Parser>::parse();
    println!("#sbd-serverd# {config:?}");
    let _server = SbdServer::new(Arc::new(config)).await.unwrap();
    std::future::pending::<()>().await;
}
