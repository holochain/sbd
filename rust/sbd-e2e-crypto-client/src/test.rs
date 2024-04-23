use crate::*;
use sbd_server::*;
use std::sync::Arc;

async fn endpoint(
    listener: bool,
    addrs: &[std::net::SocketAddr],
) -> SbdCryptoEndpoint {
    for addr in addrs {
        if let Ok(ep) =
            SbdCryptoEndpoint::new(&format!("ws://{addr}"), listener, true)
                .await
        {
            return ep;
        }
    }
    panic!()
}

#[tokio::test(flavor = "multi_thread")]
async fn sanity() {
    let config = Arc::new(Config {
        bind: vec!["127.0.0.1:0".to_string(), "[::1]:0".to_string()],
        ..Default::default()
    });

    let server = SbdServer::new(config).await.unwrap();
    println!("{:?}", server.bind_addrs());

    let ep1 = endpoint(true, server.bind_addrs()).await;
    let ep2 = endpoint(false, server.bind_addrs()).await;

    let c2 = ep2.connect(ep1.pub_key()).await.unwrap();
    let c1 = ep1.recv().await.unwrap();

    c1.send(b"hello").await.unwrap();
    c2.send(b"world").await.unwrap();

    let r = c1.recv().await.unwrap();
    assert_eq!(b"world", r.as_slice());

    let r = c2.recv().await.unwrap();
    assert_eq!(b"hello", r.as_slice());
}
