use crate::*;
use std::sync::Arc;

pub struct Test {
    server: sbd_server::SbdServer,
}

impl Test {
    pub async fn new() -> Self {
        let config = Arc::new(sbd_server::Config {
            bind: vec!["127.0.0.1:0".to_string(), "[::1]:0".to_string()],
            ..Default::default()
        });

        let server = sbd_server::SbdServer::new(config).await.unwrap();

        Self { server }
    }

    pub async fn conn(&self, listener: bool) -> SbdClientCrypto {
        for addr in self.server.bind_addrs() {
            if let Ok(cli) = SbdClientCrypto::new(
                &format!("ws://{addr}"),
                Arc::new(Config {
                    listener,
                    allow_plain_text: true,
                    ..Default::default()
                }),
            )
            .await
            {
                return cli;
            }
        }
        panic!("could not connect to sbd server");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sanity() {
    let test = Test::new().await;

    let c1 = test.conn(true).await;
    let c2 = test.conn(false).await;

    c1.send(c2.pub_key(), b"hello").await.unwrap();
    c2.send(c1.pub_key(), b"world").await.unwrap();

    let (rk, rm) = c1.recv().await.unwrap();
    assert_eq!(c2.pub_key(), &rk);
    assert_eq!(b"world", rm.as_slice());

    let (rk, rm) = c2.recv().await.unwrap();
    assert_eq!(c1.pub_key(), &rk);
    assert_eq!(b"hello", rm.as_slice());
}
