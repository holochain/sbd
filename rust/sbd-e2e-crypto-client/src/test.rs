use crate::*;
use std::sync::Arc;

pub struct Cfg(pub Config);

impl Cfg {
    pub fn d() -> Self {
        Self(Config {
            listener: true,
            allow_plain_text: true,
            cooldown: tokio::time::Duration::from_secs(1),
            max_connections: 100,
            max_idle: tokio::time::Duration::from_secs(1),
        })
    }

    pub fn no_listen(mut self) -> Self {
        self.0.listener = false;
        self
    }

    pub fn max(mut self, max: usize) -> Self {
        self.0.max_connections = max;
        self
    }

    pub fn cool(mut self, cool: std::time::Duration) -> Self {
        self.0.cooldown = cool;
        self
    }
}

pub struct Test {
    server: sbd_server::SbdServer,
}

impl Test {
    pub async fn new() -> Self {
        let config = Arc::new(sbd_server::Config {
            bind: vec!["127.0.0.1:0".to_string(), "[::1]:0".to_string()],
            limit_clients: 100,
            ..Default::default()
        });

        let server = sbd_server::SbdServer::new(config).await.unwrap();

        Self { server }
    }

    pub async fn conn(&self, c: Cfg) -> SbdClientCrypto {
        let c = Arc::new(c.0);
        for addr in self.server.bind_addrs() {
            if let Ok(cli) =
                SbdClientCrypto::new(&format!("ws://{addr}"), c.clone()).await
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

    let c1 = test.conn(Cfg::d()).await;
    let c2 = test.conn(Cfg::d()).await;

    c2.send(c1.pub_key(), b"hello").await.unwrap();
    c1.send(c2.pub_key(), b"world").await.unwrap();

    let (rk, rm) = c1.recv().await.unwrap();
    assert_eq!(c2.pub_key(), &rk);
    assert_eq!(b"hello", rm.as_slice());

    let (rk, rm) = c2.recv().await.unwrap();
    assert_eq!(c1.pub_key(), &rk);
    assert_eq!(b"world", rm.as_slice());
}

#[tokio::test(flavor = "multi_thread")]
async fn listener_config_works() {
    let test = Test::new().await;

    let (c1, c2, c3, c4) = tokio::join!(
        test.conn(Cfg::d().no_listen()),
        test.conn(Cfg::d()),
        test.conn(Cfg::d().no_listen()),
        test.conn(Cfg::d().no_listen()),
    );

    // send from 1 to 2 and 3 to 4
    tokio::try_join!(
        c1.send(c2.pub_key(), b"yep"),
        c3.send(c4.pub_key(), b"nope"),
    )
    .unwrap();

    tokio::join!(
        async {
            // 1 to 2 should work, because 2 was a listener
            assert!(tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(1))
                    => false,
                _ = c2.recv() => true,
            });
        },
        async {
            // 3 to 4 should NOT work, because 4 was not a listener
            assert!(tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(1))
                    => true,
                _ = c4.recv() => false,
            });
        },
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn max_connections_config_works() {
    let test = Test::new().await;

    // three connections that only accept one peer at a time
    let (c1, c2, c3) = tokio::join!(
        test.conn(Cfg::d().max(1)),
        test.conn(Cfg::d().max(1)),
        test.conn(Cfg::d().max(1)),
    );

    // try to have both 2 and 3 connect to 1
    tokio::try_join!(
        c2.send(c1.pub_key(), b"msg-a"),
        c3.send(c1.pub_key(), b"msg-b"),
    )
    .unwrap();

    // 1 should get 1 of the messages
    let (got_pk, r) = c1.recv().await.unwrap();
    assert!(String::from_utf8_lossy(&r).starts_with("msg-"));

    // since 1 has an open connection, it should not be able
    // to send to the *other* peer
    if &got_pk == c2.pub_key() {
        assert!(c1.send(c3.pub_key(), b"msg-c").await.is_err());
    } else if &got_pk == c3.pub_key() {
        assert!(c1.send(c2.pub_key(), b"msg-c").await.is_err());
    }

    // and it should not receive the second message
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(1), c1.recv())
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn cooldown_config_works_from_send_side() {
    let test = Test::new().await;

    let (c1, c2, c3) = tokio::join!(
        test.conn(Cfg::d().cool(std::time::Duration::from_millis(1))),
        test.conn(Cfg::d().cool(std::time::Duration::from_millis(1))),
        test.conn(Cfg::d().cool(std::time::Duration::from_secs(5000))),
    );

    tokio::try_join!(
        c2.send(c1.pub_key(), b"msg-a"),
        c3.send(c1.pub_key(), b"msg-b"),
    )
    .unwrap();

    c2.close_peer(c1.pub_key()).await;
    c3.close_peer(c1.pub_key()).await;

    tokio::time::sleep(std::time::Duration::from_millis(2)).await;

    assert!(c3.send(c1.pub_key(), b"msg-c").await.is_err());
    assert!(c2.send(c1.pub_key(), b"msg-d").await.is_ok());

    let (_, r) = c1.recv().await.unwrap();
    assert!(r == b"msg-a" || r == b"msg-b");
    let (_, r) = c1.recv().await.unwrap();
    assert!(r == b"msg-a" || r == b"msg-b");
    let (_, r) = c1.recv().await.unwrap();
    assert!(r == b"msg-d");
}
