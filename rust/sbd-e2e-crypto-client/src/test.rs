use crate::*;
use std::sync::Arc;

pub struct Cfg(pub Config);

impl Cfg {
    pub fn d() -> Self {
        Self(Config {
            client_config: SbdClientConfig {
                allow_plain_text: true,
                ..Default::default()
            },
            listener: true,
            max_connections: 100,
            max_idle: tokio::time::Duration::from_secs(10),
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

    pub fn idle(mut self, idle: std::time::Duration) -> Self {
        self.0.max_idle = idle;
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

    pub async fn conn(&self, c: Cfg) -> (SbdClientCrypto, MsgRecv) {
        let c = Arc::new(c.0);
        for addr in self.server.bind_addrs() {
            if let Ok(r) =
                SbdClientCrypto::new(&format!("ws://{addr}"), c.clone()).await
            {
                return r;
            }
        }
        panic!("could not connect to sbd server");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sanity() {
    let test = Test::new().await;

    let (c1, mut r1) = test.conn(Cfg::d()).await;
    let (c2, mut r2) = test.conn(Cfg::d()).await;

    c2.send(c1.pub_key(), b"hello").await.unwrap();
    c1.send(c2.pub_key(), b"world").await.unwrap();

    let (rk, rm) = r1.recv().await.unwrap();
    assert_eq!(c2.pub_key(), &rk);
    assert_eq!(b"hello", rm.as_ref());

    let (rk, rm) = r2.recv().await.unwrap();
    assert_eq!(c1.pub_key(), &rk);
    assert_eq!(b"world", rm.as_ref());
}

#[tokio::test(flavor = "multi_thread")]
async fn listener_config_works() {
    let test = Test::new().await;

    let ((c1, _r1), (c2, mut r2), (c3, _r3), (c4, mut r4)) = tokio::join!(
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
                _ = r2.recv() => true,
            });
        },
        async {
            // 3 to 4 should NOT work, because 4 was not a listener
            assert!(tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(1))
                    => true,
                _ = r4.recv() => false,
            });
        },
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn max_connections_config_works() {
    let test = Test::new().await;

    // three connections that only accept one peer at a time
    let ((c1, mut r1), (c2, _r2), (c3, _r3)) = tokio::join!(
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
    let (got_pk, r) = r1.recv().await.unwrap();
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
        tokio::time::timeout(std::time::Duration::from_secs(1), r1.recv())
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn max_msg_size() {
    let test = Test::new().await;

    let ((c1, mut r1), (c2, _r2)) =
        tokio::join!(test.conn(Cfg::d()), test.conn(Cfg::d()),);

    const MSG: &[u8] = &[0xdb; 21_000];

    for (size, is_ok) in [
        (21_000, false),
        (20_000, false),
        (19_968, false),
        (19_952, false),
        (19_951, false),
        (19_950, true),
    ] {
        let res = c2.send(c1.pub_key(), &MSG[..size]).await;
        assert_eq!(is_ok, res.is_ok())
    }

    let (_, r) = r1.recv().await.unwrap();
    assert_eq!(&MSG[..19_950], r.as_ref());
}

#[tokio::test(flavor = "multi_thread")]
async fn idle_close_connections() {
    const DUR: std::time::Duration = std::time::Duration::from_millis(500);

    let test = Test::new().await;

    let ((c1, mut r1), (c2, _r2)) = tokio::join!(
        test.conn(Cfg::d().idle(DUR)),
        test.conn(Cfg::d().idle(DUR)),
    );

    c2.send(c1.pub_key(), b"wabonb").await.unwrap();
    let _ = r1.recv().await.unwrap();

    tokio::time::sleep(DUR * 2).await;

    assert_eq!(0, c1.active_peers().len());
    assert_eq!(0, c2.active_peers().len());
}
