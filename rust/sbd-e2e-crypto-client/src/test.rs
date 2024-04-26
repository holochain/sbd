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

    pub fn cool(mut self, cool: std::time::Duration) -> Self {
        self.0.cooldown = cool;
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
async fn max_msg_size() {
    let test = Test::new().await;

    let (c1, c2) = tokio::join!(test.conn(Cfg::d()), test.conn(Cfg::d()),);

    const MSG: &[u8] = &[0xdb; 21_000];

    for (size, is_ok) in [
        (21_000, false),
        (20_000, false),
        (19_968, false),
        (19_952, false),
        (19_951, true),
    ] {
        assert_eq!(is_ok, c2.send(c1.pub_key(), &MSG[..size]).await.is_ok())
    }

    let (_, r) = c1.recv().await.unwrap();
    assert_eq!(&MSG[..19_951], r.as_slice());
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

    let (_, r) = c1.recv().await.unwrap();
    assert!(r == b"msg-a" || r == b"msg-b");
    let (_, r) = c1.recv().await.unwrap();
    assert!(r == b"msg-a" || r == b"msg-b");

    c2.close_peer(c1.pub_key()).await;
    c3.close_peer(c1.pub_key()).await;

    tokio::time::sleep(std::time::Duration::from_millis(2)).await;

    assert!(c3.send(c1.pub_key(), b"msg-c").await.is_err());
    assert!(c2.send(c1.pub_key(), b"msg-d").await.is_ok());

    let (_, r) = c1.recv().await.unwrap();
    assert!(r == b"msg-d");
}

#[tokio::test(flavor = "multi_thread")]
async fn cooldown_config_works_from_recv_side() {
    let test = Test::new().await;

    let (c1, c2, c3) = tokio::join!(
        test.conn(Cfg::d().cool(std::time::Duration::from_secs(5000))),
        test.conn(Cfg::d().cool(std::time::Duration::from_millis(1))),
        test.conn(Cfg::d().cool(std::time::Duration::from_millis(1))),
    );

    tokio::try_join!(
        c3.send(c1.pub_key(), b"msg-a"),
        c3.send(c2.pub_key(), b"msg-b"),
    )
    .unwrap();

    let (_, r) = c1.recv().await.unwrap();
    assert_eq!(b"msg-a", r.as_slice());
    let (_, r) = c2.recv().await.unwrap();
    assert_eq!(b"msg-b", r.as_slice());

    c1.close_peer(c3.pub_key()).await;
    c2.close_peer(c3.pub_key()).await;

    // note we have to close the send side too, or it won't re-init crypto
    c3.close_peer(c1.pub_key()).await;
    c3.close_peer(c2.pub_key()).await;

    tokio::time::sleep(std::time::Duration::from_millis(2)).await;

    tokio::try_join!(
        c3.send(c1.pub_key(), b"msg-c"),
        c3.send(c2.pub_key(), b"msg-d"),
    )
    .unwrap();

    let (_, r) = c2.recv().await.unwrap();
    assert_eq!(b"msg-d", r.as_slice());

    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(1), c1.recv())
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn idle_close_even_if_sending() {
    let (took, exited_early) =
        idle_close_even_if_sending_inner(std::time::Duration::from_secs(5000))
            .await;
    assert!(!exited_early);
    let iter_millis = took.as_millis() as u64 / 20;
    println!("1 iter took: {} millis", iter_millis);

    // let's try to have it close right in the middle of the run
    let (_took, exited_early) = idle_close_even_if_sending_inner(
        std::time::Duration::from_millis(iter_millis * 10),
    )
    .await;
    assert!(exited_early);
}

async fn idle_close_even_if_sending_inner(
    idle_dur: std::time::Duration,
) -> (std::time::Duration, bool) {
    let test = Test::new().await;

    let (c1, c2) = tokio::join!(
        test.conn(Cfg::d().idle(idle_dur)),
        test.conn(Cfg::d().idle(idle_dur)),
    );

    c2.send(c1.pub_key(), b"").await.unwrap();
    let _ = c1.recv().await.unwrap();

    let mut exited_early = false;

    let start = tokio::time::Instant::now();
    for i in 0..20 {
        let istart = tokio::time::Instant::now();
        if c2.send(c1.pub_key(), &[i]).await.is_err() {
            exited_early = true;
            break;
        }
        match tokio::time::timeout(std::time::Duration::from_secs(1), c1.recv())
            .await
        {
            Err(_) | Ok(None) => {
                exited_early = true;
                break;
            }
            Ok(Some((_, r))) => {
                assert_eq!(&[i], r.as_slice());
            }
        }
        let ielapsed = istart.elapsed();
        let ten = std::time::Duration::from_millis(10);
        if ielapsed < ten {
            tokio::time::sleep(ten - ielapsed).await;
        }
    }
    (start.elapsed(), exited_early)
}
