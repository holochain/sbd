use sbd_client::*;
use sbd_server::*;
use std::sync::Arc;

async fn get_client(addrs: &[std::net::SocketAddr]) -> (SbdClient, MsgRecv) {
    for addr in addrs {
        if let Ok(r) = SbdClient::connect_config(
            &format!("ws://{addr}"),
            &DefaultCrypto::default(),
            SbdClientConfig {
                allow_plain_text: true,
                ..Default::default()
            },
        )
        .await
        {
            return r;
        }
    }
    panic!()
}

#[tokio::test(flavor = "multi_thread")]
async fn reasonable_rate_limit() {
    let config = Arc::new(Config {
        bind: vec!["127.0.0.1:0".to_string(), "[::1]:0".to_string()],
        limit_clients: 10,
        limit_ip_kbps: 20,
        limit_ip_byte_burst: 100000,
        ..Default::default()
    });

    let server = SbdServer::new(config).await.unwrap();

    let (mut c1, mut r1) = get_client(server.bind_addrs()).await;
    let p1 = c1.pub_key().clone();
    let (mut c2, mut r2) = get_client(server.bind_addrs()).await;
    let p2 = c2.pub_key().clone();

    //warmup
    run(2, &mut c1, &p1, &mut r1, &mut c2, &p2, &mut r2).await;

    let (rate1, rate2) =
        run(10, &mut c1, &p1, &mut r1, &mut c2, &p2, &mut r2).await;

    println!("got {rate1} bps and {rate2} bps");

    // 20 kbps divided between 2 connections
    // we should be in the range of 10000 bps
    assert!(rate1 / 10000.0 > 0.5);
    assert!(rate1 / 10000.0 < 1.5);
    assert!(rate2 / 10000.0 > 0.5);
    assert!(rate2 / 10000.0 < 1.5);
}

const MSG: &[u8; 100] = &[0xdb; 100];

async fn run(
    iters: usize,
    c1: &mut SbdClient,
    p1: &sbd_client::PubKey,
    r1: &mut MsgRecv,
    c2: &mut SbdClient,
    p2: &sbd_client::PubKey,
    r2: &mut MsgRecv,
) -> (f64, f64) {
    let start = tokio::time::Instant::now();
    let mut rate1 = 0.0;
    let mut rate2 = 0.0;
    tokio::join!(
        async {
            for _ in 0..iters {
                c1.send(&p2, MSG).await.unwrap();
                println!("c1 sent");
            }
        },
        async {
            for _ in 0..iters {
                c2.send(&p1, MSG).await.unwrap();
                println!("c2 sent");
            }
        },
        async {
            let mut tot = 0;
            loop {
                let r = r1.recv().await.unwrap();
                assert_eq!(r.pub_key_ref(), &p2[..]);
                tot += r.message().len();
                println!("r1 got {} bytes", tot);
                rate1 += (32 + r.message().len()) as f64;
                if tot >= 100 * iters {
                    break;
                }
            }
        },
        async {
            let mut tot = 0;
            loop {
                let r = r2.recv().await.unwrap();
                assert_eq!(r.pub_key_ref(), &p1[..]);
                tot += r.message().len();
                println!("r2 got {} bytes", tot);
                rate2 += (32 + r.message().len()) as f64;
                if tot >= 100 * iters {
                    break;
                }
            }
        },
    );
    let elapsed = start.elapsed().as_secs_f64();
    (rate1 / elapsed * 8.0, rate2 / elapsed * 8.0)
}
