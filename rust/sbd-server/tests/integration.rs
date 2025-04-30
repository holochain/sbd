use sbd_client::raw_client::*;
use sbd_client::*;
use sbd_server::*;
use std::sync::Arc;

async fn get_client(
    pk: &[u8; 32],
    addrs: &[std::net::SocketAddr],
) -> (WsRawSend, WsRawRecv) {
    use base64::Engine;

    for addr in addrs {
        if let Ok(r) = (WsRawConnect {
            full_url: format!(
                "ws://{addr}/{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pk)
            ),
            max_message_size: 100,
            allow_plain_text: true,
            danger_disable_certificate_check: false,
            headers: Vec::new(),
            auth_material: None,
            alter_token_cb: None,
        })
        .connect()
        .await
        {
            return r;
        }
    }
    panic!()
}

#[tokio::test(flavor = "multi_thread")]
async fn rate_limit_enforced() {
    let config = Arc::new(Config {
        bind: vec!["127.0.0.1:0".to_string(), "[::1]:0".to_string()],
        limit_clients: 10,
        limit_ip_kbps: 1,
        limit_ip_byte_burst: 1000,
        ..Default::default()
    });

    let server = SbdServer::new(config).await.unwrap();

    let c1 = DefaultCrypto::default();
    let (mut s1, mut r1) = get_client(c1.pub_key(), server.bind_addrs()).await;
    let c2 = DefaultCrypto::default();
    let (mut s2, mut r2) = get_client(c2.pub_key(), server.bind_addrs()).await;

    Handshake::handshake(&mut s1, &mut r1, &c1).await.unwrap();
    Handshake::handshake(&mut s2, &mut r2, &c2).await.unwrap();

    let mut msg = Vec::with_capacity(32 + 5);
    msg.extend_from_slice(c2.pub_key());
    msg.extend_from_slice(b"hello");

    let start_send_fast_s = Arc::new(tokio::sync::Barrier::new(2));
    let start_send_fast_r = start_send_fast_s.clone();

    let mut send_slow_complete = false;
    let mut send_fast_complete = false;

    tokio::select! {
        _ = async {
            loop {
                if r1.recv().await.is_err() {
                    eprintln!("R1 RECV ERR");
                    break;
                }
            }
        } => (),
        _ = async {
            // should be able to send on the order of millis
            for _ in 0..10 {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                if s1.send(msg.clone()).await.is_err() {
                    eprintln!("S1 SLOW SEND ERR");
                    break;
                }
            }

            start_send_fast_s.wait().await;

            // but should get dropped if we start spamming
            for _ in 0..100 {
                if s1.send(msg.clone()).await.is_err() {
                    eprintln!("S1 FAST SEND ERR");
                    break;
                }
            }

            // the receive side is what triggers this to exit
            std::future::pending::<()>().await;
        } => (),
        _ = async {
            for _ in 0..10 {
                let r = match r2.recv().await {
                    Ok(r) => r,
                    Err(_) => {
                        eprintln!("R2 SLOW RECV ERR");
                        break;
                    }
                };
                assert_eq!(32 + 5, r.len());
            }

            send_slow_complete = true;
            start_send_fast_r.wait().await;

            for _ in 0..100 {
                let r = match r2.recv().await {
                    Ok(r) => r,
                    Err(_) => {
                        eprintln!("R2 FAST RECV ERR");
                        break;
                    }
                };
                assert_eq!(32 + 5, r.len());
            }

            send_fast_complete = true;
        } => (),
    }

    assert!(send_slow_complete);
    assert!(!send_fast_complete);
}
