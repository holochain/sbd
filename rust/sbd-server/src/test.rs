use crate::*;

#[tokio::test(flavor = "multi_thread")]
async fn tls_sanity() {
    let tmp = tempfile::tempdir().unwrap();
    let tmp_dir = tmp.path().to_owned();
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .unwrap();
    let mut cert_path = tmp_dir.clone();
    cert_path.push("cert.pem");
    tokio::fs::write(&cert_path, cert.pem()).await.unwrap();
    let mut key_path = tmp_dir.clone();
    key_path.push("key.pem");
    tokio::fs::write(&key_path, key_pair.serialize_pem())
        .await
        .unwrap();

    let mut config = Config::default();
    config.cert_pem_file = Some(cert_path);
    config.priv_key_pem_file = Some(key_path);
    config.bind.push("127.0.0.1:0".into());
    println!("{config:?}");

    let server = SbdServer::new(Arc::new(config)).await.unwrap();

    let addr = server.bind_addrs()[0].clone();

    println!("addr: {addr:?}");

    let (client1, mut rcv1) = sbd_client::SbdClient::connect_config(
        &format!("wss://{addr}"),
        &sbd_client::DefaultCrypto::default(),
        sbd_client::SbdClientConfig {
            allow_plain_text: true,
            danger_disable_certificate_check: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let (client2, mut rcv2) = sbd_client::SbdClient::connect_config(
        &format!("wss://{addr}"),
        &sbd_client::DefaultCrypto::default(),
        sbd_client::SbdClientConfig {
            allow_plain_text: true,
            danger_disable_certificate_check: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    client1.send(client2.pub_key(), b"hello").await.unwrap();

    let res_data = rcv2.recv().await.unwrap();

    assert_eq!(&client1.pub_key()[..], res_data.pub_key_ref());
    assert_eq!(&b"hello"[..], res_data.message());

    client2.send(client1.pub_key(), b"world").await.unwrap();

    let res_data = rcv1.recv().await.unwrap();

    assert_eq!(&client2.pub_key()[..], res_data.pub_key_ref());
    assert_eq!(&b"world"[..], res_data.message());
}

#[tokio::test(flavor = "multi_thread")]
async fn fuzzy_bind_tests() {
    // these are fuzzy, because the whole point is to make a best effort
    // so we run the tests a couple times and hope we get at least 1 good one

    #[derive(Debug)]
    enum R {
        Same,
        Diff,
    }

    for (expect, addr_list) in &[
        // it should be possible to bind these to the same port
        (R::Same, &["127.0.0.1:0", "[::1]:0"][..]),
        // it will NOT be possible to bind these to the same port
        // since we're already bound to localhost, the catchall cannot dup
        (
            R::Diff,
            &["127.0.0.1:0", "[::1]:0", "0.0.0.0:0", "[::]:0"][..],
        ),
        // sanity that we can explicitly specify a port
        (
            R::Diff,
            &[
                "127.0.0.1:12233",
                "[::1]:13344",
                "0.0.0.0:14455",
                "[::]:15566",
            ][..],
        ),
        // make sure we can mix zeroes and explicit ports
        (
            R::Diff,
            &["127.0.0.1:0", "[::1]:0", "0.0.0.0:17788", "[::]:18899"][..],
        ),
    ] {
        println!("testing {expect:?} {addr_list:?}");
        let mut passed = false;

        for _ in 0..3 {
            let config = Config {
                bind: addr_list.iter().map(|a| a.to_string()).collect(),
                ..Default::default()
            };

            let server = SbdServer::new(Arc::new(config)).await.unwrap();

            let mut all_same = true;

            let addr_list = server.bind_addrs();
            println!(" - result: {addr_list:?}");

            let first = addr_list.first().unwrap();
            for addr in addr_list {
                if addr.port() != first.port() {
                    all_same = false;
                }
            }

            match expect {
                R::Same => {
                    if all_same {
                        passed = true;
                    }
                }
                R::Diff => {
                    if !all_same {
                        passed = true;
                    }
                }
            }
        }

        if !passed {
            panic!("test failed");
        }
    }
}
