use crate::*;

#[tokio::test]
async fn drop_sender() {
    let config = Arc::new(sbd_server::Config {
        bind: vec!["127.0.0.1:0".to_string(), "[::1]:0".to_string()],
        ..Default::default()
    });

    let server = sbd_server::SbdServer::new(config).await.unwrap();

    let (s, mut r) = SbdClient::connect_config(
        &format!("ws://{}", server.bind_addrs().get(0).unwrap()),
        &DefaultCrypto::default(),
        SbdClientConfig {
            allow_plain_text: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    drop(s);

    assert!(r.recv().await.is_none());
}
