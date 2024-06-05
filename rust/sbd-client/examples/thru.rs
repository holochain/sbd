use sbd_client::*;

const DATA: [u8; 4096] = [0xdb; 4096];

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let mut it = std::env::args();
    it.next().expect("please specify sbd server url");
    let url = it.next().expect("please specify sbd server url");
    println!("url: {url}");

    let crypto1 = DefaultCrypto::default();
    let (cli1, mut recv1) = SbdClient::connect_config(
        &url,
        &crypto1,
        SbdClientConfig {
            allow_plain_text: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let crypto2 = DefaultCrypto::default();
    let (cli2, mut recv2) = SbdClient::connect_config(
        &url,
        &crypto2,
        SbdClientConfig {
            allow_plain_text: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    iter(&cli1, &mut recv1, &cli2, &mut recv2).await;

    let mut tx = 0.0_f64;
    let start = std::time::Instant::now();
    while start.elapsed() < std::time::Duration::from_secs(3) {
        iter(&cli1, &mut recv1, &cli2, &mut recv2).await;
        tx += DATA.len() as f64 * 2.0;
    }

    let elapsed = start.elapsed().as_secs_f64();
    let m_bits_per_sec = tx * 0.000008 / elapsed;
    println!("- TOTAL SENT: {tx} bytes");
    println!("- TOTAL TIME: {elapsed} s");
    println!("- THROUGHPUT: {m_bits_per_sec} mbps");
}

async fn iter(
    cli1: &SbdClient,
    recv1: &mut MsgRecv,
    cli2: &SbdClient,
    recv2: &mut MsgRecv,
) {
    tokio::try_join!(
        cli1.send(cli2.pub_key(), &DATA[..]),
        cli2.send(cli1.pub_key(), &DATA[..]),
    )
    .unwrap();

    let (r1, r2) = tokio::join!(recv1.recv(), recv2.recv(),);

    assert_eq!(&DATA[..], r1.unwrap().message());
    assert_eq!(&DATA[..], r2.unwrap().message());
}
