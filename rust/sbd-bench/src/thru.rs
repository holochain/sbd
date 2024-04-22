use super::*;

pub struct ThruBenchmark {
    _server: SbdServer,
    crypto1: DefaultCrypto,
    send1: WsRawSend,
    recv1: WsRawRecv,
    crypto2: DefaultCrypto,
    send2: WsRawSend,
    recv2: WsRawRecv,
    message1: Option<Vec<u8>>,
    message2: Option<Vec<u8>>,
}

impl ThruBenchmark {
    pub async fn new() -> Self {
        let config = Arc::new(Config {
            bind: vec!["127.0.0.1:0".to_string(), "[::1]:0".to_string()],
            limit_clients: 100,
            disable_rate_limiting: true,
            ..Default::default()
        });

        let server = SbdServer::new(config).await.unwrap();

        let crypto1 = DefaultCrypto::default();
        let (mut send1, mut recv1) =
            raw_connect(crypto1.pub_key(), server.bind_addrs())
                .await
                .unwrap();

        let crypto2 = DefaultCrypto::default();
        let (mut send2, mut recv2) =
            raw_connect(crypto2.pub_key(), server.bind_addrs())
                .await
                .unwrap();

        Handshake::handshake(&mut send1, &mut recv1, &crypto1)
            .await
            .unwrap();
        Handshake::handshake(&mut send2, &mut recv2, &crypto2)
            .await
            .unwrap();

        Self {
            _server: server,
            crypto1,
            send1,
            recv1,
            crypto2,
            send2,
            recv2,
            message1: None,
            message2: None,
        }
    }

    pub async fn iter(&mut self) {
        let Self {
            crypto1,
            send1,
            recv1,
            crypto2,
            send2,
            recv2,
            message1,
            message2,
            ..
        } = self;

        let mut b1 = message1.take().unwrap_or_else(|| vec![0xdb; 1000]);
        let mut b2 = message2.take().unwrap_or_else(|| vec![0xca; 1000]);

        tokio::join!(
            async {
                b1[0..32].copy_from_slice(crypto2.pub_key());
                send1.send(b1).await.unwrap();
            },
            async {
                b2[0..32].copy_from_slice(crypto1.pub_key());
                send2.send(b2).await.unwrap();
            },
            async {
                let b2 = recv1.recv().await.unwrap();
                assert_eq!(1000, b2.len());
                *message2 = Some(b2);
            },
            async {
                let b1 = recv2.recv().await.unwrap();
                assert_eq!(1000, b1.len());
                *message1 = Some(b1);
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn thru_bench_test() {
        let mut b = ThruBenchmark::new().await;

        // warmup
        for _ in 0..10 {
            b.iter().await;
        }

        let start = tokio::time::Instant::now();
        for _ in 0..100 {
            b.iter().await;
        }
        let elapsed = start.elapsed();

        println!("{} nanos per iter", elapsed.as_nanos() / 100);
    }
}
