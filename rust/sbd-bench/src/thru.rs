use super::*;

pub struct ThruBenchmark {
    _server: SbdServer,
    c1: DefaultCrypto,
    s1: WsRawSend,
    r1: WsRawRecv,
    c2: DefaultCrypto,
    s2: WsRawSend,
    r2: WsRawRecv,
    v1: Option<Vec<u8>>,
    v2: Option<Vec<u8>>,
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

        let c1 = DefaultCrypto::default();
        let (mut s1, mut r1) = raw_connect(c1.pub_key(), server.bind_addrs())
            .await
            .unwrap();

        let c2 = DefaultCrypto::default();
        let (mut s2, mut r2) = raw_connect(c2.pub_key(), server.bind_addrs())
            .await
            .unwrap();

        Handshake::handshake(&mut s1, &mut r1, &c1).await.unwrap();
        Handshake::handshake(&mut s2, &mut r2, &c2).await.unwrap();

        Self {
            _server: server,
            c1,
            s1,
            r1,
            c2,
            s2,
            r2,
            v1: None,
            v2: None,
        }
    }

    pub async fn iter(&mut self) {
        let Self {
            c1,
            s1,
            r1,
            c2,
            s2,
            r2,
            v1,
            v2,
            ..
        } = self;

        let mut b1 = v1.take().unwrap_or_else(|| vec![0xdb; 1000]);
        let mut b2 = v2.take().unwrap_or_else(|| vec![0xca; 1000]);

        tokio::join!(
            async {
                b1[0..32].copy_from_slice(c2.pub_key());
                s1.send(b1).await.unwrap();
            },
            async {
                b2[0..32].copy_from_slice(c1.pub_key());
                s2.send(b2).await.unwrap();
            },
            async {
                let b2 = r1.recv().await.unwrap();
                assert_eq!(1000, b2.len());
                *v2 = Some(b2);
            },
            async {
                let b1 = r2.recv().await.unwrap();
                assert_eq!(1000, b1.len());
                *v1 = Some(b1);
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
