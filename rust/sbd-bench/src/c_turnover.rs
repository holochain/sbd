use super::*;
use std::collections::VecDeque;

pub struct CTurnoverBenchmark {
    server: SbdServer,
    house: VecDeque<(WsRawSend, WsRawRecv)>,
}

impl CTurnoverBenchmark {
    pub async fn new() -> Self {
        let config = Arc::new(Config {
            bind: vec!["127.0.0.1:0".to_string(), "[::1]:0".to_string()],
            limit_clients: 4,
            ..Default::default()
        });

        let server = SbdServer::new(config).await.unwrap();

        let mut this = Self {
            server,
            house: VecDeque::new(),
        };

        // make sure we have a full house even before the warmup
        this.iter().await;

        this
    }

    pub async fn iter(&mut self) {
        // ensure full house
        while self.try_connect().await.is_ok() {}

        // drop one
        if let Some((mut s, r)) = self.house.pop_front() {
            s.close().await;
            drop(s);
            drop(r);
        }

        // this next one should succeed
        self.try_connect().await.unwrap();
    }

    async fn try_connect(&mut self) -> std::io::Result<()> {
        let c = DefaultCrypto::default();
        let (mut s, mut r) =
            raw_connect(c.pub_key(), self.server.bind_addrs()).await?;
        Handshake::handshake(&mut s, &mut r, &c).await?;
        self.house.push_back((s, r));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn c_turnover_bench_test() {
        let mut b = CTurnoverBenchmark::new().await;

        // warmup
        for _ in 0..10 {
            b.iter().await;
        }

        let start = tokio::time::Instant::now();
        for _ in 0..10 {
            b.iter().await;
        }
        let elapsed = start.elapsed();

        println!("{} nanos per iter", elapsed.as_nanos() / 10);
    }
}
