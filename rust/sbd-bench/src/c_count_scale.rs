use super::*;
use std::sync::Mutex;

pub struct Fail(Arc<tokio::sync::Semaphore>, bool);

impl Clone for Fail {
    fn clone(&self) -> Self {
        Self(self.0.clone(), false)
    }
}

impl Drop for Fail {
    fn drop(&mut self) {
        if self.1 {
            self.0.close();
        }
    }
}

impl Default for Fail {
    fn default() -> Self {
        Self(Arc::new(tokio::sync::Semaphore::new(0)), false)
    }
}

impl Fail {
    fn set_fail_on_drop(&mut self, fail_on_drop: bool) {
        self.1 = fail_on_drop;
    }

    async fn fail(&self) {
        let _ = self.0.acquire().await;
    }
}

struct Stats {
    addr: std::net::SocketAddr,
    last_ip: u32,
    client_count: usize,
    messages_sent: usize,
}

impl std::fmt::Debug for Stats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stats")
            .field("client_count", &self.client_count)
            .field("messages_sent", &self.messages_sent)
            .finish()
    }
}

async fn create_client(this: &Mutex<Stats>) -> (SbdClient, MsgRecv) {
    let crypto = DefaultCrypto::default();

    let (ip, addr) = {
        let mut lock = this.lock().unwrap();
        let ip = lock.last_ip;
        lock.last_ip += 1;
        lock.client_count += 1;
        (ip, lock.addr)
    };

    let ip = ip.to_be_bytes();
    let ip = std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]);
    let ip = format!("{ip}");

    let c = SbdClientConfig {
        allow_plain_text: true,
        headers: vec![("test-ip".to_string(), ip)],
        ..Default::default()
    };

    let url = format!("ws://{}", addr);

    SbdClient::connect_config(&url, &crypto, c).await.unwrap()
}

pub async fn c_count_scale(max: usize) -> ! {
    let config = Arc::new(Config {
        bind: vec!["127.0.0.1:0".to_string(), "[::1]:0".to_string()],
        trusted_ip_header: Some("test-ip".to_string()),
        ..Default::default()
    });

    let server = SbdServer::new(config).await.unwrap();

    let addr = *server.bind_addrs().first().unwrap();

    let stats = Arc::new(Mutex::new(Stats {
        addr,
        last_ip: u32::from_be_bytes([1, 1, 1, 1]),
        client_count: 0,
        messages_sent: 0,
    }));

    let fail = Fail::default();

    for _ in 0..16 {
        let stats = stats.clone();
        let mut fail = fail.clone();
        tokio::task::spawn(async move {
            loop {
                fail.set_fail_on_drop(true);

                let client_count = stats.lock().unwrap().client_count;
                if client_count > max {
                    fail.set_fail_on_drop(false);

                    return;
                }

                let (c_a, mut r_a) = create_client(&stats).await;
                let (c_b, mut r_b) = create_client(&stats).await;

                let mut fail = fail.clone();
                let stats = stats.clone();
                tokio::task::spawn(async move {
                    fail.set_fail_on_drop(true);

                    loop {
                        c_a.send(c_b.pub_key(), b"hello").await.unwrap();
                        c_b.send(c_a.pub_key(), b"world").await.unwrap();
                        let m = r_b.recv().await?;
                        assert_eq!(b"hello", m.message());
                        let m = r_a.recv().await?;
                        assert_eq!(b"world", m.message());

                        stats.lock().unwrap().messages_sent += 2;

                        tokio::time::sleep(std::time::Duration::from_secs(2))
                            .await;
                    }

                    #[allow(unreachable_code)]
                    Some(())
                });
            }
        });
    }

    tokio::task::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;

            println!("{:?}", *stats.lock().unwrap());
        }
    });

    fail.fail().await;

    panic!("test failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn c_count_scale_test() {
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            c_count_scale(300),
        )
        .await;
    }
}
