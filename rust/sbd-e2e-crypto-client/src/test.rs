use crate::*;
use sbd_server::*;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

async fn endpoint(
    listener: bool,
    addrs: &[std::net::SocketAddr],
) -> SbdCryptoEndpoint {
    for addr in addrs {
        if let Ok(ep) =
            SbdCryptoEndpoint::new(&format!("ws://{addr}"), listener, true)
                .await
        {
            return ep;
        }
    }
    panic!()
}

struct TestEp {
    pub ep: Arc<SbdCryptoEndpoint>,
    pub recv_buf: Arc<Mutex<VecDeque<(sbd_client::PubKey, Vec<u8>)>>>,
    pub conn_map:
        Arc<Mutex<HashMap<sbd_client::PubKey, Arc<SbdCryptoConnection>>>>,
    task_list: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl Drop for TestEp {
    fn drop(&mut self) {
        for task in self.task_list.lock().unwrap().iter() {
            task.abort();
        }
    }
}

impl TestEp {
    pub fn new(ep: SbdCryptoEndpoint) -> Self {
        let ep = Arc::new(ep);

        let recv_buf = Arc::new(Mutex::new(VecDeque::default()));
        let conn_map = Arc::new(Mutex::new(HashMap::default()));
        let task_list = Arc::new(Mutex::new(Vec::default()));

        let ep2 = ep.clone();
        let recv_buf2 = recv_buf.clone();
        let conn_map2 = conn_map.clone();
        let task_list2 = task_list.clone();
        task_list
            .lock()
            .unwrap()
            .push(tokio::task::spawn(async move {
                while let Some(conn) = ep2.recv().await {
                    let conn = Arc::new(conn);

                    let recv_buf2 = recv_buf2.clone();
                    let conn2 = conn.clone();
                    task_list2.lock().unwrap().push(tokio::task::spawn(
                        async move {
                            while let Some(msg) = conn2.recv().await {
                                recv_buf2.lock().unwrap().push_back((conn2.pub_key, msg));
                            }
                        },
                    ));

                    conn_map2.lock().unwrap().insert(conn.pub_key, conn);
                }
            }));

        Self {
            ep,
            recv_buf,
            conn_map,
            task_list,
        }
    }
}

struct Test {
    pub server: SbdServer,
}

impl Test {
    pub async fn new() -> Self {
        let config = Arc::new(Config {
            bind: vec!["127.0.0.1:0".to_string(), "[::1]:0".to_string()],
            ..Default::default()
        });

        let server = SbdServer::new(config).await.unwrap();

        Self { server }
    }

    pub async fn ep(&self, listener: bool) -> TestEp {
        for addr in self.server.bind_addrs() {
            if let Ok(ep) =
                SbdCryptoEndpoint::new(&format!("ws://{addr}"), listener, true)
                    .await
            {
                return TestEp::new(ep);
            }
        }
        panic!("failed to connect ep");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sanity() {
    let config = Arc::new(Config {
        bind: vec!["127.0.0.1:0".to_string(), "[::1]:0".to_string()],
        ..Default::default()
    });

    let server = SbdServer::new(config).await.unwrap();
    println!("{:?}", server.bind_addrs());

    let ep1 = endpoint(true, server.bind_addrs()).await;
    let ep2 = endpoint(false, server.bind_addrs()).await;

    let c2 = ep2.connect(ep1.pub_key()).await.unwrap();
    let c1 = ep1.recv().await.unwrap();

    c1.send(b"hello").await.unwrap();
    c2.send(b"world").await.unwrap();

    let r = c1.recv().await.unwrap();
    assert_eq!(b"world", r.as_slice());

    let r = c2.recv().await.unwrap();
    assert_eq!(b"hello", r.as_slice());
}
