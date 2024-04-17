//! Sbd server library.
#![deny(missing_docs)]

use std::io::{Error, Result};
use std::sync::{Arc, Mutex, Weak};

mod config;
pub use config::*;

mod maybe_tls;
use maybe_tls::*;

/// Websocket backend abstraction.
pub mod ws {
    /// Payload.
    pub enum Payload<'a> {
        /// Immutable slice.
        Slice(&'a [u8]),

        /// Mutable slice.
        SliceMut(&'a mut [u8]),

        /// Vec.
        Vec(Vec<u8>),

        /// BytesMut.
        BytesMut(bytes::BytesMut),
    }

    impl std::ops::Deref for Payload<'_> {
        type Target = [u8];

        #[inline(always)]
        fn deref(&self) -> &Self::Target {
            match self {
                Payload::Slice(b) => b,
                Payload::SliceMut(b) => b,
                Payload::Vec(v) => v.as_slice(),
                Payload::BytesMut(b) => b.as_ref(),
            }
        }
    }

    impl Payload<'_> {
        /// Mutable payload.
        #[inline(always)]
        pub fn to_mut(&mut self) -> &mut [u8] {
            match self {
                Payload::Slice(borrowed) => {
                    *self = Payload::Vec(borrowed.to_owned());
                    match self {
                        Payload::Vec(owned) => owned,
                        _ => unreachable!(),
                    }
                }
                Payload::SliceMut(borrowed) => borrowed,
                Payload::Vec(ref mut owned) => owned,
                Payload::BytesMut(b) => b.as_mut(),
            }
        }
    }

    #[cfg(feature = "tungstenite")]
    mod ws_tungstenite;
    #[cfg(feature = "tungstenite")]
    pub use ws_tungstenite::*;

    #[cfg(all(not(feature = "tungstenite"), feature = "fastwebsockets"))]
    mod ws_fastwebsockets;
    #[cfg(all(not(feature = "tungstenite"), feature = "fastwebsockets"))]
    pub use ws_fastwebsockets::*;
}

use ws::*;

/// Public key.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PubKey(pub Arc<[u8; 32]>);

impl PubKey {
    /// Verify a signature with this pub key.
    pub fn verify(&self, sig: &[u8; 64], data: &[u8]) -> bool {
        use ed25519_dalek::Verifier;
        if let Ok(k) = ed25519_dalek::VerifyingKey::from_bytes(&*self.0) {
            k.verify(data, &ed25519_dalek::Signature::from_bytes(sig))
                .is_ok()
        } else {
            false
        }
    }
}

enum ClientInfo {
    Local {
        ws: Arc<ws::WebSocket<MaybeTlsStream>>,
        ip: std::net::Ipv6Addr,
        read_task: tokio::task::JoinHandle<()>,
    }, // TODO - remote (back channel) clients
}

impl Drop for ClientInfo {
    fn drop(&mut self) {
        match self {
            Self::Local { read_task, .. } => {
                read_task.abort();
            }
        }
    }
}

struct ClientMap(std::collections::HashMap<PubKey, ClientInfo>);

impl Default for ClientMap {
    fn default() -> Self {
        Self(std::collections::HashMap::new())
    }
}

impl ClientMap {
    pub fn insert(&mut self, pub_key: PubKey, client_info: ClientInfo) {
        self.0.insert(pub_key, client_info);
    }

    pub fn get_ws(
        &mut self,
        pub_key: &PubKey,
    ) -> Option<Arc<ws::WebSocket<MaybeTlsStream>>> {
        match self.0.get(pub_key) {
            Some(ClientInfo::Local { ws, .. }) => Some(ws.clone()),
            _ => None,
        }
    }
}

/// SbdServer.
pub struct SbdServer {
    config: Arc<Config>,
    task_list: Vec<tokio::task::JoinHandle<()>>,
    bind_addrs: Vec<std::net::SocketAddr>,
    client_map: Arc<Mutex<ClientMap>>,
}

impl Drop for SbdServer {
    fn drop(&mut self) {
        for task in self.task_list.iter() {
            task.abort();
        }
    }
}

async fn check_accept_connection(
    config: Arc<Config>,
    tcp: MaybeTlsStream,
    addr: std::net::SocketAddr,
    weak_client_map: Weak<Mutex<ClientMap>>,
) {
    const PROTO_VER: &[u8; 4] = b"sbd0";
    let limit_msg = config.limit_message_bytes.to_be_bytes();
    let limit_rate = config.limit_ip_byte_nanos.to_be_bytes();

    let raw_ip = match addr.ip() {
        std::net::IpAddr::V4(ip) => ip.to_ipv6_mapped(),
        std::net::IpAddr::V6(ip) => ip,
    };

    // TODO if config.trusted_ip_header.is_none() do the ip check BEFORE upgrade

    let (ws, pub_key, ip) = ws::WebSocket::upgrade(config, tcp).await.unwrap();

    let ip: std::net::Ipv6Addr = if let Some(ip) = ip { ip } else { raw_ip };

    // TODO if config.trusted_ip_header.is_some() do the ip check AFTER upgrade

    use rand::Rng;
    let mut nonce = [0xdb; 32];
    rand::thread_rng().fill(&mut nonce[..]);

    let mut msg = Vec::with_capacity(4 + 4 + 4 + 32);
    msg.extend_from_slice(&PROTO_VER[..]);
    msg.extend_from_slice(&limit_msg[..]);
    msg.extend_from_slice(&limit_rate[..]);
    msg.extend_from_slice(&nonce[..]);

    ws.send(Payload::Vec(msg)).await.unwrap();

    let sig = ws.recv().await.unwrap();
    if sig.len() != 64 {
        return;
    }
    let mut sig_sized = [0; 64];
    sig_sized.copy_from_slice(sig.as_ref());
    if !pub_key.verify(&sig_sized, &nonce) {
        return;
    }

    let ws = Arc::new(ws);
    let ws2 = ws.clone();
    let weak_client_map2 = weak_client_map.clone();
    let pub_key2 = pub_key.clone();
    let read_task = tokio::task::spawn(async move {
        while let Ok(mut payload) = ws2.recv().await {
            // TODO - rate limiting

            if payload.len() < 32 {
                break;
            }

            const KEEPALIVE: &[u8; 32] = &[0; 32];

            let dest = {
                let payload = payload.to_mut();

                if &payload[..32] == KEEPALIVE {
                    // TODO - keepalive
                    continue;
                }

                let mut dest = [0; 32];
                dest.copy_from_slice(&payload[..32]);
                let dest = PubKey(Arc::new(dest));

                payload[..32].copy_from_slice(&pub_key2.0[..]);

                dest
            };

            if let Some(client_map) = weak_client_map2.upgrade() {
                let ws = client_map.lock().unwrap().get_ws(&dest);
                if let Some(ws) = ws {
                    if ws.send(payload).await.is_err() {
                        break;
                    }
                }
            } else {
                break;
            }
        }

        // TODO delete us from the client map
    });

    if let Some(client_map) = weak_client_map.upgrade() {
        client_map
            .lock()
            .unwrap()
            .insert(pub_key, ClientInfo::Local { ws, ip, read_task });
    } else {
        read_task.abort();
    }
}

impl SbdServer {
    /// Construct a new running sbd server with the provided config.
    pub async fn new(config: Arc<Config>) -> Result<Self> {
        let mut task_list = Vec::new();
        let mut bind_addrs = Vec::new();
        let client_map = Arc::new(Mutex::new(ClientMap::default()));

        let weak_client_map = Arc::downgrade(&client_map);
        for bind in config.bind.iter() {
            let a: std::net::SocketAddr = bind.parse().map_err(Error::other)?;

            let tcp = tokio::net::TcpListener::bind(a).await?;
            bind_addrs.push(tcp.local_addr()?);

            let config = config.clone();
            let weak_client_map = weak_client_map.clone();
            task_list.push(tokio::task::spawn(async move {
                loop {
                    if let Ok((tcp, addr)) = tcp.accept().await {
                        let tcp = MaybeTlsStream::Tcp(tcp);
                        // just let this task die on its own time
                        tokio::task::spawn(check_accept_connection(
                            config.clone(),
                            tcp,
                            addr,
                            weak_client_map.clone(),
                        ));
                    }
                }
            }));
        }

        Ok(Self {
            config,
            task_list,
            bind_addrs,
            client_map,
        })
    }

    /// Get the list of addresses bound locally.
    pub fn bind_addrs(&self) -> &[std::net::SocketAddr] {
        self.bind_addrs.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn sanity() {
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

        let (client1, url1, pk1, mut rcv1) =
            sbd_client::SbdClient::connect_config(
                &format!("ws://{addr}"),
                &sbd_client::DefaultCrypto::default(),
                sbd_client::SbdClientConfig {
                    allow_plain_text: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        println!("client url1: {url1}");

        let (client2, url2, pk2, mut rcv2) =
            sbd_client::SbdClient::connect_config(
                &format!("ws://{addr}"),
                &sbd_client::DefaultCrypto::default(),
                sbd_client::SbdClientConfig {
                    allow_plain_text: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        println!("client url2: {url2}");

        client1.send(&pk2, b"hello").await.unwrap();

        let res_data = rcv2.recv().await.unwrap();

        assert_eq!(&pk1.0, res_data.pub_key_ref());
        assert_eq!(&b"hello"[..], res_data.message());

        client2.send(&pk1, b"world").await.unwrap();

        let res_data = rcv1.recv().await.unwrap();

        assert_eq!(&pk2.0, res_data.pub_key_ref());
        assert_eq!(&b"world"[..], res_data.message());
    }
}
