//! Sbd server library.
#![deny(missing_docs)]

/// defined by the sbd spec
const MAX_MSG_BYTES: i32 = 16000;

use std::io::{Error, Result};
use std::sync::{Arc, Mutex, Weak};

mod config;
pub use config::*;

mod maybe_tls;
use maybe_tls::*;

mod ip_deny;
mod ip_rate;

mod cslot;

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

    pub fn remove_ws(
        &mut self,
        pub_key: &PubKey,
        subj_ws: &Arc<ws::WebSocket<MaybeTlsStream>>,
    ) {
        let should_drop =
            if let Some(ClientInfo::Local { ws, .. }) = self.0.get(pub_key) {
                if Arc::ptr_eq(subj_ws, ws) {
                    true
                } else {
                    false
                }
            } else {
                false
            };

        if should_drop {
            self.0.remove(pub_key);
        }
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
    task_list: Vec<tokio::task::JoinHandle<()>>,
    bind_addrs: Vec<std::net::SocketAddr>,
    _client_map: Arc<Mutex<ClientMap>>,
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
    ip_deny: Arc<ip_deny::IpDeny>,
    ip_rate: Arc<ip_rate::IpRate>,
    tcp: MaybeTlsStream,
    addr: std::net::SocketAddr,
    weak_client_map: Weak<Mutex<ClientMap>>,
) {
    let raw_ip = match addr.ip() {
        std::net::IpAddr::V4(ip) => ip.to_ipv6_mapped(),
        std::net::IpAddr::V6(ip) => ip,
    };
    drop(addr);

    let mut calc_ip = raw_ip;

    let use_trusted_ip = config.trusted_ip_header.is_some();

    let (pub_key, client_info) =
        match tokio::time::timeout(std::time::Duration::from_secs(10), async {
            const PROTO_VER: &[u8; 4] = b"sbd0";
            let limit_rate = config.limit_ip_byte_nanos.to_be_bytes();

            if !use_trusted_ip {
                // Do this check BEFORE handshake to avoid extra
                // server process when capable.
                // If we *are* behind a reverse proxy, we assume
                // some amount of DDoS mitigation is happening there
                // and thus we can accept a little more process overhead
                if ip_deny.is_blocked(raw_ip).await.unwrap() {
                    return Err(Error::other("ip blocked"));
                }

                // Also precheck our rate limit, using up one byte
                if !ip_rate.is_ok(raw_ip, 1) {
                    ip_deny.block(raw_ip).await.unwrap();
                    return Err(Error::other("ip rate limited"));
                }
            }

            // TODO TLS upgrade

            let (ws, pub_key, ip) =
                ws::WebSocket::upgrade(config, tcp).await.unwrap();

            if let Some(ip) = ip {
                calc_ip = ip;
            }

            if use_trusted_ip {
                // if using a trusted ip, check block here.
                // see note above before the handshakes.
                if ip_deny.is_blocked(calc_ip).await.unwrap() {
                    return Err(Error::other("ip blocked"));
                }

                // Also precheck our rate limit, using up one byte
                if !ip_rate.is_ok(calc_ip, 1) {
                    ip_deny.block(calc_ip).await.unwrap();
                    return Err(Error::other("ip rate limited"));
                }
            }

            use rand::Rng;
            let mut nonce = [0xdb; 32];
            rand::thread_rng().fill(&mut nonce[..]);

            let mut msg = Vec::with_capacity(4 + 4 + 32);
            msg.extend_from_slice(&PROTO_VER[..]);
            msg.extend_from_slice(&limit_rate[..]);
            msg.extend_from_slice(&nonce[..]);

            ws.send(Payload::Vec(msg)).await.unwrap();

            let sig = ws.recv().await.unwrap();

            // use up 64 bytes of rate
            if !ip_rate.is_ok(calc_ip, 64) {
                ip_deny.block(calc_ip).await.unwrap();
                return Err(Error::other("ip rate limited"));
            }

            if sig.len() != 64 {
                return Err(Error::other("invalid sig len"));
            }
            let mut sig_sized = [0; 64];
            sig_sized.copy_from_slice(sig.as_ref());
            if !pub_key.verify(&sig_sized, &nonce) {
                return Err(Error::other("invalid sig"));
            }

            let ws = Arc::new(ws);

            struct DoDrop {
                pub_key: PubKey,
                ws: Weak<ws::WebSocket<MaybeTlsStream>>,
                client_map: Weak<Mutex<ClientMap>>,
            }

            impl Drop for DoDrop {
                fn drop(&mut self) {
                    if let Some(client_map) = self.client_map.upgrade() {
                        if let Some(ws) = self.ws.upgrade() {
                            client_map
                                .lock()
                                .unwrap()
                                .remove_ws(&self.pub_key, &ws);
                        }
                    }
                }
            }

            let do_drop = DoDrop {
                pub_key: pub_key.clone(),
                ws: Arc::downgrade(&ws),
                client_map: weak_client_map.clone(),
            };

            let ws2 = ws.clone();
            let weak_client_map2 = weak_client_map.clone();
            let pub_key2 = pub_key.clone();
            let read_task = tokio::task::spawn(async move {
                let _do_drop = do_drop;

                while let Ok(mut payload) = ws2.recv().await {
                    if !ip_rate.is_ok(calc_ip, payload.len()) {
                        ip_deny.block(calc_ip).await.unwrap();
                        break;
                    }

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

                        if &payload[..32] == &pub_key2.0[..] {
                            // no self-sends
                            break;
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
            });

            Ok((
                pub_key,
                ClientInfo::Local {
                    ws,
                    ip: calc_ip,
                    read_task,
                },
            ))
        })
        .await
        {
            Ok(Ok(r)) => r,
            _ => return,
        };

    if let Some(client_map) = weak_client_map.upgrade() {
        client_map.lock().unwrap().insert(pub_key, client_info);
    }
}

impl SbdServer {
    /// Construct a new running sbd server with the provided config.
    pub async fn new(config: Arc<Config>) -> Result<Self> {
        let mut task_list = Vec::new();
        let mut bind_addrs = Vec::new();
        let client_map = Arc::new(Mutex::new(ClientMap::default()));

        let ip_deny = Arc::new(ip_deny::IpDeny::new(config.clone()));

        let ip_rate = Arc::new(ip_rate::IpRate::new(
            config.limit_ip_byte_nanos as u64,
            config.limit_ip_byte_nanos as u64
                * config.limit_ip_byte_burst as u64,
        ));

        let weak_client_map = Arc::downgrade(&client_map);
        for bind in config.bind.iter() {
            let a: std::net::SocketAddr = bind.parse().map_err(Error::other)?;

            let tcp = tokio::net::TcpListener::bind(a).await?;
            bind_addrs.push(tcp.local_addr()?);

            let config = config.clone();
            let weak_client_map = weak_client_map.clone();
            let ip_deny = ip_deny.clone();
            let ip_rate = ip_rate.clone();
            task_list.push(tokio::task::spawn(async move {
                loop {
                    if let Ok((tcp, addr)) = tcp.accept().await {
                        let tcp = MaybeTlsStream::Tcp(tcp);
                        // just let this task die on its own time
                        tokio::task::spawn(check_accept_connection(
                            config.clone(),
                            ip_deny.clone(),
                            ip_rate.clone(),
                            tcp,
                            addr,
                            weak_client_map.clone(),
                        ));
                    }
                }
            }));
        }

        Ok(Self {
            task_list,
            bind_addrs,
            _client_map: client_map,
        })
    }

    /// Get the list of addresses bound locally.
    pub fn bind_addrs(&self) -> &[std::net::SocketAddr] {
        self.bind_addrs.as_slice()
    }
}
