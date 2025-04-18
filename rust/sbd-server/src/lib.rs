//! Sbd server library.
#![deny(missing_docs)]

/// defined by the sbd spec
const MAX_MSG_BYTES: i32 = 20_000;

use std::io::{Error, Result};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;

mod config;
pub use config::*;

mod maybe_tls;
pub use maybe_tls::*;

mod ip_deny;
mod ip_rate;
pub use ip_rate::*;

mod cslot;
pub use cslot::*;

mod cmd;

/// Websocket backend abstraction.
pub mod ws {
    /// Payload.
    pub enum Payload {
        /// Vec.
        Vec(Vec<u8>),

        /// BytesMut.
        BytesMut(bytes::BytesMut),
    }

    impl std::ops::Deref for Payload {
        type Target = [u8];

        #[inline(always)]
        fn deref(&self) -> &Self::Target {
            match self {
                Payload::Vec(v) => v.as_slice(),
                Payload::BytesMut(b) => b.as_ref(),
            }
        }
    }

    impl Payload {
        /// Mutable payload.
        #[inline(always)]
        pub fn to_mut(&mut self) -> &mut [u8] {
            match self {
                Payload::Vec(ref mut owned) => owned,
                Payload::BytesMut(b) => b.as_mut(),
            }
        }
    }

    #[cfg(feature = "tungstenite")]
    mod ws_tungstenite;

    use futures::future::BoxFuture;
    #[cfg(feature = "tungstenite")]
    pub use ws_tungstenite::*;

    #[cfg(all(not(feature = "tungstenite"), feature = "fastwebsockets"))]
    mod ws_fastwebsockets;
    #[cfg(all(not(feature = "tungstenite"), feature = "fastwebsockets"))]
    pub use ws_fastwebsockets::*;

    /// Websocket trait.
    pub trait SbdWebsocket: Send + Sync + 'static {
        /// Receive from the websocket.
        fn recv(&self) -> BoxFuture<'static, std::io::Result<Payload>>;

        /// Send to the websocket.
        fn send(
            &self,
            payload: Payload,
        ) -> BoxFuture<'static, std::io::Result<()>>;

        /// Close the websocket.
        fn close(&self) -> BoxFuture<'static, ()>;
    }
}

pub use ws::{Payload, SbdWebsocket};

/// Public key.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PubKey(pub Arc<[u8; 32]>);

impl PubKey {
    /// Verify a signature with this pub key.
    pub fn verify(&self, sig: &[u8; 64], data: &[u8]) -> bool {
        use ed25519_dalek::Verifier;
        if let Ok(k) = ed25519_dalek::VerifyingKey::from_bytes(&self.0) {
            k.verify(data, &ed25519_dalek::Signature::from_bytes(sig))
                .is_ok()
        } else {
            false
        }
    }
}

/// SbdServer.
pub struct SbdServer {
    task_list: Vec<tokio::task::JoinHandle<()>>,
    bind_addrs: Vec<std::net::SocketAddr>,
    _cslot: cslot::CSlot,
}

impl Drop for SbdServer {
    fn drop(&mut self) {
        for task in self.task_list.iter() {
            task.abort();
        }
    }
}

/// Convert an IP address to an IPv6 address.
pub fn to_canonical_ip(ip: IpAddr) -> Arc<Ipv6Addr> {
    Arc::new(match ip {
        IpAddr::V4(ip) => ip.to_ipv6_mapped(),
        IpAddr::V6(ip) => ip,
    })
}

/// If the check passes, the canonical IP is returned, otherwise None and the connection should be
/// dropped.
pub async fn preflight_ip_check(
    config: &Config,
    ip_rate: &IpRate,
    addr: std::net::SocketAddr,
) -> Option<Arc<Ipv6Addr>> {
    let raw_ip = to_canonical_ip(addr.ip());

    let use_trusted_ip = config.trusted_ip_header.is_some();

    if !use_trusted_ip {
        // Do this check BEFORE handshake to avoid extra
        // server process when capable.
        // If we *are* behind a reverse proxy, we assume
        // some amount of DDoS mitigation is happening there
        // and thus we can accept a little more process overhead
        if ip_rate.is_blocked(&raw_ip).await {
            return None;
        }

        // Also precheck our rate limit, using up one byte
        if !ip_rate.is_ok(&raw_ip, 1).await {
            return None;
        }
    }

    Some(raw_ip)
}

/// Handle an upgraded websocket connection.
pub async fn handle_upgraded(
    config: Arc<Config>,
    ip_rate: Arc<IpRate>,
    weak_cslot: WeakCSlot,
    ws: Arc<impl SbdWebsocket>,
    pub_key: PubKey,
    calc_ip: Arc<Ipv6Addr>,
) {
    let use_trusted_ip = config.trusted_ip_header.is_some();

    // illegal pub key
    if &pub_key.0[..28] == cmd::CMD_PREFIX {
        return;
    }

    let ws = Arc::new(ws);

    if use_trusted_ip {
        // if using a trusted ip, check block here.
        // see note above before the handshakes.
        if ip_rate.is_blocked(&calc_ip).await {
            return;
        }

        // Also precheck our rate limit, using up one byte
        if !ip_rate.is_ok(&calc_ip, 1).await {
            return;
        }
    }

    if let Some(cslot) = weak_cslot.upgrade() {
        cslot.insert(&config, calc_ip, pub_key, ws).await;
    }
}

async fn check_accept_connection(
    _connect_permit: tokio::sync::OwnedSemaphorePermit,
    config: Arc<Config>,
    tls_config: Option<Arc<TlsConfig>>,
    ip_rate: Arc<IpRate>,
    tcp: tokio::net::TcpStream,
    addr: std::net::SocketAddr,
    weak_cslot: WeakCSlot,
) {
    let _ = tokio::time::timeout(config.idle_dur(), async {
        let Some(mut calc_ip) =
            preflight_ip_check(&config, &ip_rate, addr).await
        else {
            return;
        };

        let socket = if let Some(tls_config) = &tls_config {
            match MaybeTlsStream::tls(tls_config, tcp).await {
                Err(_) => return,
                Ok(tls) => tls,
            }
        } else {
            MaybeTlsStream::Tcp(tcp)
        };

        let (ws, pub_key, ip) =
            match ws::WebSocket::upgrade(config.clone(), socket).await {
                Ok(r) => r,
                Err(_) => return,
            };

        if let Some(ip) = ip {
            calc_ip = Arc::new(ip);
        }

        handle_upgraded(
            config,
            ip_rate,
            weak_cslot,
            Arc::new(ws),
            pub_key,
            calc_ip,
        )
        .await;
    })
    .await;
}

async fn bind_all<I: IntoIterator<Item = std::net::SocketAddr>>(
    i: I,
) -> Vec<tokio::net::TcpListener> {
    let mut listeners = Vec::new();
    for a in i.into_iter() {
        if let Ok(tcp) = tokio::net::TcpListener::bind(a).await {
            listeners.push(tcp);
        }
    }
    listeners
}

impl SbdServer {
    /// Construct a new running sbd server with the provided config.
    pub async fn new(config: Arc<Config>) -> Result<Self> {
        let tls_config = if let (Some(cert), Some(pk)) =
            (&config.cert_pem_file, &config.priv_key_pem_file)
        {
            Some(Arc::new(maybe_tls::TlsConfig::new(cert, pk).await?))
        } else {
            None
        };

        let mut task_list = Vec::new();
        let mut bind_addrs = Vec::new();

        let ip_rate = Arc::new(IpRate::new(config.clone()));
        task_list.push(spawn_prune_task(ip_rate.clone()));

        let cslot = CSlot::new(config.clone(), ip_rate.clone());

        // limit the number of connections that can be "connecting" at a time.
        // MAYBE make this configurable.
        // Read this as a prioritization of existing connections over incoming
        let connect_limit = Arc::new(tokio::sync::Semaphore::new(1024));

        let mut bind_port_zero = Vec::new();
        let mut bind_explicit_port = Vec::new();

        for bind in config.bind.iter() {
            let a: std::net::SocketAddr = bind.parse().map_err(Error::other)?;

            if a.port() == 0 {
                bind_port_zero.push(a);
            } else {
                bind_explicit_port.push(a);
            }
        }

        let (mut listeners, mut l2) = tokio::join!(
            async {
                // bail if there are no zero port bindings
                if bind_port_zero.is_empty() {
                    return Vec::new();
                }

                // try twice to re-use port
                'top: for _ in 0..2 {
                    let mut listeners = Vec::new();

                    let mut a_iter = bind_port_zero.iter();

                    let a = a_iter.next().unwrap();
                    if let Ok(tcp) = tokio::net::TcpListener::bind(a).await {
                        let port = tcp.local_addr().unwrap().port();
                        listeners.push(tcp);

                        for a in a_iter {
                            let mut a = *a;
                            a.set_port(port);
                            match tokio::net::TcpListener::bind(a).await {
                                Err(_) => continue 'top,
                                Ok(tcp) => listeners.push(tcp),
                            }
                        }

                        return listeners;
                    }
                }

                // just use whatever we can get
                bind_all(bind_port_zero).await
            },
            async { bind_all(bind_explicit_port).await },
        );

        listeners.append(&mut l2);

        if listeners.is_empty() {
            return Err(Error::other("failed to bind any listeners"));
        }

        let weak_cslot = cslot.weak();
        for tcp in listeners {
            bind_addrs.push(tcp.local_addr()?);

            let tls_config = tls_config.clone();
            let connect_limit = connect_limit.clone();
            let config = config.clone();
            let weak_cslot = weak_cslot.clone();
            let ip_rate = ip_rate.clone();
            task_list.push(tokio::task::spawn(async move {
                loop {
                    if let Ok((tcp, addr)) = tcp.accept().await {
                        // Drop connections as fast as possible
                        // if we are overloaded on accepting connections.
                        let connect_permit =
                            match connect_limit.clone().try_acquire_owned() {
                                Ok(permit) => permit,
                                _ => continue,
                            };

                        // just let this task die on its own time
                        // MAYBE preallocate these tasks like cslot
                        tokio::task::spawn(check_accept_connection(
                            connect_permit,
                            config.clone(),
                            tls_config.clone(),
                            ip_rate.clone(),
                            tcp,
                            addr,
                            weak_cslot.clone(),
                        ));
                    }
                }
            }));
        }

        Ok(Self {
            task_list,
            bind_addrs,
            _cslot: cslot,
        })
    }

    /// Get the list of addresses bound locally.
    pub fn bind_addrs(&self) -> &[std::net::SocketAddr] {
        self.bind_addrs.as_slice()
    }
}

#[cfg(test)]
mod test;
