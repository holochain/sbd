//! Sbd server library.
#![deny(missing_docs)]

/// defined by the sbd spec
const MAX_MSG_BYTES: i32 = 16000;

use std::io::{Error, Result};
use std::sync::Arc;

mod config;
pub use config::*;

mod maybe_tls;
use maybe_tls::*;

mod ip_deny;
mod ip_rate;

mod cslot;

mod cmd;

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

async fn check_accept_connection(
    _connect_permit: tokio::sync::OwnedSemaphorePermit,
    config: Arc<Config>,
    ip_rate: Arc<ip_rate::IpRate>,
    tcp: tokio::net::TcpStream,
    addr: std::net::SocketAddr,
    weak_cslot: cslot::WeakCSlot,
) {
    let raw_ip = Arc::new(match addr.ip() {
        std::net::IpAddr::V4(ip) => ip.to_ipv6_mapped(),
        std::net::IpAddr::V6(ip) => ip,
    });

    let mut calc_ip = raw_ip.clone();

    let use_trusted_ip = config.trusted_ip_header.is_some();

    let _ = tokio::time::timeout(config.idle_dur(), async {
        if !use_trusted_ip {
            // Do this check BEFORE handshake to avoid extra
            // server process when capable.
            // If we *are* behind a reverse proxy, we assume
            // some amount of DDoS mitigation is happening there
            // and thus we can accept a little more process overhead
            if ip_rate.is_blocked(&raw_ip).await {
                return;
            }

            // Also precheck our rate limit, using up one byte
            if !ip_rate.is_ok(&raw_ip, 1).await {
                return;
            }
        }

        // TODO TLS upgrade
        let tcp = MaybeTlsStream::Tcp(tcp);

        let (ws, pub_key, ip) =
            ws::WebSocket::upgrade(config.clone(), tcp).await.unwrap();
        let ws = Arc::new(ws);

        if let Some(ip) = ip {
            calc_ip = Arc::new(ip);
        }

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
            cslot
                .insert(calc_ip, pub_key, ws, config.limit_ip_byte_nanos)
                .await;
        }
    })
    .await;
}

impl SbdServer {
    /// Construct a new running sbd server with the provided config.
    pub async fn new(config: Arc<Config>) -> Result<Self> {
        let mut task_list = Vec::new();
        let mut bind_addrs = Vec::new();

        let ip_rate = Arc::new(ip_rate::IpRate::new(config.clone()));

        {
            let ip_rate = Arc::downgrade(&ip_rate);
            task_list.push(tokio::task::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    if let Some(ip_rate) = ip_rate.upgrade() {
                        ip_rate.prune();
                    } else {
                        break;
                    }
                }
            }));
        }

        let cslot = cslot::CSlot::new(config.clone(), ip_rate.clone());

        // limit the number of connections that can be "connecting" at a time.
        // MAYBE make this configurable.
        // read this as a prioritization of existing connections over incoming
        let connect_limit = Arc::new(tokio::sync::Semaphore::new(1024));

        let weak_cslot = cslot.weak();
        for bind in config.bind.iter() {
            let a: std::net::SocketAddr = bind.parse().map_err(Error::other)?;

            let tcp = tokio::net::TcpListener::bind(a).await?;
            bind_addrs.push(tcp.local_addr()?);

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
