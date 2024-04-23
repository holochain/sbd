//! Sbd end to end encryption client.
#![deny(missing_docs)]

use std::collections::HashMap;
use std::io::{Error, Result};
use std::sync::{Arc, Mutex, Weak};

mod sodoken_crypto;
pub use sodoken_crypto::*;

type MsgSend = tokio::sync::mpsc::Sender<sbd_client::Msg>;
type MsgRecv = tokio::sync::mpsc::Receiver<sbd_client::Msg>;

type ConnSend = tokio::sync::mpsc::Sender<SbdCryptoConnection>;
type ConnRecv =
    tokio::sync::Mutex<tokio::sync::mpsc::Receiver<SbdCryptoConnection>>;

enum PeerEntry {
    Cooldown(tokio::time::Instant),
    Active(ConRef),
}

struct ConRef {
    recv: MsgSend,
    #[allow(clippy::type_complexity)]
    send: Weak<
        Mutex<
            Option<
                Arc<
                    tokio::sync::Mutex<(
                        Weak<sbd_client::SbdClient>,
                        sodoken_crypto::Encryptor,
                    )>,
                >,
            >,
        >,
    >,
}

enum FetchResult {
    Err(Error),
    None,
    Cooldown,
    Insert(SbdCryptoConnection, [u8; 24], MsgSend),
    Fetch(MsgSend),
}

struct PeerMap {
    weak_client: Weak<sbd_client::SbdClient>,
    crypto: Arc<sodoken_crypto::SodokenCrypto>,
    listener: bool,
    conn_send: ConnSend,
    map: Arc<Mutex<HashMap<sbd_client::PubKey, PeerEntry>>>,
    weak_peer_map: Weak<Self>,
}

impl PeerMap {
    fn cool_down(&self, pub_key: sbd_client::PubKey) {
        let t =
            tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        let rm = self
            .map
            .lock()
            .unwrap()
            .insert(pub_key, PeerEntry::Cooldown(t));
        if let Some(PeerEntry::Active(conn_ref)) = rm {
            if let Some(send) = conn_ref.send.upgrade() {
                send.lock().unwrap().take();
            }
        }
    }

    async fn handle_msg_okay(&self, msg: sbd_client::Msg) -> bool {
        match self.fetch_or_maybe_insert_conn(msg.pub_key(), self.listener) {
            FetchResult::Err(_) => false,
            FetchResult::Cooldown => true,
            FetchResult::Fetch(msg_send) => {
                let _ = msg_send.send(msg).await;
                true
            }
            FetchResult::None => true,
            FetchResult::Insert(c, h, m) => {
                let _ = c.raw_send(&h).await;
                let _ = m.send(msg).await;
                self.conn_send.send(c).await.is_ok()
            }
        }
    }

    fn prune(map: &mut HashMap<sbd_client::PubKey, PeerEntry>) {
        let now = tokio::time::Instant::now();
        map.retain(|_, e| match e {
            PeerEntry::Cooldown(at) => now < *at,
            PeerEntry::Active(conn_ref) => {
                if let Some(send) = conn_ref.send.upgrade() {
                    send.lock().unwrap().is_some()
                } else {
                    false
                }
            }
        });
    }

    fn try_insert_conn(
        &self,
        pub_key: sbd_client::PubKey,
    ) -> Result<(SbdCryptoConnection, [u8; 24])> {
        match self.fetch_or_maybe_insert_conn(pub_key, true) {
            FetchResult::Err(err) => Err(err),
            FetchResult::Cooldown => {
                Err(Error::other("connection still cooling down"))
            }
            FetchResult::Fetch(_) => {
                Err(Error::other("connection already active"))
            }
            FetchResult::None => unreachable!(),
            FetchResult::Insert(c, h, _) => Ok((c, h)),
        }
    }

    fn fetch_or_maybe_insert_conn(
        &self,
        pub_key: sbd_client::PubKey,
        should_insert: bool,
    ) -> FetchResult {
        let mut lock = self.map.lock().unwrap();

        Self::prune(&mut lock);

        use std::collections::hash_map::Entry;
        match lock.entry(pub_key) {
            Entry::Occupied(e) => match e.get() {
                PeerEntry::Cooldown(_) => FetchResult::Cooldown,
                PeerEntry::Active(r) => FetchResult::Fetch(r.recv.clone()),
            },
            Entry::Vacant(e) => {
                if !should_insert {
                    return FetchResult::None;
                }

                let (enc, hdr, dec) = match self.crypto.new_enc(&pub_key.0) {
                    Err(err) => return FetchResult::Err(err),
                    Ok(r) => r,
                };

                let send = (self.weak_client.clone(), enc);
                let send = tokio::sync::Mutex::new(send);
                let send = Arc::new(send);
                let send = Some(send);
                let send = Mutex::new(send);
                let send = Arc::new(send);
                let weak_send = Arc::downgrade(&send);
                let (msg_send, msg_recv) = tokio::sync::mpsc::channel(32);
                let msg_recv = tokio::sync::Mutex::new((msg_recv, dec));

                let conn = SbdCryptoConnection {
                    pub_key,
                    recv: msg_recv,
                    send,
                    weak_peer_map: self.weak_peer_map.clone(),
                };

                let conn_ref = ConRef {
                    recv: msg_send.clone(),
                    send: weak_send,
                };

                e.insert(PeerEntry::Active(conn_ref));

                FetchResult::Insert(conn, hdr, msg_send)
            }
        }
    }
}

/// A secure communication channel over an sbd relay server to a single
/// remote peer.
pub struct SbdCryptoConnection {
    pub_key: sbd_client::PubKey,
    recv: tokio::sync::Mutex<(MsgRecv, sodoken_crypto::Decryptor)>,
    #[allow(clippy::type_complexity)]
    send: Arc<
        Mutex<
            Option<
                Arc<
                    tokio::sync::Mutex<(
                        Weak<sbd_client::SbdClient>,
                        sodoken_crypto::Encryptor,
                    )>,
                >,
            >,
        >,
    >,
    weak_peer_map: Weak<PeerMap>,
}

impl Drop for SbdCryptoConnection {
    fn drop(&mut self) {
        self.close();
    }
}

impl SbdCryptoConnection {
    /// Receive a message from the remote peer.
    pub async fn recv(&self) -> Option<Vec<u8>> {
        let mut out = None;
        {
            let mut lock = self.recv.lock().await;
            for _ in 0..2 {
                let raw_msg = match lock.0.recv().await {
                    None => break,
                    Some(raw_msg) => raw_msg,
                };

                match lock.1.decrypt(raw_msg.message()) {
                    Ok(Some(msg)) => {
                        out = Some(msg);
                        break;
                    }
                    Ok(None) => (),
                    Err(_) => break,
                }
            }
        }
        match out {
            Some(msg) => Some(msg),
            None => {
                self.close();
                None
            }
        }
    }

    /// Send a message to the remote peer.
    pub async fn send(&self, msg: &[u8]) -> Result<()> {
        let result = self.send_inner(msg).await;
        if result.is_err() {
            self.close();
        }
        result
    }

    async fn send_inner(&self, msg: &[u8]) -> Result<()> {
        let inner = self.send.lock().unwrap().clone();
        let inner = match inner {
            Some(inner) => inner,
            None => return Err(Error::other("closed")),
        };
        let mut lock = inner.lock().await;
        let msg = lock.1.encrypt(msg)?;
        if let Some(client) = lock.0.upgrade() {
            client.send(&self.pub_key, &msg).await?;
            Ok(())
        } else {
            Err(Error::other("closed"))
        }
    }

    /// Close the connection.
    pub fn close(&self) {
        self.send.lock().unwrap().take();
        if let Some(peer_map) = self.weak_peer_map.upgrade() {
            peer_map.cool_down(self.pub_key);
        }
    }

    async fn raw_send(&self, msg: &[u8]) -> Result<()> {
        let result = self.raw_send_inner(msg).await;
        if result.is_err() {
            self.close();
        }
        result
    }

    async fn raw_send_inner(&self, msg: &[u8]) -> Result<()> {
        let inner = self.send.lock().unwrap().clone();
        let inner = match inner {
            Some(inner) => inner,
            None => return Err(Error::other("closed")),
        };
        let lock = inner.lock().await;
        if let Some(client) = lock.0.upgrade() {
            client.send(&self.pub_key, msg).await?;
            Ok(())
        } else {
            Err(Error::other("closed"))
        }
    }
}

/// A registry for establishing (or accepting incoming) secure communications
/// channels over an sbd relay server.
pub struct SbdCryptoEndpoint {
    pub_key: sbd_client::PubKey,
    recv_task: tokio::task::JoinHandle<()>,
    weak_peer_map: Weak<PeerMap>,
    conn_recv: ConnRecv,
}

impl Drop for SbdCryptoEndpoint {
    fn drop(&mut self) {
        self.recv_task.abort();
    }
}

impl SbdCryptoEndpoint {
    /// Connect to an sbd server as a client.
    /// If listener is set to `true`, messages from unknown peers will
    /// be received as new connections. If listener is set to `false`,
    /// messages from unknown peers will be ignored.
    pub async fn new(
        url: &str,
        listener: bool,
        allow_plain_text: bool,
    ) -> Result<Self> {
        let crypto = Arc::new(SodokenCrypto::new()?);

        let (client, _, pub_key, mut recv) =
            sbd_client::SbdClient::connect_config(
                url,
                &*crypto,
                sbd_client::SbdClientConfig {
                    allow_plain_text,
                    ..Default::default()
                },
            )
            .await?;

        let client = Arc::new(client);

        let (conn_send, conn_recv) = tokio::sync::mpsc::channel(32);

        let peer_map = Arc::new_cyclic(|this| PeerMap {
            weak_client: Arc::downgrade(&client),
            crypto,
            listener,
            conn_send,
            map: Arc::new(Mutex::new(HashMap::default())),
            weak_peer_map: this.clone(),
        });
        let weak_peer_map = Arc::downgrade(&peer_map);

        let recv_task = tokio::task::spawn(async move {
            while let Some(msg) = recv.recv().await {
                if !peer_map.handle_msg_okay(msg).await {
                    break;
                }
            }
            client.close().await;
        });

        Ok(Self {
            pub_key,
            recv_task,
            weak_peer_map,
            conn_recv: tokio::sync::Mutex::new(conn_recv),
        })
    }

    /// The local pub key of this node.
    pub fn pub_key(&self) -> sbd_client::PubKey {
        self.pub_key
    }

    /// Receive a new incoming connection.
    pub async fn recv(&self) -> Option<SbdCryptoConnection> {
        self.conn_recv.lock().await.recv().await
    }

    /// Establish a new outgoing connection.
    pub async fn connect(
        &self,
        peer_pub_key: sbd_client::PubKey,
    ) -> Result<SbdCryptoConnection> {
        if let Some(peer_map) = self.weak_peer_map.upgrade() {
            let (conn, hdr) = peer_map.try_insert_conn(peer_pub_key)?;
            conn.raw_send(&hdr).await?;
            Ok(conn)
        } else {
            Err(Error::other("closed"))
        }
    }
}

#[cfg(test)]
mod test;
