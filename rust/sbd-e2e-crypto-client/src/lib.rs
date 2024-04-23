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

struct Peer {
    msg_send: MsgSend,
}

struct PeerMap {
    listener: bool,
    crypto: Arc<SodokenCrypto>,
    client: Weak<sbd_client::SbdClient>,
    conn_send: ConnSend,
    map: Mutex<HashMap<sbd_client::PubKey, Peer>>,
}

impl PeerMap {
    pub fn new(
        listener: bool,
        crypto: Arc<SodokenCrypto>,
        client: Weak<sbd_client::SbdClient>,
        conn_send: ConnSend,
    ) -> Self {
        Self {
            listener,
            crypto,
            client,
            conn_send,
            map: Mutex::new(HashMap::default()),
        }
    }

    pub fn new_outgoing(
        &self,
        peer_pub_key: sbd_client::PubKey,
    ) -> Result<SbdCryptoConnection> {
        use std::collections::hash_map::Entry;

        let mut lock = self.map.lock().unwrap();
        match lock.entry(peer_pub_key.clone()) {
            Entry::Occupied(_) => Err(Error::other("already connected")),
            Entry::Vacant(e) => {
                let (enc, dec) = self.crypto.new_enc(&peer_pub_key.0)?;
                let (msg_send, msg_recv) = tokio::sync::mpsc::channel(32);
                let conn = SbdCryptoConnection {
                    pub_key: peer_pub_key,
                    decrypt: tokio::sync::Mutex::new(Decrypt::new(msg_recv, dec)),
                    client: self.client.clone(),
                    encryptor: tokio::sync::Mutex::new(enc),
                };
                e.insert(Peer { msg_send });
                Ok(conn)
            }
        }
    }

    pub async fn send(&self, msg: sbd_client::Msg) -> Result<()> {
        use std::collections::hash_map::Entry;

        let mut conn_send = None;

        let pub_key = msg.pub_key();

        let sender = {
            let mut lock = self.map.lock().unwrap();
            match lock.entry(pub_key.clone()) {
                Entry::Occupied(e) => Some(e.get().msg_send.clone()),
                Entry::Vacant(e) => {
                    if self.listener {
                        let (enc, dec) = self.crypto.new_enc(&pub_key.0)?;
                        let (msg_send, msg_recv) =
                            tokio::sync::mpsc::channel(32);
                        let conn = SbdCryptoConnection {
                            pub_key,
                            decrypt: tokio::sync::Mutex::new(Decrypt::new(
                                msg_recv,
                                dec,
                            )),
                            client: self.client.clone(),
                            encryptor: tokio::sync::Mutex::new(enc),
                        };
                        conn_send = Some(conn);
                        e.insert(Peer {
                            msg_send: msg_send.clone(),
                        });
                        Some(msg_send)
                    } else {
                        None
                    }
                }
            }
        };

        if let Some(conn) = conn_send {
            let _ = conn.init().await;
            let _ = self.conn_send.send(conn).await;
        }
        if let Some(sender) = sender {
            println!("GOT RECV: forwarding: {:?}", msg.message());
            let _ = sender.send(msg);
        }

        Ok(())
    }
}

struct Decrypt {
    msg_recv: MsgRecv,
    decryptor: Decryptor,
}

impl Decrypt {
    pub fn new(msg_recv: MsgRecv, decryptor: Decryptor) -> Self {
        Self { msg_recv, decryptor: decryptor }
    }

    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        loop {
            let raw_msg = match self.msg_recv.recv().await {
                None => return None,
                Some(raw_msg) => raw_msg,
            };
            println!("DEC got raw: {:?}", raw_msg.message());

            match self.decryptor.decrypt(raw_msg.message()) {
                Ok(msg) => return Some(msg),
                Err(_) => {
                    println!("dec fail, try header");
                    if raw_msg.message().len() == 24 {
                        let mut header = [0; 24];
                        header.copy_from_slice(raw_msg.message());
                        if self.decryptor.init(header).is_err() {
                            return None;
                        } else {
                            println!("header ok");
                            continue;
                        }
                    } else {
                        return None;
                    }
                }
            }
        }
    }
}

/// A secure communication channel over an sbd relay server to a single
/// remote peer.
pub struct SbdCryptoConnection {
    pub_key: sbd_client::PubKey,
    decrypt: tokio::sync::Mutex<Decrypt>,
    client: Weak<sbd_client::SbdClient>,
    encryptor: tokio::sync::Mutex<Encryptor>,
}

impl SbdCryptoConnection {
    /// Pub key of the remote peer.
    pub fn peer_pub_key(&self) -> &sbd_client::PubKey {
        todo!()
    }

    /// Receive a message from the remote peer.
    pub async fn recv(&self) -> Option<Vec<u8>> {
        self.decrypt.lock().await.recv().await
    }

    /// Send a message to the remote peer.
    pub async fn send(&self, msg: &[u8]) -> Result<()> {
        let mut lock = self.encryptor.lock().await;
        let enc = lock.encrypt(msg)?;
        self.raw_send(&enc).await
    }

    // -- private -- //

    async fn raw_send(&self, msg: &[u8]) -> Result<()> {
        if let Some(client) = self.client.upgrade() {
            client.send(&self.pub_key, msg).await?;
            println!("sent {msg:?}");
            Ok(())
        } else {
            Err(Error::other("closed"))
        }
    }

    async fn init(&self) -> Result<()> {
        let mut lock = self.encryptor.lock().await;
        let header = lock.init()?;
        self.raw_send(&header).await
    }
}

/// A registry for establishing (or accepting incoming) secure communications
/// channels over an sbd relay server.
pub struct SbdCryptoEndpoint {
    pub_key: sbd_client::PubKey,
    recv_task: tokio::task::JoinHandle<()>,
    peer_map: Arc<PeerMap>,
    conn_recv: ConnRecv,
    _client: Arc<sbd_client::SbdClient>,
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
        let peer_map = Arc::new(PeerMap::new(
            listener,
            crypto,
            Arc::downgrade(&client),
            conn_send,
        ));

        let weak_peer_map = Arc::downgrade(&peer_map);
        let recv_task = tokio::task::spawn(async move {
            while let Some(msg) = recv.recv().await {
                println!("recv {:?}", msg.message());
                if let Some(peer_map) = weak_peer_map.upgrade() {
                    if peer_map.send(msg).await.is_err() {
                        // TODO - remove the entry
                    }
                } else {
                    // TODO - remove the entry
                }
            }
        });

        Ok(Self {
            pub_key,
            recv_task,
            peer_map,
            conn_recv: tokio::sync::Mutex::new(conn_recv),
            _client: client,
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
        let conn = self.peer_map.new_outgoing(peer_pub_key)?;
        conn.init().await?;
        Ok(conn)
    }
}

#[cfg(test)]
mod test;
