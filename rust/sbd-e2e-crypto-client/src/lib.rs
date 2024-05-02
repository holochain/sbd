//! Sbd end to end encryption client.
#![deny(missing_docs)]

// Mutex strategy in this file is built on the assumption that this will
// largely be network bound. Since we only have the one rate-limited connection
// to the sbd server, it is okay to wrap it with a tokio Mutex and do the
// encryption / decryption while that mutex is locked. Without this top-level
// locking it is much easier to send secretstream headers out of order,
// especially on the receiving new connection side when a naive implementation
// trying to be clever might not lock the send side correctly.

use std::collections::HashMap;
use std::io::{Error, Result};
use std::sync::{Arc, Mutex};

pub use sbd_client::PubKey;

mod sodoken_crypto;
pub use sodoken_crypto::*;

/// Configuration for setting up an SbdClientCrypto connection.
pub struct Config {
    /// If `true` we will accept incoming "connections", otherwise
    /// messages from nodes we didn't explicitly "connect" to will
    /// be ignored.
    pub listener: bool,

    /// If `true` we will allow connecting to insecure plaintext servers.
    pub allow_plain_text: bool,

    /// Cooldown time to prevent comms on "connection" close.
    pub cooldown: std::time::Duration,

    /// Max connection count.
    pub max_connections: usize,

    /// Max time without receiving before a connection is "closed".
    pub max_idle: std::time::Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listener: false,
            allow_plain_text: false,
            cooldown: std::time::Duration::from_secs(10),
            max_connections: 4096,
            max_idle: std::time::Duration::from_secs(10),
        }
    }
}

enum Conn {
    Cooldown(tokio::time::Instant),
    Active {
        last_active: tokio::time::Instant,
        enc: sodoken_crypto::Encryptor,
        dec: sodoken_crypto::Decryptor,
    },
}

struct Inner {
    config: Arc<Config>,
    crypto: sodoken_crypto::SodokenCrypto,
    client: sbd_client::SbdClient,
    map: HashMap<PubKey, Conn>,
}

impl Inner {
    pub async fn close(&mut self) {
        self.client.close().await;
    }

    pub async fn close_peer(&mut self, pk: &PubKey) {
        if let Some(conn) = self.map.get_mut(pk) {
            *conn = Conn::Cooldown(
                tokio::time::Instant::now() + self.config.cooldown,
            );
        }
    }

    pub async fn assert(&mut self, pk: &PubKey) -> Result<()> {
        let Self {
            config,
            crypto,
            client,
            map,
        } = self;

        let (conn, hdr) = Self::priv_assert_con(pk, config, crypto, map, true)?;

        match conn {
            Conn::Cooldown(_) => {
                Err(Error::other("connection still cooling down"))
            }
            Conn::Active { .. } => {
                if let Err(err) = async {
                    if let Some(hdr) = hdr {
                        client.send(pk, &hdr).await
                    } else {
                        Ok(())
                    }
                }
                .await
                {
                    *conn = Conn::Cooldown(
                        tokio::time::Instant::now() + config.cooldown,
                    );
                    Err(err)
                } else {
                    Ok(())
                }
            }
        }
    }

    pub async fn recv(
        &mut self,
        msg: sbd_client::Msg,
    ) -> Result<Option<(PubKey, Vec<u8>)>> {
        let Self {
            config,
            crypto,
            client,
            map,
        } = self;

        let pk = msg.pub_key();

        match Self::priv_assert_con(&pk, config, crypto, map, config.listener) {
            Err(_) => Ok(None),
            Ok((conn, hdr)) => {
                if let Some(hdr) = hdr {
                    client.send(&pk, &hdr).await?;
                }

                match conn {
                    Conn::Cooldown(_) => Ok(None),
                    Conn::Active {
                        last_active, dec, ..
                    } => {
                        *last_active = tokio::time::Instant::now();

                        match dec.decrypt(msg.message()) {
                            Err(_) => {
                                *conn = Conn::Cooldown(
                                    tokio::time::Instant::now()
                                        + config.cooldown,
                                );
                                Ok(None)
                            }
                            Ok(None) => Ok(None),
                            Ok(Some(msg)) => Ok(Some((pk, msg))),
                        }
                    }
                }
            }
        }
    }

    pub async fn send(&mut self, pk: &PubKey, msg: &[u8]) -> Result<()> {
        let Self {
            config,
            crypto,
            client,
            map,
        } = self;

        let (conn, hdr) = Self::priv_assert_con(pk, config, crypto, map, true)?;

        match conn {
            Conn::Cooldown(_) => {
                Err(Error::other("connection still cooling down"))
            }
            Conn::Active { enc, .. } => {
                if let Err(err) = async {
                    if let Some(hdr) = hdr {
                        client.send(pk, &hdr).await?;
                    }
                    let msg = enc.encrypt(msg)?;
                    client.send(pk, &msg).await
                }
                .await
                {
                    *conn = Conn::Cooldown(
                        tokio::time::Instant::now() + config.cooldown,
                    );
                    Err(err)
                } else {
                    Ok(())
                }
            }
        }
    }

    fn prune(config: &Config, map: &mut HashMap<PubKey, Conn>) {
        let now = tokio::time::Instant::now();

        map.retain(|_, c| {
            if let Conn::Active { last_active, .. } = c {
                if now - *last_active > config.max_idle {
                    *c = Conn::Cooldown(
                        tokio::time::Instant::now() + config.cooldown,
                    );
                }
            }

            if let Conn::Cooldown(at) = c {
                now < *at
            } else {
                true
            }
        })
    }

    fn priv_assert_con<'a>(
        pk: &PubKey,
        config: &Config,
        crypto: &sodoken_crypto::SodokenCrypto,
        map: &'a mut HashMap<PubKey, Conn>,
        do_create: bool,
    ) -> Result<(&'a mut Conn, Option<[u8; 24]>)> {
        use std::collections::hash_map::Entry;

        // TODO - more efficient to only prune if we need to
        //        but then, we'd need to manage expired cooldowns
        //        in-line, lest we keep denying connections
        //if map.len() >= config.max_connections {
        //    Self::prune(config, map);
        //}
        // instead, for now, we just always prune
        Self::prune(config, map);

        let len = map.len();

        match map.entry(pk.clone()) {
            Entry::Occupied(e) => Ok((e.into_mut(), None)),
            Entry::Vacant(e) => {
                if !do_create {
                    return Err(Error::other("ignore"));
                }
                if len >= config.max_connections {
                    return Err(Error::other("too many connections"));
                }
                let (enc, hdr, dec) = crypto.new_enc(pk)?;
                Ok((
                    e.insert(Conn::Active {
                        last_active: tokio::time::Instant::now(),
                        enc,
                        dec,
                    }),
                    Some(hdr),
                ))
            }
        }
    }
}

/// An encrypted connection to peers through an Sbd server.
pub struct SbdClientCrypto {
    pub_key: PubKey,
    inner: tokio::sync::Mutex<Option<Inner>>,
    recv: tokio::sync::Mutex<sbd_client::MsgRecv>,
}

impl SbdClientCrypto {
    /// Establish a new connection.
    pub async fn new(url: &str, config: Arc<Config>) -> Result<Self> {
        let client_config = sbd_client::SbdClientConfig {
            allow_plain_text: config.allow_plain_text,
            ..Default::default()
        };
        let crypto = sodoken_crypto::SodokenCrypto::new()?;
        use sbd_client::Crypto;
        let pub_key = PubKey(Arc::new(*crypto.pub_key()));
        let (client, recv) =
            sbd_client::SbdClient::connect_config(url, &crypto, client_config)
                .await?;
        let inner = tokio::sync::Mutex::new(Some(Inner {
            config,
            crypto,
            client,
            map: HashMap::default(),
        }));
        let recv = tokio::sync::Mutex::new(recv);
        Ok(Self {
            pub_key,
            inner,
            recv,
        })
    }

    /// Get the public key of this node.
    pub fn pub_key(&self) -> &PubKey {
        &self.pub_key
    }

    /// Assert that we are connected to a peer without sending any data.
    pub async fn assert(&self, pk: &PubKey) -> Result<()> {
        let mut lock = self.inner.lock().await;
        if let Some(inner) = &mut *lock {
            inner.assert(pk).await
        } else {
            Err(Error::other("closed"))
        }
    }

    /// Receive a message from a peer.
    pub async fn recv(&self) -> Option<(PubKey, Vec<u8>)> {
        loop {
            // hold this lock the whole time incase some other task
            // is also invoking recv.
            let mut recv_lock = self.recv.lock().await;

            let raw_msg = match recv_lock.recv().await {
                None => {
                    self.close().await;
                    return None;
                }
                Some(raw_msg) => raw_msg,
            };

            if let Some(inner) = &mut *self.inner.lock().await {
                match inner.recv(raw_msg).await {
                    Err(_) => {
                        self.close().await;
                        return None;
                    }
                    Ok(None) => continue,
                    Ok(Some(o)) => return Some(o),
                }
            } else {
                self.close().await;
                return None;
            }
        }
    }

    /// Send a message to a peer.
    pub async fn send(&self, pk: &PubKey, msg: &[u8]) -> Result<()> {
        const SBD_MAX: usize = 20_000;
        const SBD_HDR: usize = 32;
        const SS_ABYTES: usize = sodoken::secretstream::ABYTES;
        const MAX_MSG: usize = SBD_MAX - SBD_HDR - SS_ABYTES;

        if msg.len() > MAX_MSG {
            return Err(Error::other("message too long"));
        }

        let mut lock = self.inner.lock().await;
        if let Some(inner) = &mut *lock {
            inner.send(pk, msg).await
        } else {
            Err(Error::other("closed"))
        }
    }

    /// Close a connection to a specific peer.
    pub async fn close_peer(&self, pk: &PubKey) {
        if let Some(inner) = self.inner.lock().await.as_mut() {
            inner.close_peer(pk).await;
        }
    }

    /// Close the entire sbd client connection.
    pub async fn close(&self) {
        if let Some(mut inner) = self.inner.lock().await.take() {
            inner.close().await;
        }
    }
}

#[cfg(test)]
mod test;
