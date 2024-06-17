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
use std::sync::{Arc, Mutex, Weak};

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

fn do_close_peer(pk: &PubKey, conn: &mut Conn, cooldown: std::time::Duration) {
    tracing::debug!(
        target: "NETAUDIT",
        pub_key = ?pk,
        cooldown_s = cooldown.as_secs_f64(),
        m = "sbd-e2e-crypto-client",
        a = "close_peer",
    );
    *conn = Conn::Cooldown(tokio::time::Instant::now() + cooldown);
}

impl Inner {
    pub async fn close(&mut self) {
        self.client.close().await;
    }

    pub fn close_peer(&mut self, pk: &PubKey) {
        if let Some(conn) = self.map.get_mut(pk) {
            do_close_peer(pk, conn, self.config.cooldown);
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
                    do_close_peer(pk, conn, config.cooldown);
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
                                do_close_peer(&pk, conn, config.cooldown);
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
                    do_close_peer(pk, conn, config.cooldown);
                    Err(err)
                } else {
                    Ok(())
                }
            }
        }
    }

    fn prune(config: &Config, map: &mut HashMap<PubKey, Conn>) {
        let now = tokio::time::Instant::now();

        map.retain(|pk, c| {
            if let Conn::Active { last_active, .. } = c {
                if now - *last_active > config.max_idle {
                    do_close_peer(pk, c, config.cooldown);
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
                    tracing::debug!(
                        target: "NETAUDIT",
                        pub_key = ?pk,
                        m = "sbd-e2e-crypto-client",
                        "cannot open: too many connections",
                    );
                    return Err(Error::other("too many connections"));
                }
                tracing::debug!(
                    target: "NETAUDIT",
                    pub_key = ?pk,
                    m = "sbd-e2e-crypto-client",
                    a = "open_peer",
                );
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

async fn close_inner(inner: &mut Option<Inner>) {
    if let Some(mut inner) = inner.take() {
        inner.close().await;
    }
}

/// Handle to receive data from the crypto connection.
pub struct MsgRecv {
    inner: Weak<tokio::sync::Mutex<Option<Inner>>>,
    recv: sbd_client::MsgRecv,
}

impl MsgRecv {
    /// Receive data from the crypto connection.
    pub async fn recv(&mut self) -> Option<(PubKey, Vec<u8>)> {
        loop {
            let raw_msg = match self.recv.recv().await {
                None => return None,
                Some(raw_msg) => raw_msg,
            };

            if let Some(inner) = self.inner.upgrade() {
                let mut lock = inner.lock().await;

                if let Some(inner) = &mut *lock {
                    match inner.recv(raw_msg).await {
                        Err(_) => (),
                        Ok(None) => continue,
                        Ok(Some(o)) => return Some(o),
                    }
                } else {
                    return None;
                }

                // the only code path leading out of the branches above
                // is the error one where we need to close the connection
                close_inner(&mut lock).await;
            } else {
                return None;
            }
        }
    }
}

/// An encrypted connection to peers through an Sbd server.
pub struct SbdClientCrypto {
    pub_key: PubKey,
    inner: Arc<tokio::sync::Mutex<Option<Inner>>>,
}

impl SbdClientCrypto {
    /// Establish a new connection.
    pub async fn new(
        url: &str,
        config: Arc<Config>,
    ) -> Result<(Self, MsgRecv)> {
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
        let inner = Arc::new(tokio::sync::Mutex::new(Some(Inner {
            config,
            crypto,
            client,
            map: HashMap::default(),
        })));
        let weak_inner = Arc::downgrade(&inner);
        Ok((
            Self { pub_key, inner },
            MsgRecv {
                inner: weak_inner,
                recv,
            },
        ))
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
            inner.close_peer(pk);
        }
    }

    /// Close the entire sbd client connection.
    pub async fn close(&self) {
        close_inner(&mut *self.inner.lock().await).await;
    }
}

#[cfg(test)]
mod test;
