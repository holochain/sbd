#![deny(missing_docs)]
//! Sbd end to end encryption client.
//!
//! See the [protocol] module documentation for spec details.

use std::collections::HashMap;
use std::io::{Error, Result};
use std::sync::{Arc, Mutex, Weak};

pub use sbd_client::{PubKey, SbdClientConfig};

pub mod protocol;

mod sodoken_crypto;
pub use sodoken_crypto::*;

/// Configuration for setting up an SbdClientCrypto connection.
pub struct Config {
    /// Config required for the sbd client itself.
    pub client_config: sbd_client::SbdClientConfig,

    /// If `true` we will accept incoming "connections", otherwise
    /// messages from nodes we didn't explicitly "connect" to will
    /// be ignored.
    pub listener: bool,

    /// Max connection count.
    pub max_connections: usize,

    /// Max time without receiving before a connection is "closed".
    pub max_idle: std::time::Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            client_config: Default::default(),
            listener: false,
            max_connections: 4096,
            max_idle: std::time::Duration::from_secs(10),
        }
    }
}

// tokio mutex required to ensure ordering on new stream messages.
// We can't send in parallel over the same sub-client anyways.
type ClientSync = tokio::sync::Mutex<sbd_client::SbdClient>;

/// Handle to receive data from the crypto connection.
pub struct MsgRecv {
    inner: Arc<Mutex<Inner>>,
    recv: sbd_client::MsgRecv,
    client: Weak<ClientSync>,
}

impl MsgRecv {
    /// Receive data from the crypto connection.
    pub async fn recv(&mut self) -> Option<(PubKey, bytes::Bytes)> {
        while let Some(msg) = self.recv.recv().await {
            let pk = msg.pub_key();
            let dec = self.inner.lock().unwrap().dec(msg);
            match dec {
                DecRes::Ok(msg) => return Some((pk, msg)),
                DecRes::Ignore => (),
                DecRes::ReqNewStream => {
                    // error decoding, we need to request a new stream
                    if let Some(client) = self.client.upgrade() {
                        let msg =
                            protocol::Protocol::request_new_stream(&*pk.0);
                        if let Err(err) =
                            client.lock().await.send(&pk, msg.base_msg()).await
                        {
                            tracing::debug!(?err, "failure sending request_new_stream in message receive handler");
                        }
                    } else {
                        return None;
                    }
                }
            }
        }
        None
    }
}

/// An encrypted connection to peers through an Sbd server.
pub struct SbdClientCrypto {
    pub_key: PubKey,
    inner: Arc<Mutex<Inner>>,
    client: Arc<ClientSync>,
}

impl SbdClientCrypto {
    /// Establish a new connection.
    pub async fn new(
        url: &str,
        config: Arc<Config>,
    ) -> Result<(Self, MsgRecv)> {
        // establish crypto
        let crypto = sodoken_crypto::SodokenCrypto::new()?;
        use sbd_client::Crypto;
        let pub_key = PubKey(Arc::new(*crypto.pub_key()));

        // open a new connection
        let (client, recv) = sbd_client::SbdClient::connect_config(
            url,
            &crypto,
            config.client_config.clone(),
        )
        .await?;

        let client = Arc::new(tokio::sync::Mutex::new(client));
        let inner = Arc::new(Mutex::new(Inner::new(config, crypto)));

        let recv = MsgRecv {
            inner: inner.clone(),
            recv,
            client: Arc::downgrade(&client),
        };

        let this = Self {
            pub_key,
            inner,
            client,
        };

        Ok((this, recv))
    }

    /// Get the public key of this node.
    pub fn pub_key(&self) -> &PubKey {
        &self.pub_key
    }

    /// Get the current active "connected" peers.
    pub fn active_peers(&self) -> Vec<PubKey> {
        let mut inner = self.inner.lock().unwrap();
        let max_idle = inner.config.max_idle;
        Inner::prune(&mut inner.c_map, max_idle);
        inner.c_map.keys().cloned().collect()
    }

    /// Assert that we are connected to a peer without sending any data.
    pub async fn assert(&self, pk: &PubKey) -> Result<()> {
        let enc = self.inner.lock().unwrap().enc(pk, None)?;

        {
            let client = self.client.lock().await;
            for enc in enc {
                client.send(pk, &enc).await?;
            }
        }

        Ok(())
    }

    /// Send a message to a peer.
    pub async fn send(&self, pk: &PubKey, msg: &[u8]) -> Result<()> {
        const SBD_MAX: usize = 20_000;
        const SBD_HDR: usize = 32;
        // This is the internal "secretstream" header for distinguishing
        // stream starts and messages, etc.
        const SBD_SS_HDR: usize = 1;
        const SS_ABYTES: usize = sodoken::secretstream::ABYTES;
        const MAX_MSG: usize = SBD_MAX - SBD_HDR - SBD_SS_HDR - SS_ABYTES;

        if msg.len() > MAX_MSG {
            return Err(Error::other("message too long"));
        }

        // get or create an encryptor, returns a list of messages to send
        let enc = self.inner.lock().unwrap().enc(pk, Some(msg))?;

        {
            let client = self.client.lock().await;

            // send the encrypted messages to send
            for enc in enc {
                client.send(pk, &enc).await?;
            }
        }

        Ok(())
    }

    /// Close a connection to a specific peer.
    pub async fn close_peer(&self, pk: &PubKey) {
        self.inner.lock().unwrap().close(pk);
    }

    /// Close the entire sbd client connection.
    pub async fn close(&self) {
        self.client.lock().await.close().await;
    }
}

enum DecRes {
    Ok(bytes::Bytes),
    Ignore,
    ReqNewStream,
}

struct InnerRec {
    enc: Option<Encryptor>,
    dec: Option<Decryptor>,
    last_active: std::time::Instant,
}

impl InnerRec {
    pub fn new() -> Self {
        Self {
            enc: None,
            dec: None,
            last_active: std::time::Instant::now(),
        }
    }
}

struct Inner {
    config: Arc<Config>,
    crypto: SodokenCrypto,
    c_map: HashMap<PubKey, InnerRec>,
}

impl Inner {
    /// Construct a new inner cryto client state.
    fn new(config: Arc<Config>, crypto: SodokenCrypto) -> Self {
        Self {
            config,
            crypto,
            c_map: HashMap::new(),
        }
    }

    /// Drop inner crypto client state for a particular peer.
    fn close(&mut self, pk: &PubKey) {
        self.c_map.remove(pk);
    }

    /// Prune any internal crypto client state info that has idle expired.
    fn prune(
        c_map: &mut HashMap<PubKey, InnerRec>,
        max_idle: std::time::Duration,
    ) {
        let now = std::time::Instant::now();
        c_map.retain(|_pk, r| now - r.last_active < max_idle);
    }

    /// Assert inner crypto client state exists for a particular peer.
    fn loc_assert<'a>(
        config: &'a Config,
        c_map: &'a mut HashMap<PubKey, InnerRec>,
        pk: PubKey,
        do_create: bool,
    ) -> Result<&'a mut InnerRec> {
        use std::collections::hash_map::Entry;
        let tot = c_map.len();
        Self::prune(c_map, config.max_idle);
        match c_map.entry(pk.clone()) {
            Entry::Vacant(e) => {
                if do_create {
                    if tot >= config.max_connections {
                        return Err(Error::other("too many connections"));
                    }
                    Ok(e.insert(InnerRec::new()))
                } else {
                    Err(Error::other("ignore unsolicited"))
                }
            }
            Entry::Occupied(e) => Ok(e.into_mut()),
        }
    }

    /// Get or create an encryptor for a particular peer,
    /// optionally encrypting a message. Note, even if you
    /// don't pass a message, calling this may generate
    /// crypto handshake data to be sent.
    fn enc(
        &mut self,
        pk: &PubKey,
        msg: Option<&[u8]>,
    ) -> Result<Vec<bytes::Bytes>> {
        let Self {
            config,
            crypto,
            c_map,
        } = self;

        let mut out = Vec::new();

        // assert we have a record for the pubkey
        let rec = Self::loc_assert(config, c_map, pk.clone(), true)?;
        rec.last_active = std::time::Instant::now();

        // assert we have an Encryptor, adding header to output as needed
        if rec.enc.is_none() {
            let (enc, hdr) = crypto.new_enc(pk)?;
            rec.enc = Some(enc);
            let msg = protocol::Protocol::new_stream(&**pk, &hdr);

            // push handshake message
            out.push(msg.base_msg().clone());
        }

        if let Some(msg) = msg {
            // encrypt our message
            let msg = rec.enc.as_mut().unwrap().encrypt(&*pk.0, msg)?;

            out.push(msg.base_msg().clone());
        }

        Ok(out)
    }

    /// Get or create a decryptor for a given peer, and
    /// process an incoming message.
    fn dec(&mut self, msg: sbd_client::Msg) -> DecRes {
        let Self {
            config,
            crypto,
            c_map,
        } = self;

        // ensure inner crypto state exists for the peer
        let rec = match Self::loc_assert(
            config,
            c_map,
            msg.pub_key(),
            config.listener,
        ) {
            Ok(rec) => rec,
            Err(_) => {
                // too many connections, or unsolicited... ignore this message
                return DecRes::Ignore;
            }
        };

        // update idle tracking
        rec.last_active = std::time::Instant::now();

        // decode the message
        let dec = match protocol::Protocol::from_full(
            bytes::Bytes::copy_from_slice(&msg.0),
        ) {
            Some(dec) => dec,
            None => {
                rec.dec = None;
                // cannot decode, request a new stream
                // MAYBE track these too so we ban bad actors?
                return DecRes::ReqNewStream;
            }
        };

        // process the decoded message
        match dec {
            protocol::Protocol::NewStream { header, .. } => {
                // peer instructs us to start a new decryption stream
                let dec =
                    match crypto.new_dec(msg.pub_key_ref(), header.as_ref()) {
                        Ok(dec) => dec,
                        Err(_) => return DecRes::ReqNewStream,
                    };
                rec.dec = Some(dec);
                DecRes::Ignore
            }
            protocol::Protocol::Message { message, .. } => {
                // we got a message, forward to receiver
                match rec.dec.as_mut() {
                    Some(dec) => match dec.decrypt(message.as_ref()) {
                        Ok(message) => DecRes::Ok(message),
                        Err(_) => DecRes::ReqNewStream,
                    },
                    None => {
                        // we don't want to entertain peers that don't
                        // properly send us a new stream first
                        DecRes::Ignore
                    }
                }
            }
            protocol::Protocol::RequestNewStream { .. } => {
                // peer wants us to establish a new encryption stream
                rec.enc = None;
                DecRes::Ignore
            }
        }
    }
}

#[cfg(test)]
mod test;
