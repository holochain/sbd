//! Sbd client library.
#![deny(missing_docs)]

use std::io::{Error, Result};
use std::sync::Arc;

/// defined by the sbd spec
const MAX_MSG_SIZE: usize = 20_000;

/// defined by ed25519 spec
const PK_SIZE: usize = 32;

/// defined by ed25519 spec
const SIG_SIZE: usize = 64;

/// sbd spec defines headers to be the same size as ed25519 pub keys
const HDR_SIZE: usize = PK_SIZE;

/// defined by sbd spec
const NONCE_SIZE: usize = 32;

/// defined by sbd spec
const CMD_PREFIX: &[u8; 28] = &[0; 28];

const F_LIMIT_BYTE_NANOS: &[u8] = b"lbrt";
const F_LIMIT_IDLE_MILLIS: &[u8] = b"lidl";
const F_AUTH_REQ: &[u8] = b"areq";
const F_READY: &[u8] = b"srdy";

#[cfg(feature = "raw_client")]
pub mod raw_client;
#[cfg(not(feature = "raw_client"))]
mod raw_client;

mod send_buf;

/// Crypto to use. Note, the pair should be fresh for each new connection.
pub trait Crypto {
    /// The pubkey.
    fn pub_key(&self) -> &[u8; PK_SIZE];

    /// Sign the nonce.
    fn sign(&self, nonce: &[u8]) -> Result<[u8; SIG_SIZE]>;
}

#[cfg(feature = "crypto")]
mod default_crypto {
    use super::*;

    /// Default signer. Use a fresh one for every new connection.
    pub struct DefaultCrypto([u8; PK_SIZE], ed25519_dalek::SigningKey);

    impl Default for DefaultCrypto {
        fn default() -> Self {
            loop {
                let k = ed25519_dalek::SigningKey::generate(
                    &mut rand::thread_rng(),
                );
                let pk = k.verifying_key().to_bytes();
                if &pk[..28] == CMD_PREFIX {
                    continue;
                } else {
                    return Self(pk, k);
                }
            }
        }
    }

    impl super::Crypto for DefaultCrypto {
        fn pub_key(&self) -> &[u8; PK_SIZE] {
            &self.0
        }

        fn sign(&self, nonce: &[u8]) -> std::io::Result<[u8; SIG_SIZE]> {
            use ed25519_dalek::Signer;
            Ok(self.1.sign(nonce).to_bytes())
        }
    }
}
#[cfg(feature = "crypto")]
pub use default_crypto::*;

/// Public key.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PubKey(pub Arc<[u8; PK_SIZE]>);

impl std::ops::Deref for PubKey {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Debug for PubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use base64::Engine;
        let out = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(&self.0[..]);
        f.write_str(&out)
    }
}

enum MsgType<'t> {
    Msg {
        #[allow(dead_code)]
        pub_key: &'t [u8],
        #[allow(dead_code)]
        message: &'t [u8],
    },
    LimitByteNanos(i32),
    LimitIdleMillis(i32),
    AuthReq(&'t [u8]),
    Ready,
    Unknown,
}

/// A message received from a remote.
/// This is just a single buffer. The first 32 bytes are the public key
/// of the sender, or 28 `0`s followed by a 4 byte command. Any remaining bytes are the message. The buffer
/// contained in this type is guaranteed to be at least 32 bytes long.
pub struct Msg(pub Vec<u8>);

impl Msg {
    /// Get a reference to the slice containing the pubkey data.
    pub fn pub_key_ref(&self) -> &[u8] {
        &self.0[..PK_SIZE]
    }

    /// Extract a pubkey from the message.
    pub fn pub_key(&self) -> PubKey {
        PubKey(Arc::new(self.0[..PK_SIZE].try_into().unwrap()))
    }

    /// Get a reference to the slice containing the message data.
    pub fn message(&self) -> &[u8] {
        &self.0[PK_SIZE..]
    }

    // -- private -- //

    fn parse(&self) -> Result<MsgType<'_>> {
        if self.0.len() < PK_SIZE {
            return Err(Error::other("invalid message length"));
        }
        if &self.0[..28] == CMD_PREFIX {
            match &self.0[28..HDR_SIZE] {
                F_LIMIT_BYTE_NANOS => {
                    if self.0.len() != HDR_SIZE + 4 {
                        return Err(Error::other("invalid lbrt length"));
                    }
                    Ok(MsgType::LimitByteNanos(i32::from_be_bytes(
                        self.0[PK_SIZE..].try_into().unwrap(),
                    )))
                }
                F_LIMIT_IDLE_MILLIS => {
                    if self.0.len() != HDR_SIZE + 4 {
                        return Err(Error::other("invalid lidl length"));
                    }
                    Ok(MsgType::LimitIdleMillis(i32::from_be_bytes(
                        self.0[HDR_SIZE..].try_into().unwrap(),
                    )))
                }
                F_AUTH_REQ => {
                    if self.0.len() != HDR_SIZE + NONCE_SIZE {
                        return Err(Error::other("invalid areq length"));
                    }
                    Ok(MsgType::AuthReq(&self.0[HDR_SIZE..]))
                }
                F_READY => Ok(MsgType::Ready),
                _ => Ok(MsgType::Unknown),
            }
        } else {
            Ok(MsgType::Msg {
                pub_key: &self.0[..PK_SIZE],
                message: &self.0[PK_SIZE..],
            })
        }
    }
}

/// Handle to receive data from the sbd connection.
pub struct MsgRecv(tokio::sync::mpsc::Receiver<Msg>);

impl MsgRecv {
    /// Receive data from the sbd connection.
    pub async fn recv(&mut self) -> Option<Msg> {
        self.0.recv().await
    }
}

/// Configuration for connecting an SbdClient.
#[derive(Clone)]
pub struct SbdClientConfig {
    /// Outgoing message buffer size.
    pub out_buffer_size: usize,

    /// Setting this to `true` allows `ws://` scheme.
    pub allow_plain_text: bool,

    /// Setting this to `true` disables certificate verification on `wss://`
    /// scheme. WARNING: this is a dangerous configuration and should not
    /// be used outside of testing (i.e. self-signed tls certificates).
    pub danger_disable_certificate_check: bool,

    /// Set any custom http headers to send with the websocket connect.
    pub headers: Vec<(String, String)>,

    /// If you must pass authentication material to the sbd server,
    /// specify it here.
    pub auth_material: Option<Vec<u8>>,
}

impl Default for SbdClientConfig {
    fn default() -> Self {
        Self {
            out_buffer_size: MAX_MSG_SIZE * 8,
            allow_plain_text: false,
            danger_disable_certificate_check: false,
            headers: Vec::new(),
            auth_material: None,
        }
    }
}

/// SbdClient represents a single connection to a single sbd server
/// through which we can communicate with any number of peers on that server.
pub struct SbdClient {
    url: String,
    pub_key: PubKey,
    send_buf: Arc<tokio::sync::Mutex<send_buf::SendBuf>>,
    read_task: tokio::task::JoinHandle<()>,
    write_task: tokio::task::JoinHandle<()>,
}

impl Drop for SbdClient {
    fn drop(&mut self) {
        self.read_task.abort();
        self.write_task.abort();
    }
}

impl SbdClient {
    /// Connect to the remote sbd server.
    pub async fn connect<C: Crypto>(
        url: &str,
        crypto: &C,
    ) -> Result<(Self, MsgRecv)> {
        Self::connect_config(url, crypto, SbdClientConfig::default()).await
    }

    /// Connect to the remote sbd server.
    pub async fn connect_config<C: Crypto>(
        url: &str,
        crypto: &C,
        config: SbdClientConfig,
    ) -> Result<(Self, MsgRecv)> {
        use base64::Engine;
        let full_url = format!(
            "{url}/{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(crypto.pub_key())
        );

        // establish a "raw" low-level websocket connection to the server
        let (mut send, mut recv) = raw_client::WsRawConnect {
            full_url: full_url.clone(),
            max_message_size: MAX_MSG_SIZE,
            allow_plain_text: config.allow_plain_text,
            danger_disable_certificate_check: config
                .danger_disable_certificate_check,
            headers: config.headers,
            auth_material: config.auth_material,
            alter_token_cb: None,
        }
        .connect()
        .await?;

        // performing the initial handshake authenticates us as a client
        // and returns some server configuration values
        let raw_client::Handshake {
            limit_byte_nanos,
            limit_idle_millis,
            bytes_sent,
        } = raw_client::Handshake::handshake(&mut send, &mut recv, crypto)
            .await?;

        // SendBuf helps us track rate-limiting so we don't ban ourselves
        let send_buf = send_buf::SendBuf::new(
            full_url.clone(),
            send,
            config.out_buffer_size,
            (limit_byte_nanos as f64 * 1.1) as u64,
            std::time::Duration::from_millis((limit_idle_millis / 2) as u64),
            bytes_sent,
        );
        let send_buf = Arc::new(tokio::sync::Mutex::new(send_buf));

        // spawn the read task that reads from the websocket connection
        let send_buf2 = send_buf.clone();
        let (recv_send, recv_recv) = tokio::sync::mpsc::channel(4);
        let read_task = tokio::task::spawn(async move {
            while let Ok(data) = recv.recv().await {
                let data = Msg(data);

                match match data.parse() {
                    Ok(data) => data,
                    Err(_) => break,
                } {
                    MsgType::Msg { .. } => {
                        // we got a message from someone, forward to user
                        if recv_send.send(data).await.is_err() {
                            break;
                        }
                    }
                    MsgType::LimitByteNanos(rate) => {
                        // the server is reconfiguring the ratelimiting
                        send_buf2
                            .lock()
                            .await
                            .new_rate_limit((rate as f64 * 1.1) as u64);
                    }
                    // idle messages should not be sent at this stage
                    MsgType::LimitIdleMillis(_) => break,
                    // authorization requests should not be sent at this stage
                    MsgType::AuthReq(_) => break,
                    // we can safely ignore late readys
                    MsgType::Ready => (),
                    // ignore all protocol messages we don't understand
                    MsgType::Unknown => (),
                }
            }

            send_buf2.lock().await.close().await;
        });

        // spawn the write task that sends data respecting rate limits
        let send_buf2 = send_buf.clone();
        let write_task = tokio::task::spawn(async move {
            loop {
                // if we know we have to wait, do that wait
                if let Some(dur) = send_buf2.lock().await.next_step_dur() {
                    tokio::time::sleep(dur).await;
                }

                match send_buf2.lock().await.write_next_queued().await {
                    Err(_) => break,
                    // send_buf was able to send something, loop again
                    Ok(true) => (),
                    // send_buf failed to do anything, we need a short
                    // delay before we try looping again to avoid a busy wait
                    Ok(false) => {
                        tokio::time::sleep(std::time::Duration::from_millis(
                            10,
                        ))
                        .await;
                    }
                }
            }

            send_buf2.lock().await.close().await;
        });

        let pub_key = PubKey(Arc::new(*crypto.pub_key()));

        let this = Self {
            url: full_url,
            pub_key,
            send_buf,
            read_task,
            write_task,
        };

        Ok((this, MsgRecv(recv_recv)))
    }

    /// The full url of this client.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The pub key of this client.
    pub fn pub_key(&self) -> &PubKey {
        &self.pub_key
    }

    /// Close the connection.
    pub async fn close(&self) {
        self.send_buf.lock().await.close().await;
    }

    /// Send a message to a peer.
    pub async fn send(&self, peer: &PubKey, data: &[u8]) -> Result<()> {
        self.send_buf.lock().await.send(peer, data).await
    }
}

#[cfg(test)]
mod test;
