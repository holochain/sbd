//! Sbd client library.
#![deny(missing_docs)]

use std::io::{Error, Result};
use std::sync::Arc;

/// defined by the sbd spec
const MAX_MSG_SIZE: usize = 16000;

#[cfg(feature = "raw_client")]
pub mod raw_client;
#[cfg(not(feature = "raw_client"))]
mod raw_client;

mod send_buf;

/// Crypto to use. Note, the pair should be fresh for each new connection.
pub trait Crypto {
    /// The pubkey.
    fn pub_key(&self) -> &[u8; 32];

    /// Sign the nonce.
    fn sign(&self, nonce: &[u8; 32]) -> [u8; 64];
}

#[cfg(feature = "crypto")]
mod default_crypto {
    /// Default signer. Use a fresh one for every new connection.
    pub struct DefaultCrypto([u8; 32], ed25519_dalek::SigningKey);

    impl Default for DefaultCrypto {
        fn default() -> Self {
            let k =
                ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
            let pk = k.verifying_key().to_bytes();
            Self(pk, k)
        }
    }

    impl super::Crypto for DefaultCrypto {
        fn pub_key(&self) -> &[u8; 32] {
            &self.0
        }

        fn sign(&self, nonce: &[u8; 32]) -> [u8; 64] {
            use ed25519_dalek::Signer;
            self.1.sign(&nonce[..]).to_bytes()
        }
    }
}
#[cfg(feature = "crypto")]
pub use default_crypto::*;

/// Public key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PubKey(pub [u8; 32]);

impl std::fmt::Debug for PubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use base64::Engine;
        let out = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(&self.0[..]);
        f.write_str(&out)
    }
}

/// A message received from a remote.
/// This is just a single buffer. The first 32 bytes are the public key
/// of the sender. Any remaining bytes are the message. The buffer
/// contained in this type is guaranteed to be at least 32 bytes long.
pub struct Msg(pub Vec<u8>);

impl Msg {
    /// Get a reference to the slice containing the pubkey data.
    pub fn pub_key_ref(&self) -> &[u8] {
        &self.0[..32]
    }

    /// Extract a pubkey from the message.
    pub fn pub_key(&self) -> PubKey {
        PubKey(self.0[..32].try_into().unwrap())
    }

    /// Get a reference to the slice containing the message data.
    pub fn message(&self) -> &[u8] {
        &self.0[32..]
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
#[derive(Clone, Copy)]
pub struct SbdClientConfig {
    /// Outgoing message buffer size.
    pub out_buffer_size: usize,

    /// Setting this to `true` allows `ws://` scheme.
    pub allow_plain_text: bool,

    /// Setting this to `true` disables certificate verification on `wss://`
    /// scheme. WARNING: this is a dangerous configuration and should not
    /// be used outside of testing (i.e. self-signed tls certificates).
    pub danger_disable_certificate_check: bool,
}

impl Default for SbdClientConfig {
    fn default() -> Self {
        Self {
            out_buffer_size: MAX_MSG_SIZE * 8,
            allow_plain_text: false,
            danger_disable_certificate_check: false,
        }
    }
}

/// SbdClient represents a single connection to a single sbd server
/// through which we can communicate with any number of peers on that server.
pub struct SbdClient {
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
    ) -> Result<(Self, String, PubKey, MsgRecv)> {
        Self::connect_config(url, crypto, SbdClientConfig::default()).await
    }

    /// Connect to the remote sbd server.
    pub async fn connect_config<C: Crypto>(
        url: &str,
        crypto: &C,
        config: SbdClientConfig,
    ) -> Result<(Self, String, PubKey, MsgRecv)> {
        use base64::Engine;
        let full_url = format!(
            "{url}/{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(crypto.pub_key())
        );

        let (mut send, mut recv) = raw_client::WsRawConnect {
            full_url: full_url.clone(),
            max_message_size: MAX_MSG_SIZE,
            allow_plain_text: config.allow_plain_text,
            danger_disable_certificate_check: config
                .danger_disable_certificate_check,
        }
        .connect()
        .await?;

        let handshake = recv.recv().await?;
        if handshake.len() != 4 + 4 + 32 {
            return Err(Error::other("invalid handshake"));
        }

        let limit_rate = i32::from_be_bytes([
            handshake[4],
            handshake[5],
            handshake[6],
            handshake[7],
        ]);

        println!("rate: {limit_rate}");

        let mut nonce = [0; 32];
        nonce.copy_from_slice(&handshake[8..]);

        let sig = crypto.sign(&nonce);

        send.send(sig.to_vec()).await?;

        let (recv_send, recv_recv) = tokio::sync::mpsc::channel(4);
        let read_task = tokio::task::spawn(async move {
            while let Ok(data) = recv.recv().await {
                if data.len() < 32 {
                    break;
                }

                if &data[..32] == &[0; 32] {
                    break;
                }

                if recv_send.send(Msg(data)).await.is_err() {
                    break;
                }
            }

            // TODO - shutdown
        });

        let send_buf = send_buf::SendBuf {
            ws: send,
            buf: std::collections::VecDeque::new(),
            out_buffer_size: config.out_buffer_size,
            origin: tokio::time::Instant::now(),
            limit_rate: (limit_rate as f64 * 0.9) as u64,
            next_send_at: 0,
        };
        let send_buf = Arc::new(tokio::sync::Mutex::new(send_buf));

        let send_buf2 = send_buf.clone();
        let write_task = tokio::task::spawn(async move {
            loop {
                if let Some(dur) = send_buf2.lock().await.next_step_dur() {
                    tokio::time::sleep(dur).await;
                }
                match send_buf2.lock().await.write_next_queued().await {
                    Err(_) => break,
                    Ok(true) => (),
                    Ok(false) => {
                        tokio::time::sleep(std::time::Duration::from_millis(
                            10,
                        ))
                        .await;
                    }
                }
            }

            // TODO - shutdown
        });

        let this = Self {
            send_buf,
            read_task,
            write_task,
        };

        Ok((
            this,
            full_url,
            PubKey(*crypto.pub_key()),
            MsgRecv(recv_recv),
        ))
    }

    /// Send a message to a peer.
    pub async fn send(&self, peer: &PubKey, data: &[u8]) -> Result<()> {
        self.send_buf.lock().await.send(peer, data).await
    }
}
