//! `feature = "raw_client"` Raw websocket interaction types.

use crate::*;

/// Connection info for creating a raw websocket connection.
pub struct WsRawConnect {
    /// The full url including the pubkey path parameter.
    pub full_url: String,

    /// The maximum message size. If a message is larger than this
    /// the connection will be closed.
    pub max_message_size: usize,

    /// Setting this to `true` allows `ws://` scheme.
    pub allow_plain_text: bool,

    #[allow(unused_variables)]
    /// Setting this to `true` disables certificate verification on `wss://`
    /// scheme. WARNING: this is a dangerous configuration and should not
    /// be used outside of testing (i.e. self-signed tls certificates).
    pub danger_disable_certificate_check: bool,
}

impl WsRawConnect {
    /// Establish the websocket connection.
    pub async fn connect(self) -> Result<(WsRawSend, WsRawRecv)> {
        let Self {
            full_url,
            max_message_size,
            allow_plain_text,
            danger_disable_certificate_check,
        } = self;

        let scheme_ws = full_url.starts_with("ws://");
        let scheme_wss = full_url.starts_with("wss://");

        if !scheme_ws && !scheme_wss {
            return Err(Error::other("scheme must be ws:// or wss://"));
        }

        if !allow_plain_text && scheme_ws {
            return Err(Error::other("plain text scheme not allowed"));
        }

        let request = tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(full_url).map_err(Error::other)?;

        let host = match request.uri().host() {
            Some(host) => host.to_string(),
            None => return Err(Error::other("invalid url")),
        };
        let port = request.uri().port_u16().unwrap_or({
            if scheme_ws {
                80
            } else {
                443
            }
        });

        let tcp =
            tokio::net::TcpStream::connect(format!("{host}:{port}")).await?;

        let maybe_tls = if scheme_ws {
            tokio_tungstenite::MaybeTlsStream::Plain(tcp)
        } else {
            let tls = priv_system_tls(danger_disable_certificate_check);
            let name = host
                .try_into()
                .unwrap_or_else(|_| "sbd".try_into().unwrap());
            let tls = tokio_rustls::TlsConnector::from(tls)
                .connect(name, tcp)
                .await?;

            tokio_tungstenite::MaybeTlsStream::Rustls(tls)
        };

        let config =
            tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
                max_message_size: Some(max_message_size),
                ..Default::default()
            };

        let (ws, _res) = tokio_tungstenite::client_async_with_config(
            request,
            maybe_tls,
            Some(config),
        )
        .await
        .map_err(Error::other)?;

        let (send, recv) = futures::stream::StreamExt::split(ws);

        Ok((WsRawSend { send }, WsRawRecv { recv }))
    }
}

use tokio_tungstenite::tungstenite::protocol::Message;
type MaybeTls = tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>;
type Ws = tokio_tungstenite::WebSocketStream<MaybeTls>;
type WsSend = futures::stream::SplitSink<Ws, Message>;
type WsRecv = futures::stream::SplitStream<Ws>;

/// The send half of the websocket connection.
pub struct WsRawSend {
    send: WsSend,
}

impl WsRawSend {
    /// Send data over the websocket.
    pub async fn send(&mut self, msg: Vec<u8>) -> Result<()> {
        use futures::sink::SinkExt;
        self.send
            .send(tokio_tungstenite::tungstenite::protocol::Message::binary(
                msg,
            ))
            .await
            .map_err(Error::other)?;
        self.send.flush().await.map_err(Error::other)?;
        Ok(())
    }

    /// Close the connection.
    pub async fn close(&mut self) {
        use futures::sink::SinkExt;
        let _ = self.send.close().await;
    }
}

/// The receive half of the websocket connection.
pub struct WsRawRecv {
    recv: WsRecv,
}

impl WsRawRecv {
    /// Receive from the websocket.
    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        use futures::stream::StreamExt;
        use tokio_tungstenite::tungstenite::protocol::Message::*;
        loop {
            match self.recv.next().await {
                None => return Err(Error::other("closed")),
                Some(r) => {
                    let msg = r.map_err(Error::other)?;
                    match msg {
                        Text(s) => return Ok(s.into_bytes()),
                        Binary(v) => return Ok(v),
                        Ping(_) | Pong(_) => (),
                        Close(_) => return Err(Error::other("closed")),
                        Frame(_) => unreachable!(),
                    }
                }
            }
        }
    }
}

/// Process the standard sbd handshake from the client side.
pub struct Handshake {
    /// limit_byte_nanos.
    pub limit_byte_nanos: i32,

    /// limit_idle_millis.
    pub limit_idle_millis: i32,

    /// bytes sent.
    pub bytes_sent: usize,
}

impl Handshake {
    /// Process the standard sbd handshake from the client side.
    pub async fn handshake<C: Crypto>(
        send: &mut WsRawSend,
        recv: &mut WsRawRecv,
        crypto: &C,
    ) -> Result<Self> {
        let mut limit_byte_nanos = 8000;
        let mut limit_idle_millis = 10_000;
        let mut bytes_sent = 0;

        loop {
            match Msg(recv.recv().await?).parse()? {
                MsgType::Msg { .. } => {
                    return Err(Error::other("invalid handshake"))
                }
                MsgType::LimitByteNanos(l) => limit_byte_nanos = l,
                MsgType::LimitIdleMillis(l) => limit_idle_millis = l,
                MsgType::AuthReq(nonce) => {
                    let sig = crypto.sign(nonce);
                    let mut auth_res = Vec::with_capacity(32 + 64);
                    auth_res.extend_from_slice(CMD_PREFIX);
                    auth_res.extend_from_slice(b"ares");
                    auth_res.extend_from_slice(&sig);
                    send.send(auth_res).await?;
                    bytes_sent += 32 + 64;
                }
                MsgType::Ready => break,
                MsgType::Unknown => (),
            }
        }

        Ok(Self {
            limit_byte_nanos,
            limit_idle_millis,
            bytes_sent,
        })
    }
}

fn priv_system_tls(
    danger_disable_certificate_check: bool,
) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();

    #[cfg(not(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos"
    )))]
    {
        roots.add_server_trust_anchors(
            webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|a| {
                rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                    a.subject.to_vec(),
                    a.spki.to_vec(),
                    a.name_constraints.map(|c| c.to_vec()),
                )
            }),
        );
    }

    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos"
    ))]
    for cert in rustls_native_certs::load_native_certs()
        .expect("failed to load system tls certs")
    {
        roots.add(cert).expect("failed to add cert to root");
    }

    if danger_disable_certificate_check {
        let v = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .unwrap();

        Arc::new(
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(V(v)))
                .with_no_client_auth(),
        )
    } else {
        Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    }
}

#[derive(Debug)]
struct V(Arc<rustls::client::WebPkiServerVerifier>);

impl rustls::client::danger::ServerCertVerifier for V {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<
        rustls::client::danger::ServerCertVerified,
        rustls::Error,
    > {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<
        rustls::client::danger::HandshakeSignatureValid,
        rustls::Error,
    > {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<
        rustls::client::danger::HandshakeSignatureValid,
        rustls::Error,
    > {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}
