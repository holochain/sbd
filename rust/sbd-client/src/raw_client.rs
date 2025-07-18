//! `feature = "raw_client"` Raw websocket interaction types.

use crate::*;

/// Alter token callback function signature.
pub type AlterTokenCb =
    Arc<dyn Fn(Arc<str>) -> Arc<str> + 'static + Send + Sync>;

/// Connection info for creating a raw websocket connection.
pub struct WsRawConnect {
    /// The full url including the pubkey path parameter.
    pub full_url: String,

    /// The maximum message size. If a message is larger than this
    /// the connection will be closed.
    pub max_message_size: usize,

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

    /// This is mostly a test api, but since we need to use it outside
    /// this crate, it is available for anyone using the "raw_client" feature.
    /// Allows altering the token post-receive so we can send bad ones.
    pub alter_token_cb: Option<AlterTokenCb>,
}

impl WsRawConnect {
    /// Establish the websocket connection.
    pub async fn connect(self) -> Result<(WsRawSend, WsRawRecv)> {
        let Self {
            full_url,
            max_message_size,
            allow_plain_text,
            danger_disable_certificate_check,
            headers,
            auth_material,
            alter_token_cb,
        } = self;

        // convert the url into a request
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let mut request =
            IntoClientRequest::into_client_request(full_url.clone())
                .map_err(Error::other)?;

        // set any headers we are configured with
        for (k, v) in headers {
            use tokio_tungstenite::tungstenite::http::header::*;
            let k =
                HeaderName::from_bytes(k.as_bytes()).map_err(Error::other)?;
            let v =
                HeaderValue::from_bytes(v.as_bytes()).map_err(Error::other)?;
            request.headers_mut().insert(k, v);
        }

        // if we have auth_material, we need to authenticate
        if let Some(auth_material) = auth_material {
            // figure out the authenticate endpoint url
            let mut auth_url =
                url::Url::parse(&full_url).map_err(Error::other)?;
            auth_url.set_path("/authenticate");
            match auth_url.scheme() {
                "ws" => {
                    let _ = auth_url.set_scheme("http");
                }
                "wss" => {
                    let _ = auth_url.set_scheme("https");
                }
                _ => (),
            }

            // request a token from the /authenticate endpoint
            let token = tokio::task::spawn_blocking(move || {
                ureq::put(auth_url.as_str())
                    .send(&auth_material[..])
                    .map_err(Error::other)?
                    .into_body()
                    .read_to_string()
                    .map_err(Error::other)
            })
            .await??;

            // parse out the token
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Token {
                auth_token: Arc<str>,
            }

            let token: Token =
                serde_json::from_str(&token).map_err(Error::other)?;
            let token = token.auth_token;

            let token = if let Some(cb) = alter_token_cb {
                // hook to allow token alterations
                cb(token)
            } else {
                token
            };

            // finally add our token to the request headers
            use tokio_tungstenite::tungstenite::http::header::*;
            let v =
                HeaderValue::from_bytes(format!("Bearer {token}").as_bytes())
                    .map_err(Error::other)?;
            request.headers_mut().insert("Authorization", v);
        };

        let scheme_ws = request.uri().scheme_str() == Some("ws");
        let scheme_wss = request.uri().scheme_str() == Some("wss");

        if !scheme_ws && !scheme_wss {
            return Err(Error::other("scheme must be ws:// or wss://"));
        }

        if !allow_plain_text && scheme_ws {
            return Err(Error::other("plain text scheme not allowed"));
        }

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

        // open the tcp connection
        let tcp =
            tokio::net::TcpStream::connect(format!("{host}:{port}")).await?;

        // optionally layer on TLS
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

        // set some default websocket config
        let config =
            tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default(
            )
            .max_message_size(Some(max_message_size));

        // establish the connection
        let (ws, _res) = tokio_tungstenite::client_async_with_config(
            request,
            maybe_tls,
            Some(config),
        )
        .await
        .map_err(Error::other)?;

        // split for parallel send and recv
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
            .send(Message::binary(msg))
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
                        // convert text into binary
                        Text(s) => return Ok(s.as_bytes().to_vec()),
                        // use binary directly
                        Binary(v) => return Ok(v.to_vec()),
                        // ignoring server ping/pong for now
                        Ping(_) | Pong(_) => (),
                        Close(_) => return Err(Error::other("closed")),
                        // we are not configured to receive raw frames
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
                    // we are not authenticated yet, we should not get msgs
                    return Err(Error::other("invalid handshake"));
                }
                // receive server rate limit
                MsgType::LimitByteNanos(l) => limit_byte_nanos = l,
                // receive server idle timeout
                MsgType::LimitIdleMillis(l) => limit_idle_millis = l,
                // process the authorization request
                MsgType::AuthReq(nonce) => {
                    let sig = crypto.sign(nonce)?;
                    let mut auth_res = Vec::with_capacity(HDR_SIZE + SIG_SIZE);
                    auth_res.extend_from_slice(CMD_PREFIX);
                    auth_res.extend_from_slice(b"ares");
                    auth_res.extend_from_slice(&sig);
                    send.send(auth_res).await?;
                    bytes_sent += HDR_SIZE + SIG_SIZE;
                }
                // hey! handshake is successful
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

    #[cfg(any(
        feature = "force_webpki_roots",
        not(any(
            target_os = "windows",
            target_os = "linux",
            target_os = "macos",
        )),
    ))]
    {
        roots.roots = webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
    }

    #[cfg(all(
        not(feature = "force_webpki_roots"),
        any(target_os = "windows", target_os = "linux", target_os = "macos",),
    ))]
    roots.add_parsable_certificates(
        rustls_native_certs::load_native_certs().certs,
    );

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
