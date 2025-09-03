//! Sbd server library.
//!
//! ## Metrics
//!
//! The server exports the following OpenTelemetry metrics if an OTLP endpoint is configured.
//!
//! Prometheus example: `sbd-serverd --otlp-endpoint http://localhost:9090/api/v1/otlp/v1/metrics`
//!
//! | Full Metric Name | Type | Unit (optional) | Description | Attributes |
//! | ---------------- | ---- | --------------- | ----------- | ---------- |
//! | `sbd.server.open_connections` | `f64_up_down_counter` | `count` | The current number of open connections | |
//! | `sbd.server.ip_rate_limited` | `u64_counter` | `count` | The number of connections that have been closed because of an IP rate limiting violation | - `pub_key`: The base64 encoded public key declared by the offending connection.<br />- `kind`: Has two possible values. It will be "auth" for violations during authentication and "msg" for violations while sending messages. |
//! | `sbd.server.bytes_send` | `u64_counter` | `bytes` | The number of bytes sent per public key. Resets when a new connection is opened. | - `pub_key`: The base64 encoded public key declared by the offending connection. |
//! | `sbd.server.bytes_recv` | `u64_counter` | `bytes` | The number of bytes received per public key. Resets when a new connection is opened. | - `pub_key`: The base64 encoded public key declared by the offending connection. |
//! | `sbd.server.auth_failures` | `u64_counter` | `count` | The number of failed authentication attempts. | - `pub_key`: The base64 encoded public key declared by the offending connection. This is only present if an invalid token is used with a specific public key. |

#![deny(missing_docs)]

/// defined by the sbd spec
const MAX_MSG_BYTES: i32 = 20_000;

use base64::Engine;
use opentelemetry::global;
use std::collections::HashMap;
use std::io::{Error, Result};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Mutex};

mod config;
pub use config::*;

mod maybe_tls;
pub use maybe_tls::*;

mod ip_deny;
mod ip_rate;
pub use ip_rate::*;

mod cslot;
pub use cslot::*;

mod cmd;

mod metrics;
pub use metrics::*;

/// Websocket backend abstraction.
pub mod ws {
    /// Payload.
    pub enum Payload {
        /// Vec.
        Vec(Vec<u8>),

        /// BytesMut.
        BytesMut(bytes::BytesMut),
    }

    impl std::ops::Deref for Payload {
        type Target = [u8];

        #[inline(always)]
        fn deref(&self) -> &Self::Target {
            match self {
                Payload::Vec(v) => v.as_slice(),
                Payload::BytesMut(b) => b.as_ref(),
            }
        }
    }

    impl Payload {
        /// Mutable payload.
        #[inline(always)]
        pub fn to_mut(&mut self) -> &mut [u8] {
            match self {
                Payload::Vec(ref mut owned) => owned,
                Payload::BytesMut(b) => b.as_mut(),
            }
        }
    }

    use futures::future::BoxFuture;

    /// Websocket trait.
    pub trait SbdWebsocket: Send + Sync + 'static {
        /// Receive from the websocket.
        fn recv(&self) -> BoxFuture<'static, std::io::Result<Payload>>;

        /// Send to the websocket.
        fn send(
            &self,
            payload: Payload,
        ) -> BoxFuture<'static, std::io::Result<()>>;

        /// Close the websocket.
        fn close(&self) -> BoxFuture<'static, ()>;
    }
}

pub use ws::{Payload, SbdWebsocket};

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

    // this should be the only non-weak cslot so the others are dropped
    // if this top-level server instance is ever dropped.
    _cslot: CSlot,
}

impl Drop for SbdServer {
    fn drop(&mut self) {
        for task in self.task_list.iter() {
            task.abort();
        }
    }
}

/// Convert an IP address to an IPv6 address.
pub fn to_canonical_ip(ip: IpAddr) -> Arc<Ipv6Addr> {
    Arc::new(match ip {
        IpAddr::V4(ip) => ip.to_ipv6_mapped(),
        IpAddr::V6(ip) => ip,
    })
}

/// If the check passes, the canonical IP is returned, otherwise None and the connection should be
/// dropped.
pub async fn preflight_ip_check(
    config: &Config,
    ip_rate: &IpRate,
    addr: std::net::SocketAddr,
) -> Option<Arc<Ipv6Addr>> {
    let raw_ip = to_canonical_ip(addr.ip());

    let use_trusted_ip = config.trusted_ip_header.is_some();

    if !use_trusted_ip {
        // Do this check BEFORE handshake to avoid extra
        // server process when capable.
        // If we *are* behind a reverse proxy, we assume
        // some amount of DDoS mitigation is happening there
        // and thus we can accept a little more process overhead
        if ip_rate.is_blocked(&raw_ip).await {
            return None;
        }

        // Also precheck our rate limit, using up one byte
        if !ip_rate.is_ok(&raw_ip, 1).await {
            return None;
        }
    }

    Some(raw_ip)
}

/// Handle an upgraded websocket connection.
pub async fn handle_upgraded(
    config: Arc<Config>,
    ip_rate: Arc<IpRate>,
    weak_cslot: WeakCSlot,
    ws: Arc<impl SbdWebsocket>,
    pub_key: PubKey,
    calc_ip: Arc<Ipv6Addr>,
    maybe_auth: Option<(Option<Arc<str>>, AuthTokenTracker)>,
) {
    let use_trusted_ip = config.trusted_ip_header.is_some();

    // illegal pub key
    if &pub_key.0[..28] == cmd::CMD_PREFIX {
        return;
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
            .insert(&config, calc_ip, pub_key, ws, maybe_auth)
            .await;
    }
}

/// Handle the /authenticate request for access token
async fn handle_auth(
    axum::extract::State(app_state): axum::extract::State<AppState>,
    body: bytes::Bytes,
) -> axum::response::Response {
    use AuthenticateTokenError::*;

    // process the actual authentication
    match process_authenticate_token(
        &app_state.config,
        &app_state.token_tracker,
        app_state.auth_failures,
        body,
    )
    .await
    {
        Ok(token) => axum::response::IntoResponse::into_response(axum::Json(
            serde_json::json!({
                "authToken": *token,
            }),
        )),
        Err(Unauthorized) => {
            tracing::debug!("/authenticate: UNAUTHORIZED");
            axum::response::IntoResponse::into_response((
                axum::http::StatusCode::UNAUTHORIZED,
                "Unauthorized",
            ))
        }
        Err(HookServerError(err)) => {
            tracing::debug!(?err, "/authenticate: BAD_GATEWAY");
            axum::response::IntoResponse::into_response((
                axum::http::StatusCode::BAD_GATEWAY,
                format!("BAD_GATEWAY: {err:?}"),
            ))
        }
        Err(OtherError(err)) => {
            tracing::warn!(?err, "/authenticate: INTERNAL_SERVER_ERROR");
            axum::response::IntoResponse::into_response((
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("INTERNAL_SERVER_ERROR: {err:?}"),
            ))
        }
    }
}

/// Authenticate token error type.
pub enum AuthenticateTokenError {
    /// The token is invalid.
    Unauthorized,
    /// We had an error talking to the hook server.
    HookServerError(Error),
    /// We had an internal error.
    OtherError(Error),
}

/// Handle receiving a PUT "/authenticate" rest api request.
pub async fn process_authenticate_token(
    config: &Config,
    token_tracker: &AuthTokenTracker,
    auth_failures: opentelemetry::metrics::Counter<u64>,
    auth_material: bytes::Bytes,
) -> std::result::Result<Arc<str>, AuthenticateTokenError> {
    use AuthenticateTokenError::*;

    let token: Arc<str> = if let Some(url) = &config.authentication_hook_server
    {
        // if a hook server is configured, forward the call to it

        let url = url.clone();
        let token = tokio::task::spawn_blocking(move || {
            ureq::put(&url)
                .header("Content-Type", "application/octet-stream")
                .send(&auth_material[..])
                .map_err(|err| {
                    auth_failures.add(1, &[]);

                    match err {
                        ureq::Error::StatusCode(401) => Unauthorized,
                        oth => HookServerError(Error::other(oth)),
                    }
                })?
                .into_body()
                .read_to_string()
                .map_err(Error::other)
                // this is a HookServerError, not an OtherError, because
                // it is the hook server that either failed to send a full
                // response, or sent back non-utf8 bytes, etc...
                .map_err(HookServerError)
        })
        .await
        .map_err(|_| OtherError(Error::other("tokio task died")))??;

        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Token {
            auth_token: String,
        }

        let token: Token = serde_json::from_str(&token)
            .map_err(|err| OtherError(Error::other(err)))?;

        token.auth_token
    } else {
        // If no hook server is configured, fallback to gen random token

        use base64::prelude::*;
        use rand::Rng;

        let mut bytes = [0; 32];
        rand::thread_rng().fill(&mut bytes);
        BASE64_URL_SAFE_NO_PAD.encode(&bytes[..])
    }
    .into();

    // register the token with our authentication token tracker
    token_tracker.register_token(token.clone());

    Ok(token)
}

/// Implement the ability to use axum websockets as our websocket backend.
#[derive(Clone)]
struct WebsocketImpl {
    write: Arc<
        tokio::sync::Mutex<
            futures::stream::SplitSink<
                axum::extract::ws::WebSocket,
                axum::extract::ws::Message,
            >,
        >,
    >,
    read: Arc<
        tokio::sync::Mutex<
            futures::stream::SplitStream<axum::extract::ws::WebSocket>,
        >,
    >,
    attr: Vec<opentelemetry::KeyValue>,
    bytes_send: opentelemetry::metrics::Counter<u64>,
    bytes_recv: opentelemetry::metrics::Counter<u64>,
}

impl SbdWebsocket for WebsocketImpl {
    fn recv(&self) -> futures::future::BoxFuture<'static, Result<Payload>> {
        let this = self.clone();
        Box::pin(async move {
            let mut read = this.read.lock().await;
            use futures::stream::StreamExt;
            loop {
                match read.next().await {
                    None => return Err(Error::other("closed")),
                    Some(r) => {
                        let msg = r.map_err(Error::other)?;
                        match msg {
                            axum::extract::ws::Message::Text(s) => {
                                this.bytes_recv.add(s.len() as u64, &this.attr);
                                return Ok(Payload::Vec(s.as_bytes().to_vec()));
                            }
                            axum::extract::ws::Message::Binary(v) => {
                                this.bytes_recv.add(v.len() as u64, &this.attr);
                                return Ok(Payload::Vec(v[..].to_vec()));
                            }
                            axum::extract::ws::Message::Ping(_)
                            | axum::extract::ws::Message::Pong(_) => (),
                            axum::extract::ws::Message::Close(_) => {
                                return Err(Error::other("closed"))
                            }
                        }
                    }
                }
            }
        })
    }

    fn send(
        &self,
        payload: Payload,
    ) -> futures::future::BoxFuture<'static, Result<()>> {
        use futures::SinkExt;
        let this = self.clone();
        Box::pin(async move {
            let mut write = this.write.lock().await;
            let v = match payload {
                Payload::Vec(v) => v,
                Payload::BytesMut(b) => b.to_vec(),
            };
            this.bytes_send.add(v.len() as u64, &this.attr);
            write
                .send(axum::extract::ws::Message::Binary(
                    bytes::Bytes::copy_from_slice(&v),
                ))
                .await
                .map_err(Error::other)?;
            write.flush().await.map_err(Error::other)?;
            Ok(())
        })
    }

    fn close(&self) -> futures::future::BoxFuture<'static, ()> {
        use futures::SinkExt;
        let this = self.clone();
        Box::pin(async move {
            let _ = this.write.lock().await.close().await;
        })
    }
}

impl WebsocketImpl {
    fn new(
        ws: axum::extract::ws::WebSocket,
        pk: PubKey,
        meter: &opentelemetry::metrics::Meter,
    ) -> Self {
        use futures::StreamExt;

        let bytes_send = meter
            .u64_counter("sbd.server.bytes_send")
            .with_description("Number of bytes sent to client")
            .with_unit("bytes")
            .build();
        let bytes_recv = meter
            .u64_counter("sbd.server.bytes_recv")
            .with_description("Number of bytes received from client")
            .with_unit("bytes")
            .build();

        let (tx, rx) = ws.split();
        Self {
            write: Arc::new(tokio::sync::Mutex::new(tx)),
            read: Arc::new(tokio::sync::Mutex::new(rx)),
            attr: vec![opentelemetry::KeyValue::new(
                "pub_key",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(*pk.0),
            )],
            bytes_send,
            bytes_recv,
        }
    }
}

/// Handle the http upgrade request for a websocket connection.
async fn handle_ws(
    axum::extract::Path(pub_key): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
    ws: axum::extract::WebSocketUpgrade,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<
        std::net::SocketAddr,
    >,
    axum::extract::State(app_state): axum::extract::State<AppState>,
) -> impl axum::response::IntoResponse {
    use axum::response::IntoResponse;
    use base64::Engine;

    // first check for auth tokens
    let token: Option<Arc<str>> = headers
        .get("Authorization")
        .and_then(|t| t.to_str().ok().map(<Arc<str>>::from));

    let maybe_auth = Some((token.clone(), app_state.token_tracker.clone()));

    // compare any passed tokens with our token authentication mechanism
    if !app_state
        .token_tracker
        .check_is_token_valid(&app_state.config, token)
    {
        // Might be useful to record the IP address here, but it's special category data. To keep
        // the server privacy-friendly, avoid exporting the IP address to the metrics even though
        // this user did not authenticate properly.
        app_state
            .auth_failures
            .add(1, &[opentelemetry::KeyValue::new("pub_key", pub_key)]);

        return axum::response::IntoResponse::into_response((
            axum::http::StatusCode::UNAUTHORIZED,
            "Unauthorized",
        ));
    }

    // get the primary key this user is claiming
    let pk = match base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(pub_key) {
        Ok(pk) if pk.len() == 32 => {
            let mut sized_pk = [0; 32];
            sized_pk.copy_from_slice(&pk);
            PubKey(Arc::new(sized_pk))
        }
        _ => return axum::http::StatusCode::BAD_REQUEST.into_response(),
    };

    let mut calc_ip = to_canonical_ip(addr.ip());

    // if we're using a trusted ip, parse that out of the header
    if let Some(trusted_ip_header) = &app_state.config.trusted_ip_header {
        if let Some(header) =
            headers.get(trusted_ip_header).and_then(|h| h.to_str().ok())
        {
            if let Ok(ip) = header.parse::<IpAddr>() {
                calc_ip = to_canonical_ip(ip);
            }
        }
    }

    // do the actual websocket upgrade
    ws.max_message_size(MAX_MSG_BYTES as usize).on_upgrade(
        move |socket| async move {
            handle_upgraded(
                app_state.config.clone(),
                app_state.ip_rate.clone(),
                app_state.cslot.clone(),
                Arc::new(WebsocketImpl::new(
                    socket,
                    pk.clone(),
                    &app_state.meter,
                )),
                pk,
                calc_ip,
                maybe_auth,
            )
            .await;
        },
    )
}

/// Utility for managing auth tokens.
#[derive(Clone, Default)]
pub struct AuthTokenTracker {
    token_map: Arc<Mutex<HashMap<Arc<str>, std::time::Instant>>>,
}

impl AuthTokenTracker {
    /// Register a token as valid.
    pub fn register_token(&self, token: Arc<str>) {
        self.token_map
            .lock()
            .unwrap()
            .insert(token, std::time::Instant::now());
    }

    /// Check that a token is valid.
    /// If so, mark it as recently used so it doesn't time out.
    /// The "token" parameter should be direct from the http header
    /// i.e. with the "Barer" include, like "Bearer base64".
    /// This should be called with None as the token if no Authenticate
    /// header was specified.
    pub fn check_is_token_valid(
        &self,
        config: &Config,
        token: Option<Arc<str>>,
    ) -> bool {
        let token: Arc<str> = if let Some(token) = token {
            // If the client supplied a token, always validate it,
            // even if no hook server was specified in the config.
            if !token.starts_with("Bearer ") {
                return false;
            }
            token.trim_start_matches("Bearer ").into()
        } else if config.authentication_hook_server.is_none() {
            // If the client did not supply a token, and we have no
            // hook server configured, allow the request.
            return true;
        } else {
            // We have no token, but one is required. Unauthorized.
            return false;
        };

        let mut lock = self.token_map.lock().unwrap();

        let idle_dur = config.idle_dur();

        lock.retain(|_t, e| e.elapsed() < idle_dur);

        if let std::collections::hash_map::Entry::Occupied(mut e) =
            lock.entry(token)
        {
            e.insert(std::time::Instant::now());
            true
        } else {
            false
        }
    }
}

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    token_tracker: AuthTokenTracker,
    ip_rate: Arc<IpRate>,
    cslot: WeakCSlot,
    auth_failures: opentelemetry::metrics::Counter<u64>,
    meter: opentelemetry::metrics::Meter,
}

impl AppState {
    pub fn new(
        config: Arc<Config>,
        ip_rate: Arc<IpRate>,
        cslot: WeakCSlot,
        meter: opentelemetry::metrics::Meter,
    ) -> Self {
        Self {
            config,
            token_tracker: AuthTokenTracker::default(),
            ip_rate,
            cslot,
            auth_failures: meter
                .u64_counter("sbd.server.auth_failures")
                .with_description("Number of failed authentication attempts")
                .with_unit("count")
                .build(),
            meter,
        }
    }
}

impl SbdServer {
    /// Construct a new running sbd server with the provided config.
    pub async fn new(config: Arc<Config>) -> Result<Self> {
        let tls_config = if let (Some(cert), Some(pk)) =
            (&config.cert_pem_file, &config.priv_key_pem_file)
        {
            Some(Arc::new(TlsConfig::new(cert, pk).await?))
        } else {
            None
        };

        let sbd_server_meter = global::meter("sbd-server");

        let mut task_list = Vec::new();
        let mut bind_addrs = Vec::new();

        let ip_rate = Arc::new(IpRate::new(config.clone()));
        task_list.push(spawn_prune_task(ip_rate.clone()));

        let cslot = CSlot::new(
            config.clone(),
            ip_rate.clone(),
            sbd_server_meter.clone(),
        );
        let weak_cslot = cslot.weak();

        // setup the axum router
        let app: axum::Router<()> = axum::Router::new()
            .route("/authenticate", axum::routing::put(handle_auth))
            .route("/{pub_key}", axum::routing::any(handle_ws))
            .layer(axum::extract::DefaultBodyLimit::max(1024))
            .with_state(AppState::new(
                config.clone(),
                ip_rate.clone(),
                weak_cslot.clone(),
                sbd_server_meter,
            ));

        let app =
            app.into_make_service_with_connect_info::<std::net::SocketAddr>();

        let mut found_port_zero: Option<u16> = None;

        // bind to configured bindings
        for bind in config.bind.iter() {
            let mut a: std::net::SocketAddr =
                bind.parse().map_err(Error::other)?;
            if let Some(found_port_zero) = &found_port_zero {
                if a.port() == 0 {
                    a.set_port(*found_port_zero);
                }
            }

            let h = axum_server::Handle::new();

            if let Some(tls_config) = &tls_config {
                let tls_config =
                    axum_server::tls_rustls::RustlsConfig::from_config(
                        tls_config.config(),
                    );
                let server = axum_server::bind_rustls(a, tls_config)
                    .handle(h.clone())
                    .serve(app.clone());
                task_list.push(tokio::task::spawn(async move {
                    if let Err(err) = server.await {
                        tracing::error!(?err);
                    }
                }));
            } else {
                let server =
                    axum_server::bind(a).handle(h.clone()).serve(app.clone());
                task_list.push(tokio::task::spawn(async move {
                    if let Err(err) = server.await {
                        tracing::error!(?err);
                    }
                }));
            }

            if let Some(addr) = h.listening().await {
                if found_port_zero.is_none() && a.port() == 0 {
                    found_port_zero = Some(addr.port());
                }
                bind_addrs.push(addr);
            }
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

#[cfg(test)]
mod test;
