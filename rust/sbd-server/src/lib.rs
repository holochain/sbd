//! Sbd server library.
#![deny(missing_docs)]

/// defined by the sbd spec
const MAX_MSG_BYTES: i32 = 20_000;

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
    _cslot: cslot::CSlot,
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

async fn handle_auth(
    axum::extract::State(app_state): axum::extract::State<AppState>,
    body: bytes::Bytes,
) -> axum::response::Response {
    match process_authenticate_token(
        &app_state.config,
        &app_state.token_tracker,
        body,
    )
    .await
    {
        Ok(token) => axum::response::IntoResponse::into_response(axum::Json(
            serde_json::json!({
                "authToken": *token,
            }),
        )),
        Err(_) => axum::response::IntoResponse::into_response((
            axum::http::StatusCode::UNAUTHORIZED,
            "Unauthorized",
        )),
    }
}

/// Handle receiving a PUT "/authenticate" rest api request.
pub async fn process_authenticate_token(
    config: &Config,
    token_tracker: &AuthTokenTracker,
    auth_material: bytes::Bytes,
) -> Result<Arc<str>> {
    let token: Arc<str> = if let Some(url) = &config.authentication_hook_server
    {
        let url = url.clone();
        tokio::task::spawn_blocking(move || {
            ureq::put(&url)
                .set("Content-Type", "application/octet-stream")
                .send(&auth_material[..])
                .map_err(std::io::Error::other)?
                .into_string()
        })
        .await??
    } else {
        // If no backend configured, fallback to gen random token:
        use base64::prelude::*;
        use rand::Rng;

        let mut bytes = [0; 32];
        rand::thread_rng().fill(&mut bytes);
        BASE64_URL_SAFE_NO_PAD.encode(&bytes[..])
    }
    .into();

    token_tracker.register_token(token.clone());

    Ok(token)
}

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
                                return Ok(Payload::Vec(s.as_bytes().to_vec()))
                            }
                            axum::extract::ws::Message::Binary(v) => {
                                return Ok(Payload::Vec(v[..].to_vec()))
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
    fn new(ws: axum::extract::ws::WebSocket) -> Self {
        use futures::StreamExt;
        let (tx, rx) = ws.split();
        Self {
            write: Arc::new(tokio::sync::Mutex::new(tx)),
            read: Arc::new(tokio::sync::Mutex::new(rx)),
        }
    }
}

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

    let token: Option<Arc<str>> = headers
        .get("Authenticate")
        .map(|t| t.to_str().ok().map(|t| <Arc<str>>::from(t)))
        .flatten();

    let maybe_auth = Some((token.clone(), app_state.token_tracker.clone()));

    if !app_state
        .token_tracker
        .check_is_token_valid(&app_state.config, token)
    {
        return axum::response::IntoResponse::into_response((
            axum::http::StatusCode::UNAUTHORIZED,
            "Unauthorized",
        ));
    }

    let pk = match base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(pub_key) {
        Ok(pk) if pk.len() == 32 => {
            let mut sized_pk = [0; 32];
            sized_pk.copy_from_slice(&pk);
            PubKey(Arc::new(sized_pk))
        }
        _ => return axum::http::StatusCode::BAD_REQUEST.into_response(),
    };

    let mut calc_ip = to_canonical_ip(addr.ip());

    if let Some(trusted_ip_header) = &app_state.config.trusted_ip_header {
        if let Some(header) =
            headers.get(trusted_ip_header).and_then(|h| h.to_str().ok())
        {
            if let Ok(ip) = header.parse::<IpAddr>() {
                calc_ip = to_canonical_ip(ip);
            }
        }
    }

    ws.max_message_size(MAX_MSG_BYTES as usize).on_upgrade(
        move |socket| async move {
            handle_upgraded(
                app_state.config.clone(),
                app_state.ip_rate.clone(),
                app_state.cslot.clone(),
                Arc::new(WebsocketImpl::new(socket)),
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

        if lock.contains_key(&token) {
            lock.insert(token, std::time::Instant::now());
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
}

impl AppState {
    pub fn new(
        config: Arc<Config>,
        ip_rate: Arc<IpRate>,
        cslot: WeakCSlot,
    ) -> Self {
        Self {
            config,
            token_tracker: AuthTokenTracker::default(),
            ip_rate,
            cslot,
        }
    }
}

impl SbdServer {
    /// Construct a new running sbd server with the provided config.
    pub async fn new(config: Arc<Config>) -> Result<Self> {
        let tls_config = if let (Some(cert), Some(pk)) =
            (&config.cert_pem_file, &config.priv_key_pem_file)
        {
            Some(Arc::new(maybe_tls::TlsConfig::new(cert, pk).await?))
        } else {
            None
        };

        let mut task_list = Vec::new();
        let mut bind_addrs = Vec::new();

        let ip_rate = Arc::new(IpRate::new(config.clone()));
        task_list.push(spawn_prune_task(ip_rate.clone()));

        let cslot = CSlot::new(config.clone(), ip_rate.clone());
        let weak_cslot = cslot.weak();

        let app: axum::Router<()> = axum::Router::new()
            .route("/authenticate", axum::routing::put(handle_auth))
            .route("/{pub_key}", axum::routing::any(handle_ws))
            .layer(axum::extract::DefaultBodyLimit::max(1024))
            .with_state(AppState::new(
                config.clone(),
                ip_rate.clone(),
                weak_cslot.clone(),
            ));

        let app =
            app.into_make_service_with_connect_info::<std::net::SocketAddr>();

        let mut found_port_zero: Option<u16> = None;

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
                    let _ = server.await;
                }));
            } else {
                let server =
                    axum_server::bind(a).handle(h.clone()).serve(app.clone());
                task_list.push(tokio::task::spawn(async move {
                    let _ = server.await;
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
