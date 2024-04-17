use super::Payload;
use crate::*;
use std::io::{Error, Result};
use std::sync::Arc;

/// WebSocket abstraction.
pub struct WebSocket<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    write: tokio::sync::Mutex<
        futures::stream::SplitSink<
            tokio_tungstenite::WebSocketStream<S>,
            tokio_tungstenite::tungstenite::protocol::Message,
        >,
    >,
    read: tokio::sync::Mutex<
        futures::stream::SplitStream<tokio_tungstenite::WebSocketStream<S>>,
    >,
}

impl<S> WebSocket<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    /// As a server, accept/upgrade a new client connection.
    pub async fn upgrade(
        config: Arc<Config>,
        s: S,
    ) -> Result<(Self, PubKey, Option<std::net::Ipv6Addr>)> {
        use tokio_tungstenite::tungstenite::{
            handshake::server, protocol::WebSocketConfig,
        };
        let mut trusted_ip = None;
        let mut ws = WebSocketConfig::default();
        ws.max_message_size = Some(config.limit_message_bytes as usize);
        struct Cb(tokio::sync::oneshot::Sender<server::Request>);
        impl server::Callback for Cb {
            fn on_request(
                self,
                request: &server::Request,
                response: server::Response,
            ) -> std::result::Result<server::Response, server::ErrorResponse>
            {
                let _ = self.0.send(request.clone());
                Ok(response)
            }
        }
        let (req_s, req_r) = tokio::sync::oneshot::channel();
        let ws = tokio_tungstenite::accept_hdr_async_with_config(
            s,
            Cb(req_s),
            Some(ws),
        )
        .await
        .map_err(Error::other)?;
        let req = req_r.await.unwrap();
        let pk = {
            let mut it = req.uri().path().split('/');
            const INV_PK: &str = "invalid pubkey path";
            if it.next().is_none() {
                return Err(Error::other(INV_PK));
            }
            let path = match it.next() {
                None => return Err(Error::other(INV_PK)),
                Some(path) => path,
            };
            use base64::Engine;
            if let Ok(ppk) =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(path)
            {
                if ppk.len() != 32 {
                    return Err(Error::other(INV_PK));
                }
                let mut pk = [0; 32];
                pk.copy_from_slice(&ppk);
                pk
            } else {
                return Err(Error::other(INV_PK));
            }
        };

        if let Some(trusted_ip_header) = &config.trusted_ip_header {
            for (k, v) in req.headers().iter() {
                if k.as_str() == trusted_ip_header {
                    if let Ok(ip) = v.to_str() {
                        if let Ok(ip) = ip.parse::<std::net::IpAddr>() {
                            trusted_ip = Some(match ip {
                                std::net::IpAddr::V4(ip) => ip.to_ipv6_mapped(),
                                std::net::IpAddr::V6(ip) => ip,
                            });
                        }
                    }
                }
            }
        }

        let (write, read) = futures::stream::StreamExt::split(ws);
        let write = tokio::sync::Mutex::new(write);
        let read = tokio::sync::Mutex::new(read);
        Ok((Self { write, read }, PubKey(Arc::new(pk)), trusted_ip))
    }

    /// Receive from the websocket.
    pub async fn recv(&self) -> Result<Payload<'_>> {
        let mut read = self.read.lock().await;
        use futures::stream::StreamExt;
        loop {
            match read.next().await {
                None => return Err(Error::other("closed")),
                Some(r) => {
                    let msg = r.map_err(Error::other)?;
                    use tokio_tungstenite::tungstenite::protocol::Message::*;
                    match msg {
                        Text(s) => return Ok(Payload::Vec(s.into_bytes())),
                        Binary(v) => return Ok(Payload::Vec(v)),
                        Ping(_) | Pong(_) => (),
                        Close(_) => return Err(Error::other("closed")),
                        Frame(_) => unreachable!(),
                    }
                }
            }
        }
    }

    /// Send to the websocket.
    pub async fn send(&self, payload: Payload<'_>) -> Result<()> {
        let mut write = self.write.lock().await;
        use futures::sink::SinkExt;
        use tokio_tungstenite::tungstenite::protocol::Message;
        let v = match payload {
            Payload::Slice(s) => s.to_vec(),
            Payload::SliceMut(s) => s.to_vec(),
            Payload::Vec(v) => v,
            Payload::BytesMut(b) => b.to_vec(),
        };
        write.send(Message::binary(v)).await.map_err(Error::other)?;
        write.flush().await.map_err(Error::other)?;
        Ok(())
    }
}
