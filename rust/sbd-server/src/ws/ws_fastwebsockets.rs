use super::Payload;
use crate::*;
use std::io::{Error, Result};
use std::sync::Arc;

/// WebSocket abstraction.
pub struct WebSocket<S>(
    fastwebsockets::WebSocket<
        hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>,
    >,
    std::marker::PhantomData<S>,
)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static;

impl<S> WebSocket<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    /// As a server, accept/upgrade a new client connection.
    pub async fn upgrade(config: Arc<Config>, s: S) -> Result<Self> {
        let io = hyper_util::rt::TokioIo::new(s);
        let (s, mut r) = tokio::sync::mpsc::unbounded_channel();
        let _res = hyper::server::conn::http1::Builder::new()
            .serve_connection(
                io,
                hyper::service::service_fn(move |mut req| {
                    // TODO report the PUBKEY here
                    println!("req {req:?}");
                    let s = s.clone();
                    async move {
                        let (response, fut) =
                            fastwebsockets::upgrade::upgrade(&mut req)
                                .map_err(Error::other)?;
                        let _ = s.send(fut);
                        Result::Ok(response)
                    }
                }),
            )
            .with_upgrades()
            .await
            .map_err(Error::other)?;
        let mut ws = r.recv().await.unwrap().await.map_err(Error::other)?;
        ws.set_max_message_size(config.limit_message_bytes);
        ws.set_auto_pong(false);
        Ok(Self(ws, std::marker::PhantomData))
    }

    /// Receive from the websocket.
    pub async fn recv(&mut self) -> Result<Payload<'_>> {
        const NO_FRAME: &str = "sbd does not allow multi-frame messages";
        loop {
            let frame = self.0.read_frame().await.map_err(Error::other)?;
            if !frame.fin {
                return Err(Error::other(NO_FRAME));
            }
            use fastwebsockets::OpCode::*;
            use fastwebsockets::Payload::*;
            match frame.opcode {
                Continuation => return Err(Error::other(NO_FRAME)),
                Text | Binary => {
                    return Ok(match frame.payload {
                        BorrowedMut(s) => Payload::SliceMut(s),
                        Borrowed(s) => Payload::Slice(s),
                        Owned(v) => Payload::Vec(v),
                        Bytes(b) => Payload::BytesMut(b),
                    });
                }
                Close => {
                    return Err(Error::other("closed"));
                }
                Ping | Pong => (),
            }
        }
    }

    /// Send to the websocket.
    pub async fn send(&mut self, payload: Payload<'_>) -> Result<()> {
        use fastwebsockets::Payload::*;
        let payload = match payload {
            Payload::Slice(s) => Borrowed(s),
            Payload::SliceMut(s) => BorrowedMut(s),
            Payload::Vec(v) => Owned(v),
            Payload::BytesMut(b) => Bytes(b),
        };
        self.0
            .write_frame(fastwebsockets::Frame::binary(payload))
            .await
            .map_err(Error::other)
    }
}
