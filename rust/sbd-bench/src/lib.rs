use sbd_client::raw_client::*;
use sbd_client::*;
use sbd_server::*;
use std::sync::Arc;

async fn raw_connect(
    pk: &[u8; 32],
    addrs: &[std::net::SocketAddr],
) -> std::io::Result<(WsRawSend, WsRawRecv)> {
    use base64::Engine;

    for addr in addrs {
        if let Ok(r) = (WsRawConnect {
            full_url: format!(
                "ws://{addr}/{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pk)
            ),
            max_message_size: 1000,
            allow_plain_text: true,
            danger_disable_certificate_check: false,
            headers: Vec::new(),
        })
        .connect()
        .await
        {
            return Ok(r);
        }
    }
    Err(std::io::Error::other("could not connect"))
}

mod thru;
pub use thru::*;

mod c_turnover;
pub use c_turnover::*;

mod c_count_scale;
pub use c_count_scale::*;
