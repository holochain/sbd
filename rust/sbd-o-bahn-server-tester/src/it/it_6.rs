use super::*;
use std::sync::Arc;

/// test 6
pub struct It6;

impl It for It6 {
    const NAME: &'static str = "6-msg-too-big";
    const DESC: &'static str =
        "connection is dropped if too large a message is sent";

    fn exec(helper: &mut TestHelper) -> impl Future<Output = Result<()>> {
        async {
            use sbd_client::Crypto;

            let crypto = sbd_client::DefaultCrypto::default();

            let pub_key = sbd_client::PubKey(Arc::new(*crypto.pub_key()));

            let (mut send, mut recv) = helper
                .connect_raw_client(format!("{pub_key:?}"), 25_000, vec![])
                .await?;

            sbd_client::raw_client::Handshake::handshake(
                &mut send, &mut recv, &crypto,
            )
            .await?;

            let mut msg = vec![0_u8; 25_000];
            msg[..32].copy_from_slice(crypto.pub_key());

            send.send(msg).await?;

            match recv.recv().await {
                Ok(_) => Err(Error::other("unexpected success")),
                Err(_) => Ok(()),
            }
        }
    }
}
