use super::*;
use std::sync::Arc;

/// test 5
pub struct It5;

impl It for It5 {
    const NAME: &'static str = "ignore-none-post-handshake";

    fn exec(helper: &mut TestHelper) -> impl Future<Output = Result<()>> {
        async {
            use sbd_client::Crypto;

            let crypto = sbd_client::DefaultCrypto::default();

            let pub_key = sbd_client::PubKey(Arc::new(*crypto.pub_key()));

            let (mut send, mut recv) = helper
                .connect_raw_client(format!("{pub_key:?}"), 20_000, vec![])
                .await?;

            sbd_client::raw_client::Handshake::handshake(
                &mut send, &mut recv, &crypto,
            )
            .await?;

            let mut none = vec![0_u8; 49];
            none[28] = b'n';
            none[29] = b'o';
            none[30] = b'n';
            none[31] = b'e';

            send.send(none).await?;

            let mut msg = vec![0_u8; 32];
            msg.copy_from_slice(crypto.pub_key());

            send.send(msg).await?;

            let _msg = recv.recv().await?;

            Ok(())
        }
    }
}
