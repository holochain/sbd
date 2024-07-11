use super::*;
use std::sync::Arc;

/// test 4
pub struct It4;

impl It for It4 {
    const NAME: &'static str = "4-ignore-none-pre-handshake";
    const DESC: &'static str = "ensure server ignores unknown commands before the handshake for forward compatibility";

    fn exec(helper: &mut TestHelper) -> impl Future<Output = Result<()>> {
        async {
            use sbd_client::Crypto;

            let crypto = sbd_client::DefaultCrypto::default();

            let pub_key = sbd_client::PubKey(Arc::new(*crypto.pub_key()));

            let (mut send, mut recv) = helper
                .connect_raw_client(format!("{pub_key:?}"), 20_000, vec![])
                .await?;

            let mut none = vec![0_u8; 49];
            none[28] = b'n';
            none[29] = b'o';
            none[30] = b'n';
            none[31] = b'e';

            send.send(none).await?;

            sbd_client::raw_client::Handshake::handshake(
                &mut send, &mut recv, &crypto,
            )
            .await?;

            Ok(())
        }
    }
}
