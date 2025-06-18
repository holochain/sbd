use super::*;
use std::sync::Arc;

/// test 3
pub struct It3;

impl It for It3 {
    const NAME: &'static str = "3-bad-handshake-sig";
    const DESC: &'static str = "connection is dropped if the client responds with a bad handshake signature";

    fn exec(helper: &mut TestHelper) -> impl Future<Output = Result<()>> {
        async {
            use sbd_client::Crypto;

            let crypto = sbd_client::DefaultCrypto::default();

            let pub_key = sbd_client::PubKey(Arc::new(*crypto.pub_key()));

            let (mut send, mut recv) = helper
                .connect_raw_client(format!("{pub_key:?}"), 20_000, vec![])
                .await?;

            let _sig = loop {
                let msg = recv.recv().await?;

                if msg.len() < 32 {
                    return Err(Error::other("invalid msg len"));
                }

                if msg[28] == b'a'
                    && msg[29] == b'r'
                    && msg[30] == b'e'
                    && msg[31] == b'q'
                {
                    break crypto.sign(&msg[32..])?;
                }
            };

            let mut res = vec![0_u8; 32 + 64];
            res[28] = b'a';
            res[29] = b'r';
            res[30] = b'e';
            res[31] = b's';

            // the following line should make it handshake success.
            // but, since we're testing the negative, leave the signature
            // as all zeroes.
            //res[32..].copy_from_slice(&sig);

            send.send(res).await?;

            loop {
                return match recv.recv().await {
                    Ok(msg) => {
                        let cmd = String::from_utf8_lossy(&msg[28..32]);
                        if cmd == "lbrt" {
                            continue;
                        }
                        Err(Error::other(format!(
                            "unexpected handshake success: {cmd}"
                        )))
                    }
                    Err(_) => Ok(()),
                };
            }
        }
    }
}
