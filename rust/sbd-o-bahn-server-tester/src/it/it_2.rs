use super::*;

/// test 2
pub struct It2;

impl It for It2 {
    const NAME: &'static str = "2-bad-pubkey-path";
    const DESC: &'static str =
        "connection is dropped if url path is not a valid pubkey";

    fn exec(helper: &mut TestHelper) -> impl Future<Output = Result<()>> {
        async {
            let (_send, mut recv) = match helper
                .connect_raw_client(
                    "bad-pubkey-path".to_string(),
                    20_000,
                    vec![],
                )
                .await
            {
                Ok(r) => r,
                Err(_) => return Ok(()),
            };

            let err = match recv.recv().await {
                Ok(_) => {
                    return Err(Error::other("unexpected connect success"))
                }
                Err(err) => err.to_string(),
            };

            let msg = format!("expected 'Connection reset', but got: {err}");

            expect!(err.contains("Connection reset"), &msg);

            Ok(())
        }
    }
}
