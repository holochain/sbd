use super::*;
use sbd_server::*;
use std::sync::Arc;

/// test 1
pub struct It1;

impl It for It1 {
    const NAME: &'static str = "sanity";

    fn exec(helper: &mut TestHelper) -> impl Future<Output = Result<()>> {
        async {
            let server = SbdServer::new(Arc::new(Config {
                bind: vec!["127.0.0.1:0".to_string(), "[::1]:0".to_string()],
                limit_clients: 100,
                ..Default::default()
            }))
            .await?;

            let (c1, c2) = tokio::join!(
                helper.connect(server.bind_addrs()),
                helper.connect(server.bind_addrs()),
            );

            tokio::join!(
                c1.send(c2.pub_key(), b"hello"),
                c2.send(c1.pub_key(), b"world"),
            );

            let (r1, r2) = tokio::join!(c1.recv(), c2.recv());
            let r1 = r1.ok_or(Error::other("closed"))?;
            let r2 = r2.ok_or(Error::other("closed"))?;

            expect!(helper, &r1.0 == c2.pub_key(), "recv from r2");
            expect!(helper, r1.1 == b"world", "recv from r2");
            expect!(helper, &r2.0 == c1.pub_key(), "recv from r2");
            expect!(helper, r1.1 == b"hello", "recv from r2");

            Ok(())
        }
    }
}
