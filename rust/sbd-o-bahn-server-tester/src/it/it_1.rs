use super::*;

/// test 1
pub struct It1;

impl It for It1 {
    const NAME: &'static str = "1-sanity";
    const DESC: &'static str =
        "two simple nodes are able to send messages to each other";

    fn exec(helper: &mut TestHelper) -> impl Future<Output = Result<()>> {
        async {
            println!("create clients");

            let ((c1, mut r1), (c2, mut r2)) = tokio::try_join!(
                helper.connect_client(),
                helper.connect_client(),
            )?;

            let p1 = c1.pub_key().clone();
            let p2 = c2.pub_key().clone();

            println!("connect clients");
            tokio::try_join!(c1.send(&p2, b"hello"), c2.send(&p1, b"world"))?;

            println!("await results");
            let (result1, result2) = tokio::try_join!(
                async { r1.recv().await.ok_or(Error::other("closed")) },
                async { r2.recv().await.ok_or(Error::other("closed")) },
            )?;

            println!("check results");

            expect!(result1.pub_key_ref() == &p2[..], "r1 recv from p2");
            expect!(result1.message() == b"world", "r1 got 'world'");
            expect!(result2.pub_key_ref() == &p1[..], "r2 recv from p1");
            expect!(result2.message() == b"hello", "r2 got 'hello'");

            Ok(())
        }
    }
}
