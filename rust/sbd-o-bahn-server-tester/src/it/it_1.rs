use super::*;

/// test 1
pub struct It1;

impl It for It1 {
    const NAME: &'static str = "sanity";

    fn exec(helper: &mut TestHelper) -> impl Future<Output = Result<()>> {
        async {
            let ((c1, _u1, p1, mut r1), (c2, _u2, p2, mut r2)) = tokio::try_join!(
                helper.connect_client(),
                helper.connect_client(),
            )?;

            tokio::try_join!(c1.send(&p2, b"hello"), c2.send(&p1, b"world"),)?;

            let (result1, result2) = tokio::try_join!(
                async { r1.recv().await.ok_or(Error::other("closed")) },
                async { r2.recv().await.ok_or(Error::other("closed")) },
            )?;

            expect!(
                helper,
                result1.pub_key_ref() == &p2[..],
                "r1 recv from p2"
            );
            expect!(helper, result1.message() == b"world", "r1 got 'world'");
            expect!(
                helper,
                result2.pub_key_ref() == &p1[..],
                "r2 recv from p1"
            );
            expect!(helper, result2.message() == b"hello", "r2 got 'hello'");

            Ok(())
        }
    }
}
