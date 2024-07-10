use super::*;
use std::sync::Arc;

const COUNT: usize = 10;

/// test 7
pub struct It7;

impl It for It7 {
    const NAME: &'static str = "7-order-stress";
    const DESC: &'static str =
        "multi-client echo stress test ensure messages are delivered in order";

    fn exec(helper: &mut TestHelper) -> impl Future<Output = Result<()>> {
        async {
            let (c, mut r) = helper.connect_client().await?;
            let p = c.pub_key().clone();

            let mut tasks = Vec::new();

            let b = Arc::new(tokio::sync::Barrier::new(COUNT));

            for _ in 0..COUNT {
                let p = p.clone();
                let b = b.clone();
                let (c, mut r) = helper.connect_client().await?;
                tasks.push(tokio::task::spawn(async move {
                    c.send(&p, b"a").await?;

                    let m =
                        r.recv().await.ok_or_else(|| Error::other("closed"))?;

                    if m.message() != b"a" {
                        return Err(Error::other("bad resp"));
                    }

                    b.wait().await;

                    const LIST: &[&[u8]] =
                        &[b"b", b"c", b"d", b"e", b"f", b"g", b"h", b"i", b"j"];

                    for d in LIST {
                        c.send(&p, d).await?;
                    }

                    for d in LIST {
                        let m = r
                            .recv()
                            .await
                            .ok_or_else(|| Error::other("closed"))?;
                        if &m.message() != d {
                            return Err(Error::other("bad resp"));
                        }
                    }

                    Ok(())
                }));
            }

            let mut count = 0;

            loop {
                count += 1;

                let msg =
                    r.recv().await.ok_or_else(|| Error::other("closed"))?;

                c.send(&msg.pub_key(), msg.message()).await?;

                if count >= COUNT * 10 {
                    break;
                }
            }

            for task in tasks {
                task.await??;
            }

            Ok(())
        }
    }
}
