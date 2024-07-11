use super::*;
use std::sync::Arc;

const NODE_COUNT: usize = 10;
const MSG_COUNT: usize = 10;

/// test 8
pub struct It8;

impl It for It8 {
    const NAME: &'static str = "8-correct-dest";
    const DESC: &'static str = "multi-client echo stress test ensure messages are only delivered to the correct target";

    fn exec(helper: &mut TestHelper) -> impl Future<Output = Result<()>> {
        async {
            let mut tasks = Vec::new();
            let mut echo_addrs = Vec::new();

            for _ in 0..NODE_COUNT {
                let (c, mut r) = helper.connect_client().await?;
                echo_addrs.push(c.pub_key().clone());
                tasks.push(tokio::task::spawn(async move {
                    for _ in 0..MSG_COUNT {
                        let msg = r
                            .recv()
                            .await
                            .ok_or_else(|| Error::other("closed"))?;

                        c.send(&msg.pub_key(), msg.message()).await?;
                    }

                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

                    Ok(())
                }));
            }

            let b = Arc::new(tokio::sync::Barrier::new(NODE_COUNT));

            for i in 0..NODE_COUNT {
                let p = echo_addrs.remove(0);
                let b = b.clone();
                let (c, mut r) = helper.connect_client().await?;
                tasks.push(tokio::task::spawn(async move {
                    for j in 0..MSG_COUNT {
                        if j == 1 {
                            b.wait().await;
                        }

                        let msg = format!("{i}-{j}");
                        c.send(&p, msg.as_bytes()).await?;

                        let m = r
                            .recv()
                            .await
                            .ok_or_else(|| Error::other("closed"))?;

                        if m.message() != msg.as_bytes() {
                            return Err(Error::other("bad resp"));
                        }
                    }

                    Ok(())
                }));
            }

            for task in tasks {
                task.await??;
            }

            Ok(())
        }
    }
}
