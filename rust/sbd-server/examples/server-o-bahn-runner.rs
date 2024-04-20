use std::sync::Arc;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    println!("CMD:READY");

    let mut lines = tokio::io::AsyncBufReadExt::lines(
        tokio::io::BufReader::new(tokio::io::stdin()),
    );

    let mut server = None;

    while let Ok(Some(line)) = lines.next_line().await {
        match line.as_str() {
            "CMD:START" => {
                drop(server);
                let mut config = sbd_server::Config::default();
                config.bind.push("127.0.0.1:0".to_string());
                config.bind.push("[::1]:0".to_string());
                server = Some(
                    sbd_server::SbdServer::new(Arc::new(config)).await.unwrap(),
                );
                println!(
                    "CMD:START:{}",
                    serde_json::to_string(
                        server.as_ref().unwrap().bind_addrs()
                    )
                    .unwrap()
                );
            }
            oth => panic!("error, unexpected: {oth}"),
        }
    }
}
