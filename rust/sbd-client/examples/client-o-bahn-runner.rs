use sbd_client::*;
use std::collections::{HashMap, VecDeque};

enum ConCmd {
    Close,
    Send(PubKey, Vec<u8>),
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    println!("CMD/READY");

    let mut lines = tokio::io::AsyncBufReadExt::lines(
        tokio::io::BufReader::new(tokio::io::stdin()),
    );

    let mut con_map = HashMap::new();

    while let Ok(Some(line)) = lines.next_line().await {
        let mut parts = line.split("/").collect::<VecDeque<_>>();
        if parts.pop_front().unwrap() != "CMD" {
            panic!();
        }
        match parts.pop_front().unwrap() {
            "CONNECT" => {
                let id: usize = parts.pop_front().unwrap().parse().unwrap();
                let (s, r) = tokio::sync::mpsc::unbounded_channel();
                con_map.insert(id, s);
                tokio::task::spawn(spawn_con(
                    id,
                    r,
                    parts.into_iter().map(|s| s.to_string()).collect(),
                ));
            }
            "SEND" => {
                let id: usize = parts.pop_front().unwrap().parse().unwrap();
                let pk = hex::decode(parts.pop_front().unwrap()).unwrap();
                let msg = hex::decode(parts.pop_front().unwrap()).unwrap();
                if let Some(s) = con_map.get(&id) {
                    let _ = s.send(ConCmd::Send(
                        PubKey(std::sync::Arc::new(pk.try_into().unwrap())),
                        msg,
                    ));
                }
            }
            "CLOSE" => {
                let id: usize = parts.pop_front().unwrap().parse().unwrap();
                if let Some(s) = con_map.get(&id) {
                    let _ = s.send(ConCmd::Close);
                }
            }
            oth => panic!("unhandled: {oth}"),
        }
    }
}

async fn connect(addrs: &[String]) -> (SbdClient, PubKey, MsgRecv) {
    for addr in addrs {
        if let Ok(c) = SbdClient::connect_config(
            &format!("ws://{addr}"),
            &DefaultCrypto::default(),
            SbdClientConfig {
                allow_plain_text: true,
                ..Default::default()
            },
        )
        .await
        {
            let pk = c.0.pub_key().clone();
            return (c.0, pk, c.1);
        }
    }
    panic!()
}

async fn spawn_con(
    id: usize,
    mut r: tokio::sync::mpsc::UnboundedReceiver<ConCmd>,
    addrs: Vec<String>,
) {
    let (cli, pk, mut rcv) = connect(addrs.as_slice()).await;
    tokio::task::spawn(async move {
        while let Some(data) = rcv.recv().await {
            println!(
                "CMD/RECV/{id}/{}/{}",
                hex::encode(data.pub_key_ref()),
                hex::encode(data.message()),
            );
        }
        println!("CMD/CLOSE/{id}");
    });
    println!("CMD/CONNECT/{id}/{}", hex::encode(&pk[..]));
    while let Some(cmd) = r.recv().await {
        match cmd {
            ConCmd::Close => break,
            ConCmd::Send(dest, msg) => {
                if cli.send(&dest, &msg).await.is_err() {
                    break;
                }
            }
        }
    }
    cli.close().await;
}
