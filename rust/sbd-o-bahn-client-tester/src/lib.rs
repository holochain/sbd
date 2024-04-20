#![deny(missing_docs)]
// uhhh... clippy...
#![allow(clippy::manual_async_fn)]

//! Test suite for sbd client compliance.
//!
//! The command supplied to the run function must:
//! - Print on stdout: `CMD/READY` when it is ready to receive commands.
//! - Listen on stdin for:
//!   - `CMD/CONNECT/id/<addr-list>` where id is a numeric identifier,
//!     addr-list is a slash separated list of addresses (ip:port)
//!     e.g. `CMD/CONNECT/42/127.0.0.1:44556/[::1]:44557`.
//!   - `CMD/SEND/id/<pubkey>/<msg-hex>` where msg-hex is hex encoded bytes to
//!     be sent to the hex encoded pubkey.
//!   - `CMD/CLOSE/id/<pubkey>` close the connection and print a response close
//! - Write to stdout:
//!   - `CMD/CONNECT/<pubkey>` where pubkey is a hex encoded
//!     pubkey of the client that was connected.
//!   - `CMD/RECV/id/<pubkey>/<msg-hex>` where msg-hex is hex encoded bytes
//!     received from the remote hex encoded pubkey peer.
//!   - `CMD/CLOSE/id/<pubkey>` if the connection closes (including when
//!     the listen close command was called).

use std::collections::HashMap;
use std::io::Result;
use tokio::io::AsyncBufReadExt;

mod it;

/// Results of the test suite run.
#[derive(Debug, Default)]
pub struct Report {
    /// The names of tests that pass.
    pub passed: Vec<String>,

    /// Failed tests: (Name, Notes).
    pub failed: Vec<(String, String)>,
}

/// Run the test suite.
pub async fn run<S: AsRef<std::ffi::OsStr>>(cmd: S) -> Report {
    let mut client = Client::spawn(cmd).await.unwrap();

    it::exec_all(&mut client).await
}

enum ReadTask {
    Client(
        u64,
        #[allow(clippy::type_complexity)]
        tokio::sync::oneshot::Sender<(
            [u8; 32],
            tokio::sync::mpsc::UnboundedReceiver<([u8; 32], Vec<u8>)>,
        )>,
    ),
    Line(String),
}

struct Client {
    _child: tokio::process::Child,
    stdin: tokio::sync::Mutex<tokio::process::ChildStdin>,
    sender: tokio::sync::mpsc::UnboundedSender<ReadTask>,
}

impl Client {
    pub async fn spawn<S: AsRef<std::ffi::OsStr>>(cmd: S) -> Result<Self> {
        let mut cmd = tokio::process::Command::new(cmd);
        cmd.kill_on_drop(true)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped());

        println!("RUNNING {cmd:?}");
        let mut child = cmd.spawn()?;
        let stdin = child.stdin.take().unwrap();

        let mut stdout =
            tokio::io::BufReader::new(child.stdout.take().unwrap()).lines();

        if let Some(line) = stdout.next_line().await? {
            if line != "CMD/READY" {
                panic!("unexpected: {line}");
            }
        } else {
            panic!("no stdout");
        }

        let (s, mut r) = tokio::sync::mpsc::unbounded_channel();

        {
            let s = s.clone();
            tokio::task::spawn(async move {
                while let Ok(Some(line)) = stdout.next_line().await {
                    if s.send(ReadTask::Line(line)).is_err() {
                        break;
                    }
                }
            });
        }

        tokio::task::spawn(async move {
            let mut pre_connect_map = HashMap::new();
            let mut con_map = HashMap::new();
            while let Some(r) = r.recv().await {
                match r {
                    ReadTask::Client(id, s) => {
                        pre_connect_map.insert(id, s);
                    }
                    ReadTask::Line(line) => {
                        let parts = line.split('/').collect::<Vec<_>>();
                        if parts[0] != "CMD" {
                            panic!();
                        }
                        match parts[1] {
                            "CONNECT" => {
                                let id: u64 = parts[2].parse().unwrap();
                                let pk = hex::decode(parts[3]).unwrap();
                                if let Some(s) = pre_connect_map.remove(&id) {
                                    let (ms, mr) =
                                        tokio::sync::mpsc::unbounded_channel();
                                    con_map.insert(id, ms);
                                    let _ =
                                        s.send((pk.try_into().unwrap(), mr));
                                }
                            }
                            "RECV" => {
                                let id: u64 = parts[2].parse().unwrap();
                                let pk = hex::decode(parts[3]).unwrap();
                                let msg = hex::decode(parts[4]).unwrap();
                                if let Some(s) = con_map.get(&id) {
                                    let _ =
                                        s.send((pk.try_into().unwrap(), msg));
                                }
                            }
                            "CLOSE" => {
                                let id: u64 = parts[2].parse().unwrap();
                                con_map.remove(&id);
                            }
                            oth => panic!("unhandled: {oth}"),
                        }
                    }
                }
            }
        });

        println!("GOT CMD/READY");

        Ok(Self {
            _child: child,
            stdin: tokio::sync::Mutex::new(stdin),
            sender: s,
        })
    }

    pub async fn connect(
        &self,
        addrs: &[std::net::SocketAddr],
    ) -> (
        u64,
        [u8; 32],
        tokio::sync::mpsc::UnboundedReceiver<([u8; 32], Vec<u8>)>,
    ) {
        use tokio::io::AsyncWriteExt;
        static ID: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(1);
        let id = ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut msg = format!("CMD/CONNECT/{id}");
        for addr in addrs {
            msg.push_str(&format!("/{addr}"));
        }
        msg.push('\n');

        let (s, r) = tokio::sync::oneshot::channel();
        self.sender.send(ReadTask::Client(id, s)).unwrap();

        {
            let mut lock = self.stdin.lock().await;
            lock.write_all(&msg.into_bytes()).await.unwrap();
            lock.flush().await.unwrap();
        }

        let (pk, r) = r.await.unwrap();
        (id, pk, r)
    }

    pub async fn send(&self, id: u64, pk: &[u8], msg: &[u8]) {
        use tokio::io::AsyncWriteExt;
        let msg = format!(
            "CMD/SEND/{id}/{}/{}\n",
            hex::encode(pk),
            hex::encode(msg),
        )
        .into_bytes();
        let mut lock = self.stdin.lock().await;
        lock.write_all(&msg).await.unwrap();
        lock.flush().await.unwrap();
    }
}
