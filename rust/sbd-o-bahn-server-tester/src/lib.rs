#![deny(missing_docs)]
// uhhh... clippy...
#![allow(clippy::manual_async_fn)]

//! Test suite for sbd server compliance.
//!
//! The command supplied to the run function must:
//! - Print on stdout: `CMD:READY` when it is ready to receive commands.
//! - Listen on stdin for: `CMD:START`, and on receiving, close any running
//!   sbd servers, start a new one on a random ephemeral port (plain text,
//!   not TLS), then print out `CMD:START:<addr-list>` where addr-list is
//!   a json representation of an array of addresses (ip:port) e.g.
//!   `CMD:START:["127.0.0.1:44556", "[::1]:44557"]`.

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
    let mut server = Server::spawn(cmd).await.unwrap();
    let addrs = server.start().await;

    println!("GOT RUNNING ADDRS: {addrs:?}");

    it::exec_all(&addrs).await
}

struct Server {
    _child: tokio::process::Child,
    stdin: tokio::process::ChildStdin,
    stdout: tokio::io::Lines<tokio::io::BufReader<tokio::process::ChildStdout>>,
}

impl Server {
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

        println!("GOT CMD/READY");

        Ok(Self {
            _child: child,
            stdin,
            stdout,
        })
    }

    pub async fn start(&mut self) -> Vec<String> {
        use tokio::io::AsyncWriteExt;
        self.stdin.write_all(b"CMD/START\n").await.unwrap();
        self.stdin.flush().await.unwrap();
        let line = self.stdout.next_line().await.unwrap().unwrap();
        if !line.starts_with("CMD/START/") {
            panic!("unexpected: {line}");
        }
        line.split('/').skip(2).map(|s| s.to_string()).collect()
    }
}
