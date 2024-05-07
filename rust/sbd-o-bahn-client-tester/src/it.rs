use std::future::Future;
use std::io::{Error, Result};

use crate::{Client, Report};

macro_rules! expect {
    ($h:ident, $cond:expr, $note:literal) => {
        $h.expect(file!(), line!(), $cond, $note)
    };
}

pub struct Conn<'h> {
    client: &'h Client,
    id: u64,
    pk: [u8; 32],
    r: tokio::sync::Mutex<
        tokio::sync::mpsc::UnboundedReceiver<([u8; 32], Vec<u8>)>,
    >,
}

impl Conn<'_> {
    pub fn pub_key(&self) -> &[u8; 32] {
        &self.pk
    }

    pub async fn recv(&self) -> Option<([u8; 32], Vec<u8>)> {
        self.r.lock().await.recv().await
    }

    pub async fn send(&self, pk: &[u8; 32], msg: &[u8]) {
        self.client.send(self.id, pk, msg).await;
    }
}

/// Utilities for helping with the test.
pub struct TestHelper<'h> {
    client: &'h Client,
    err_list: Vec<String>,
    report: Report,
}

impl<'h> TestHelper<'h> {
    fn new(client: &'h Client) -> Self {
        Self {
            client,
            err_list: Vec::new(),
            report: Report::default(),
        }
    }

    fn into_report(self) -> Report {
        self.report
    }

    /// expect a condition to be true
    pub fn expect(
        &mut self,
        file: &'static str,
        line: u32,
        cond: bool,
        note: &'static str,
    ) {
        if !cond {
            self.err_list.push(format!("{file}:{line}: failed: {note}"));
        }
    }

    pub async fn connect(&self, addrs: &[std::net::SocketAddr]) -> Conn<'h> {
        let (id, pk, r) = self.client.connect(addrs).await;
        Conn {
            client: self.client,
            id,
            pk,
            r: tokio::sync::Mutex::new(r),
        }
    }
}

/// Test definition.
pub trait It {
    const NAME: &'static str;

    fn exec(helper: &mut TestHelper) -> impl Future<Output = Result<()>>;
}

pub mod it_1;

/// Execute the full test suite.
pub async fn exec_all(client: &mut Client) -> Report {
    let mut helper = TestHelper::new(client);

    exec_one::<it_1::It1>(&mut helper).await;

    helper.into_report()
}

async fn exec_one<'h, T: It>(helper: &mut TestHelper<'h>) {
    helper.err_list.clear();
    match T::exec(helper).await {
        Ok(_) => {
            helper.report.passed.push(T::NAME.to_string());
        }
        Err(err) => {
            helper.err_list.push(err.to_string());
            let err = format!("{:?}", helper.err_list);
            helper.err_list.clear();
            helper.report.failed.push((T::NAME.to_string(), err));
        }
    }
}
