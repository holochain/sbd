use std::future::Future;
use std::io::{Error, Result};

use crate::Report;

macro_rules! expect {
    ($h:ident, $cond:expr, $note:literal) => {
        $h.expect(file!(), line!(), $cond, $note)
    };
}

/// Utilities for helping with the test.
pub struct TestHelper<'h> {
    addr_list: &'h [String],
    err_list: Vec<String>,
    report: Report,
}

impl<'h> TestHelper<'h> {
    fn new(addr_list: &'h [String]) -> Self {
        Self {
            addr_list,
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

    /// connect a client
    pub async fn connect_client(
        &self,
    ) -> Result<(
        sbd_client::SbdClient,
        String,
        sbd_client::PubKey,
        sbd_client::MsgRecv,
    )> {
        for addr in self.addr_list.iter() {
            if let Ok(client) = sbd_client::SbdClient::connect_config(
                &format!("ws://{addr}"),
                &sbd_client::DefaultCrypto::default(),
                sbd_client::SbdClientConfig {
                    allow_plain_text: true,
                    ..Default::default()
                },
            )
            .await
            {
                return Ok(client);
            }
        }
        Err(Error::other("could not connect to server"))
    }
}

/// Test definition.
pub trait It {
    const NAME: &'static str;

    fn exec(helper: &mut TestHelper) -> impl Future<Output = Result<()>>;
}

pub mod it_1;

/// Execute the full test suite.
pub async fn exec_all(addr_list: &[String]) -> Report {
    let mut helper = TestHelper::new(addr_list);

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
