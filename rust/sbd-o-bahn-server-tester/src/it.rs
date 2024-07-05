use std::future::Future;
use std::io::{Error, Result};

use crate::Report;

macro_rules! expect {
    ($cond:expr, $note:expr) => {
        if !$cond {
            return Err(::std::io::Error::other(
                format!(
                    "{}:{}: failed: {}",
                    file!(),
                    line!(),
                    $note,
                )
            ));
        }
    };
}

/// Utilities for helping with the test.
pub struct TestHelper<'h> {
    server: &'h mut crate::Server,
    addr_list: Vec<String>,
    err_list: Vec<String>,
    report: Report,
}

impl<'h> TestHelper<'h> {
    fn new(server: &'h mut crate::Server) -> Self {
        Self {
            server,
            addr_list: Vec::new(),
            err_list: Vec::new(),
            report: Report::default(),
        }
    }

    pub async fn start(&mut self) {
        self.addr_list = self.server.start().await;
        println!("GOT RUNNING ADDRS: {:?}", self.addr_list);
    }

    fn into_report(self) -> Report {
        self.report
    }

    /// connect a client
    pub async fn connect_client(
        &self,
    ) -> Result<(sbd_client::SbdClient, sbd_client::MsgRecv)> {
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

    /// connect a raw client
    pub async fn connect_raw_client(
        &self,
        path: String,
        max_message_size: usize,
        headers: Vec<(String, String)>,
    ) -> Result<(sbd_client::raw_client::WsRawSend, sbd_client::raw_client::WsRawRecv)> {
        for addr in self.addr_list.iter() {
            if let Ok(client) = (sbd_client::raw_client::WsRawConnect {
                full_url: format!("ws://{addr}/{path}"),
                max_message_size,
                allow_plain_text: true,
                danger_disable_certificate_check: false,
                headers: headers.clone(),
            }).connect().await {
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
pub mod it_2;

/// Execute the full test suite.
pub async fn exec_all(server: &mut crate::Server) -> Report {
    let mut helper = TestHelper::new(server);

    exec_one::<it_1::It1>(&mut helper).await;
    exec_one::<it_2::It2>(&mut helper).await;

    helper.into_report()
}

async fn exec_one<'h, T: It>(
    helper: &mut TestHelper<'h>,
) {
    println!("-- RUNNING TEST {} --", T::NAME);

    helper.start().await;

    helper.err_list.clear();
    match T::exec(helper).await {
        Ok(_) => {
            println!("passed");
            helper.report.passed.push(T::NAME.to_string());
        }
        Err(err) => {
            println!("{err:?}");
            helper.err_list.push(err.to_string());
            let err = format!("{:?}", helper.err_list);
            helper.err_list.clear();
            helper.report.failed.push((T::NAME.to_string(), err));
        }
    }
}
