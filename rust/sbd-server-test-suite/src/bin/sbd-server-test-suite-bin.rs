#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let mut args = std::env::args_os();
    args.next().unwrap();
    let result = sbd_server_test_suite::run(
        args.next().expect("Expected Sbd Server Suite Runner"),
    )
    .await;
    println!("{result:#?}");
    if !result.failed.is_empty() {
        panic!("TEST FAILED");
    }
}
