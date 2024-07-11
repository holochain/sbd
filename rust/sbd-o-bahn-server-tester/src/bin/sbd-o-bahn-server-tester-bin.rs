#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let mut args = std::env::args_os().collect::<Vec<_>>();
    // remove the "self" arg
    args.remove(0);
    let result = sbd_o_bahn_server_tester::run(args).await;
    println!("-- TEST RESULTS --\n{result:#?}");
    if !result.failed.is_empty() {
        eprintln!("TEST FAILED");
        std::process::exit(127);
    }
}
