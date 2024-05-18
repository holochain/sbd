#[tokio::main(flavor = "multi_thread")]
async fn main() {
    sbd_bench::c_count_scale(usize::MAX).await;
}
