#[test]
fn suite() {
    println!("BUILDING example test-suite-runner IN RELEASE MODE");
    let server = escargot::CargoBuild::new()
        .example("client-o-bahn-runner")
        .release()
        .current_target()
        .run()
        .unwrap();

    println!("BUILDING sbd-server-test-suite IN RELEASE MODE");
    let suite = escargot::CargoBuild::new()
        .bin("sbd-o-bahn-client-tester-bin")
        .manifest_path("../sbd-o-bahn-client-tester/Cargo.toml")
        .release()
        .current_target()
        .run()
        .unwrap();

    println!("RUNNING the test suite {:?}", suite.path());
    assert!(suite
        .command()
        .arg(server.path())
        .status()
        .unwrap()
        .success());
}
