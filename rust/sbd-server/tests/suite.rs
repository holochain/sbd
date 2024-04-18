#[test]
fn suite() {
    println!("BUILDING example test-suite-runner IN RELEASE MODE");
    let server = escargot::CargoBuild::new()
        .example("test-suite-runner")
        .release()
        .current_target()
        .run()
        .unwrap();

    println!("BUILDING sbd-server-test-suite IN RELEASE MODE");
    let suite = escargot::CargoBuild::new()
        .bin("sbd-server-test-suite-bin")
        .manifest_path("../sbd-server-test-suite/Cargo.toml")
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
