#[test]
fn suite() {
    println!("BUILDING example test-suite-runner IN RELEASE MODE");
    let server = escargot::CargoBuild::new()
        .example("server-o-bahn-runner")
        .release()
        .current_target()
        .run()
        .unwrap();

    println!("BUILDING sbd-server-test-suite IN RELEASE MODE");
    let suite = escargot::CargoBuild::new()
        .bin("sbd-o-bahn-server-tester-bin")
        .manifest_path("../sbd-o-bahn-server-tester/Cargo.toml")
        .release()
        .current_target()
        .run()
        .unwrap();

    println!("RUNNING the test suite {:?}", suite.path());
    let result = suite.command().arg(server.path()).status();

    match result {
        Ok(status) if status.success() => (),
        _ => std::process::exit(127),
    }
}
