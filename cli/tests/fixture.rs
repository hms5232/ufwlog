//! Test depend on fixture
//! Don't forget that clear output file after test

use assert_cmd::Command;

#[test]
/// Test use ufw.log as input, and expect ufwlog.csv as output
fn ufw_log() {
    let mut cmd = Command::cargo_bin("ufwlog").unwrap();
    let current_path = std::env::current_dir().unwrap();
    let log_path = current_path.join("tests").join("fixtures").join("ufw.log");
    let expect_path = current_path
        .join("tests")
        .join("fixtures")
        .join("ufwlog.csv");
    let output_path = current_path.join("tests").join("test_ufw.log_output");

    cmd.arg("export");
    cmd.args(["-l", log_path.to_str().unwrap()]);
    cmd.args(["-o", output_path.to_str().unwrap()]);
    cmd.assert().success();
    // check content
    let expect = std::fs::read_to_string(expect_path).unwrap();
    let output = std::fs::read_to_string(&output_path).unwrap();
    assert_eq!(expect, output);

    // teardown
    std::fs::remove_file(output_path).unwrap(); // remove output file
}
