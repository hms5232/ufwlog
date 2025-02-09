use assert_cmd::Command;

#[test]
fn run_without_args_should_show_help_info() {
    let mut cmd = Command::cargo_bin("ufwlog").unwrap();
    cmd.assert().success();
    let output = String::from_utf8(cmd.output().unwrap().stdout).unwrap();
    // assert help information
    assert!(output.contains("ufwlog")); // binary name
    assert!(output.contains("export")); // subcommand
    assert!(output.contains("completion")); // subcommand
    assert!(output.contains("help"));
}
