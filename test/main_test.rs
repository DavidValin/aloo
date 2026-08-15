//! Exercises the compiled `aloo` binary directly (`src/main.rs`'s CLI),
//! since it has no library target of its own to unit-test against.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_aloo")
}

/// @requirement TB-114
#[test]
fn help_advertises_the_documented_bind_and_port_defaults() {
    let output = Command::new(bin()).arg("--help").output().expect("run --help");
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("0.0.0.0"), "expected the default --bind address in --help output:\n{text}");
    assert!(text.contains("7878"), "expected the default --port in --help output:\n{text}");
}

/// @requirement TB-114
#[test]
fn server_bind_and_port_flags_are_parsed_into_the_listen_address() {
    let mut child = Command::new(bin())
        .args(["--server", "--bind", "127.0.0.1", "--port", "0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn server");

    // The startup line is printed before the actual bind (see main.rs
    // run_server), so reading it only waits on process/pipe startup, not
    // any network I/O.
    let stdout = child.stdout.take().expect("stdout");
    let mut line = String::new();
    BufReader::new(stdout).read_line(&mut line).expect("read startup line");

    let _ = child.kill();
    let _ = child.wait();

    assert_eq!(line.trim(), "aloo: server listening on 127.0.0.1:0");
}
