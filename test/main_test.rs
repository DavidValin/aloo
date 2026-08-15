//! Exercises the compiled `aloo` binary directly (`src/main.rs`'s CLI),
//! since it has no library target of its own to unit-test against.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_aloo")
}

// tiny non-cryptographic unique suffix so parallel test runs don't collide
fn fastrand_seed() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
}

/// A throwaway `$HOME` so a spawned `--server` process's settings
/// persistence (`main.rs::run_server`) writes under a private temp
/// directory instead of the real developer/CI machine's `~/.aloo/settings`.
fn temp_home(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("aloo-main-test-{tag}-{}-{}", std::process::id(), fastrand_seed()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Spawns the server with the given args under `home` as `$HOME`, reads its
/// one-line startup announcement, then kills it - mirrors
/// `server_bind_and_port_flags_are_parsed_into_the_listen_address`'s
/// approach: the startup line is printed before the actual bind, so reading
/// it only waits on process/pipe startup, not any network I/O.
fn spawn_server_and_read_startup_line(home: &std::path::Path, args: &[&str]) -> String {
    let mut child = Command::new(bin())
        .args(args)
        .env("HOME", home)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn server");

    let stdout = child.stdout.take().expect("stdout");
    let mut line = String::new();
    BufReader::new(stdout).read_line(&mut line).expect("read startup line");

    let _ = child.kill();
    let _ = child.wait();
    line.trim().to_string()
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
    let home = temp_home("bind-port");
    let line = spawn_server_and_read_startup_line(&home, &["--server", "--bind", "127.0.0.1", "--port", "0"]);
    assert_eq!(line, "aloo: server listening on 127.0.0.1:0");
    std::fs::remove_dir_all(&home).ok();
}

/// @requirement AC-094
#[test]
fn server_with_no_flags_reuses_the_previously_persisted_bind_and_port() {
    let home = temp_home("reuse-bind-port");

    let first = spawn_server_and_read_startup_line(&home, &["--server", "--bind", "127.0.0.2", "--port", "0"]);
    assert_eq!(first, "aloo: server listening on 127.0.0.2:0");

    // No --bind/--port this time - should come back exactly the same,
    // reloaded from ~/.aloo/settings rather than the CLI defaults.
    let second = spawn_server_and_read_startup_line(&home, &["--server"]);
    assert_eq!(second, "aloo: server listening on 127.0.0.2:0");

    std::fs::remove_dir_all(&home).ok();
}

/// @requirement TB-139
#[test]
fn an_explicit_flag_overrides_and_persists_over_a_previous_value() {
    let home = temp_home("override-bind");

    let first = spawn_server_and_read_startup_line(&home, &["--server", "--bind", "127.0.0.2", "--port", "0"]);
    assert_eq!(first, "aloo: server listening on 127.0.0.2:0");

    // Only --bind is passed this time; --port is omitted, so it should
    // still fall back to what was persisted (0), not the CLI default (7878).
    let second = spawn_server_and_read_startup_line(&home, &["--server", "--bind", "127.0.0.3"]);
    assert_eq!(second, "aloo: server listening on 127.0.0.3:0");

    // And now that the override has itself been persisted, a flag-less run
    // picks up 127.0.0.3, not the original 127.0.0.2.
    let third = spawn_server_and_read_startup_line(&home, &["--server"]);
    assert_eq!(third, "aloo: server listening on 127.0.0.3:0");

    std::fs::remove_dir_all(&home).ok();
}

/// @requirement AC-094
#[test]
fn server_with_no_flags_reuses_previously_persisted_password_auth() {
    let home = temp_home("reuse-password");

    let _ = spawn_server_and_read_startup_line(&home, &["--server", "--password", "MYPASSWORD"]);

    let settings_path = home.join(".aloo").join("settings");
    let contents = std::fs::read_to_string(&settings_path).expect("server should have written ~/.aloo/settings");
    assert!(contents.contains("server_auth_type=password"));
    assert!(contents.contains("server_auth_password=MYPASSWORD"));

    // Starting again with no --password/--enc must not silently drop back
    // to open access.
    let _ = spawn_server_and_read_startup_line(&home, &["--server"]);
    let contents_after = std::fs::read_to_string(&settings_path).unwrap();
    assert!(contents_after.contains("server_auth_type=password"));
    assert!(contents_after.contains("server_auth_password=MYPASSWORD"));

    std::fs::remove_dir_all(&home).ok();
}
