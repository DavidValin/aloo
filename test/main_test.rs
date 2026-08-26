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
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

/// A throwaway `$HOME` so a spawned `--server` process's settings
/// persistence (`main.rs::run_server`) writes under a private temp
/// directory instead of the real developer/CI machine's `~/.aloo/settings`.
fn temp_home(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aloo-main-test-{tag}-{}-{}",
        std::process::id(),
        fastrand_seed()
    ));
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
    BufReader::new(stdout)
        .read_line(&mut line)
        .expect("read startup line");

    let _ = child.kill();
    let _ = child.wait();
    line.trim().to_string()
}

/// @requirement TB-114
#[test]
fn help_advertises_the_documented_bind_and_port_defaults() {
    let output = Command::new(bin())
        .arg("--help")
        .output()
        .expect("run --help");
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("0.0.0.0"),
        "expected the default --bind address in --help output:\n{text}"
    );
    assert!(
        text.contains("7878"),
        "expected the default --port in --help output:\n{text}"
    );
}

/// @requirement TB-266
#[test]
fn help_groups_flags_under_client_commands_before_server_commands() {
    let output = Command::new(bin())
        .arg("--help")
        .output()
        .expect("run --help");
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    let client_pos = text
        .find("Client Commands:")
        .expect("expected a 'Client Commands:' heading in --help output");
    let server_pos = text
        .find("Server Commands:")
        .expect("expected a 'Server Commands:' heading in --help output");
    assert!(
        client_pos < server_pos,
        "Client Commands must be listed before Server Commands:\n{text}"
    );
    let client_section = &text[client_pos..server_pos];
    let server_section = &text[server_pos..];
    for flag in ["--daemon", "--host", "--nick", "--export-identity-card"] {
        assert!(
            client_section.contains(flag),
            "expected {flag} under Client Commands:\n{text}"
        );
    }
    for flag in ["--server", "--bind", "--register-user", "--change-password"] {
        assert!(
            server_section.contains(flag),
            "expected {flag} under Server Commands:\n{text}"
        );
    }
}

/// @requirement TB-114
#[test]
fn server_bind_and_port_flags_are_parsed_into_the_listen_address() {
    let home = temp_home("bind-port");
    let line = spawn_server_and_read_startup_line(
        &home,
        &["--server", "--bind", "127.0.0.1", "--port", "0"],
    );
    assert_eq!(line, "aloo: server listening on 127.0.0.1:0");
    std::fs::remove_dir_all(&home).ok();
}

/// @requirement AC-094
#[test]
fn server_with_no_flags_reuses_the_previously_persisted_bind_and_port() {
    let home = temp_home("reuse-bind-port");

    let first = spawn_server_and_read_startup_line(
        &home,
        &["--server", "--bind", "127.0.0.2", "--port", "0"],
    );
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

    let first = spawn_server_and_read_startup_line(
        &home,
        &["--server", "--bind", "127.0.0.2", "--port", "0"],
    );
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

/// The server's own settings keys are in the file from the first start,
/// so an operator finds `server_ssl`, `server_allow_registration` and the
/// SMTP keys already named - and a later flag-less start keeps them.
/// @requirement AC-094
#[test]
fn server_start_writes_the_ssl_and_registration_keys_and_keeps_them() {
    let home = temp_home("server-keys");

    let _ = spawn_server_and_read_startup_line(&home, &["--server", "--port", "17881"]);

    let settings_path = home.join(".aloo").join("settings");
    let contents = std::fs::read_to_string(&settings_path)
        .expect("server should have written ~/.aloo/settings");
    for key in [
        "server_ssl=off",
        "server_ssl_fullchain=~/.aloo/certs/fullchain.pem",
        "server_ssl_privkey=~/.aloo/certs/privkey.pem",
        "server_allow_registration=off",
        "server_smtp_host=",
        "server_smtp_port=",
        "server_smtp_username=",
        "server_smtp_password=",
    ] {
        assert!(contents.contains(key), "missing {key} in:\n{contents}");
    }

    // An operator's hand edit survives the next flag-less start, which
    // only rewrites bind/port.
    let edited = contents.replace("server_smtp_host=", "server_smtp_host=smtp.example.com");
    std::fs::write(&settings_path, edited).unwrap();
    let _ = spawn_server_and_read_startup_line(&home, &["--server"]);
    let contents_after = std::fs::read_to_string(&settings_path).unwrap();
    assert!(contents_after.contains("server_smtp_host=smtp.example.com"));
    assert!(contents_after.contains("server_port=17881"));

    std::fs::remove_dir_all(&home).ok();
}

/// `server_ssl=on` with no certificate refuses to start rather than
/// serving plaintext behind the operator's back.
/// @requirement AC-262
#[test]
fn server_ssl_on_without_a_certificate_refuses_to_start() {
    let home = temp_home("ssl-missing");
    let settings_dir = home.join(".aloo");
    std::fs::create_dir_all(&settings_dir).unwrap();
    std::fs::write(
        settings_dir.join("settings"),
        "server_ssl=on\nserver_ssl_fullchain=~/.aloo/certs/fullchain.pem\nserver_ssl_privkey=~/.aloo/certs/privkey.pem\n",
    )
    .unwrap();

    let output = Command::new(bin())
        .args(["--server", "--port", "17882"])
        .env("HOME", &home)
        .output()
        .expect("run server");
    assert!(!output.status.success(), "must refuse to start");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("server_ssl") && stderr.contains("fullchain.pem"),
        "the refusal names the setting and the missing file: {stderr}"
    );

    std::fs::remove_dir_all(&home).ok();
}

/// `--register-user` and `--change-password` edit `~/.aloo/users` in
/// place: an account appears active with no email and no activation
/// file, a second registration of the name is refused, and the password
/// change rewrites the stored key.
/// @requirement AC-267
#[test]
fn register_user_and_change_password_edit_the_users_registry_directly() {
    let home = temp_home("registry-cli");

    let output = Command::new(bin())
        .args(["--register-user", "alice", "first-pw"])
        .env("HOME", &home)
        .output()
        .expect("run register");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let user_dir = home.join(".aloo").join("users").join("alice");
    let key_before = std::fs::read_to_string(user_dir.join("key")).expect("key file written");
    assert!(!user_dir.join("email.txt").exists(), "manual registration has no email");
    assert!(
        !std::fs::read_dir(&user_dir)
            .unwrap()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().ends_with("_activate.txt")),
        "manual registration needs no activation"
    );

    let output = Command::new(bin())
        .args(["--register-user", "alice", "again"])
        .env("HOME", &home)
        .output()
        .expect("run register twice");
    assert!(!output.status.success(), "an existing nickname is refused");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("already registered"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let output = Command::new(bin())
        .args(["--change-password", "alice", "second-pw"])
        .env("HOME", &home)
        .output()
        .expect("run change-password");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let key_after = std::fs::read_to_string(user_dir.join("key")).unwrap();
    assert_ne!(key_before, key_after, "the stored key changes with the password");

    let output = Command::new(bin())
        .args(["--change-password", "nobody", "x"])
        .env("HOME", &home)
        .output()
        .expect("run change-password on a stranger");
    assert!(!output.status.success(), "a name nobody registered is refused");

    std::fs::remove_dir_all(&home).ok();
}
