//! Tests for `src/server/users_registry.rs`: account storage, credential
//! checking and activation (docs/PROTOCOL.md §5), independent of any
//! socket.

use aloo::server::users_registry::{
    ACTIVATION_CODE_LEN, ACTIVATION_VALIDITY_SECS, ActivationOutcome, AuthCheck, RegisterError,
    UsersRegistry, activation_code_is_well_formed, activation_email, activation_link,
    derive_user_key, generate_activation_code,
};

fn temp_registry(tag: &str) -> UsersRegistry {
    let dir = std::env::temp_dir().join(format!(
        "aloo-users-registry-test-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    UsersRegistry::open_with_iterations(dir, 10).unwrap()
}

/// @requirement TB-238
#[test]
fn derive_user_key_is_salted_by_nickname_so_the_same_password_differs() {
    let a = derive_user_key("alice", "hunter2");
    let b = derive_user_key("bob", "hunter2");
    assert_ne!(a, b, "the nickname salts the derivation");
    assert_eq!(a, derive_user_key("alice", "hunter2"), "deterministic for the same inputs");
}

/// @requirement AC-267
#[test]
fn register_manual_is_active_immediately_with_no_email_or_activation() {
    let registry = temp_registry("manual");
    registry.register_manual("alice", "hunter2").unwrap();
    assert!(registry.is_registered("alice"));
    assert_eq!(registry.email_of("alice"), None);
    assert!(registry.pending_activation("alice").is_none());
    assert!(matches!(
        registry.check_credentials("alice", "hunter2", 1_000_000),
        AuthCheck::Ok
    ));
}

/// @requirement AC-267
#[test]
fn register_manual_refuses_an_existing_account_and_change_password_refuses_a_stranger() {
    let registry = temp_registry("manual-refuse");
    registry.register_manual("alice", "first").unwrap();
    assert_eq!(
        registry.register_manual("alice", "second").unwrap_err(),
        RegisterError::AlreadyRegistered
    );
    assert_eq!(
        registry.change_password("nobody", "x").unwrap_err(),
        RegisterError::NotRegistered
    );
    registry.change_password("alice", "second").unwrap();
    assert!(matches!(
        registry.check_credentials("alice", "first", 0),
        AuthCheck::Rejected
    ));
    assert!(matches!(
        registry.check_credentials("alice", "second", 0),
        AuthCheck::Ok
    ));
}

/// A nickname the registry's own alphabet rejects can never resolve to a
/// path outside `dir` - the check happens before any path is built.
/// @requirement TB-238
#[test]
fn an_unregistrable_nickname_touches_no_file_and_is_never_registered() {
    let registry = temp_registry("traversal");
    for bad in ["../escape", "a/b", "", "waaaaaaaaaaaay-too-long-a-nickname", ".hidden"] {
        assert_eq!(
            registry.register_manual(bad, "x").unwrap_err(),
            RegisterError::InvalidNickname,
            "{bad:?}"
        );
        assert!(!registry.is_registered(bad));
    }
    // None of the traversal-shaped attempts escaped `dir` to create
    // anything in its parent.
    let parent = registry.dir().parent().unwrap();
    assert!(!parent.join("escape").exists());
}

/// @requirement AC-265, TB-238
#[test]
fn register_validates_email_and_password_before_writing_anything() {
    let registry = temp_registry("register-validate");
    assert_eq!(
        registry.register("alice", "pw", "not-an-email", 0).unwrap_err(),
        RegisterError::InvalidEmail
    );
    assert_eq!(
        registry.register("alice", "", "alice@example.com", 0).unwrap_err(),
        RegisterError::EmptyPassword
    );
    assert!(!registry.is_registered("alice"), "a rejected registration writes nothing");
}

/// @requirement AC-265
#[test]
fn register_writes_a_key_an_email_and_a_pending_activation() {
    let registry = temp_registry("register-writes");
    let registration = registry
        .register("alice", "hunter2", "alice@example.com", 1_000)
        .unwrap();
    assert_eq!(registration.created_at_utc, 1_000);
    assert_eq!(registration.code.len(), ACTIVATION_CODE_LEN);
    assert_eq!(registry.email_of("alice").as_deref(), Some("alice@example.com"));
    let pending = registry.pending_activation("alice").unwrap();
    assert_eq!(pending.code, registration.code);
    assert!(matches!(
        registry.check_credentials("alice", "hunter2", 1_000),
        AuthCheck::ActivationPending { expired: false }
    ));
}

/// Registering the same name again while a still-valid code is pending is
/// refused outright - only an expired, never-activated registration may be
/// replaced.
/// @requirement AC-265
#[test]
fn a_second_registration_while_pending_is_refused_but_an_expired_one_is_replaced() {
    let registry = temp_registry("register-again");
    registry.register("alice", "first", "alice@example.com", 1_000).unwrap();
    assert_eq!(
        registry
            .register("alice", "second", "alice@example.com", 1_001)
            .unwrap_err(),
        RegisterError::ActivationPending
    );

    let expired_at = 1_001 + ACTIVATION_VALIDITY_SECS + 1;
    let fresh = registry
        .register("alice", "second", "alice2@example.com", expired_at)
        .unwrap();
    assert_eq!(registry.email_of("alice").as_deref(), Some("alice2@example.com"));
    assert!(matches!(
        registry.check_credentials("alice", "second", expired_at),
        AuthCheck::ActivationPending { expired: false }
    ));
    let _ = fresh;
}

/// @requirement AC-265
#[test]
fn activate_accepts_the_right_code_once_and_refuses_a_wrong_or_expired_one() {
    let registry = temp_registry("activate");
    let registration = registry.register("alice", "pw", "alice@example.com", 0).unwrap();

    assert_eq!(
        registry.activate("alice", "000000000000", 0),
        ActivationOutcome::WrongCode
    );
    assert_eq!(
        registry.activate("alice", &registration.code, ACTIVATION_VALIDITY_SECS + 1),
        ActivationOutcome::Expired,
        "a code past its validity window is refused even though it is the right one"
    );
    assert_eq!(
        registry.activate("alice", &registration.code, 10),
        ActivationOutcome::Activated
    );
    assert!(registry.pending_activation("alice").is_none());
    assert!(matches!(
        registry.check_credentials("alice", "pw", 10),
        AuthCheck::Ok
    ));
    assert_eq!(
        registry.activate("alice", &registration.code, 10),
        ActivationOutcome::NothingPending,
        "activating twice finds nothing left to activate"
    );
}

/// A login attempt against an unknown nickname and one against a real,
/// wrong password get the identical answer - a login cannot be used to
/// discover which names exist.
/// @requirement AC-014
#[test]
fn unknown_nickname_and_wrong_password_are_indistinguishable() {
    let registry = temp_registry("indistinguishable");
    registry.register_manual("alice", "hunter2").unwrap();
    assert_eq!(
        registry.check_credentials("alice", "wrong", 0),
        AuthCheck::Rejected
    );
    assert_eq!(
        registry.check_credentials("nobody", "whatever", 0),
        AuthCheck::Rejected
    );
}

/// @requirement AC-267
#[test]
fn nicknames_lists_every_registered_account_sorted_and_ignores_stray_files() {
    let registry = temp_registry("listing");
    registry.register_manual("zoe", "pw").unwrap();
    registry.register_manual("amy", "pw").unwrap();
    std::fs::create_dir_all(registry.dir().join("not-an-account")).unwrap();
    assert_eq!(registry.nicknames(), vec!["amy".to_string(), "zoe".to_string()]);
}

/// @requirement AC-267
#[test]
fn remove_deletes_an_account_entirely_and_is_a_no_op_on_a_stranger() {
    let registry = temp_registry("remove");
    registry.register_manual("alice", "pw").unwrap();
    registry.remove("alice").unwrap();
    assert!(!registry.is_registered("alice"));
    registry.remove("alice").unwrap(); // already gone: not an error
}

// ---------------------------------------------------------------------
// Activation codes
// ---------------------------------------------------------------------

/// @requirement TB-014
#[test]
fn generated_activation_codes_are_the_documented_length_of_digits_and_differ_between_draws() {
    let a = generate_activation_code();
    let b = generate_activation_code();
    assert_eq!(a.len(), ACTIVATION_CODE_LEN);
    assert!(a.bytes().all(|c| c.is_ascii_digit()));
    assert_ne!(a, b, "not trivially constant");
    assert!(activation_code_is_well_formed(&a));
}

/// @requirement TB-014
#[test]
fn activation_code_is_well_formed_rejects_anything_but_the_exact_digit_shape() {
    assert!(!activation_code_is_well_formed(""));
    assert!(!activation_code_is_well_formed("12345678901")); // one short
    assert!(!activation_code_is_well_formed("1234567890ab"));
    assert!(!activation_code_is_well_formed("12345678901234")); // too long
    assert!(activation_code_is_well_formed("123456789012"));
}

// ---------------------------------------------------------------------
// The activation email itself
// ---------------------------------------------------------------------

/// @requirement AC-264
#[test]
fn activation_email_carries_the_code_and_names_the_nickname_and_recipient() {
    let msg = activation_email(
        "aloo@example.com",
        "alice@example.com",
        "alice",
        "123456789012",
        None,
    );
    assert!(msg.contains("To: <alice@example.com>"));
    assert!(msg.contains("From: aloo <aloo@example.com>"));
    assert!(msg.contains("123456789012"));
    assert!(msg.contains("alice"));
    assert!(!msg.contains("http"), "no link when no activation_url is configured");
}

/// @requirement AC-264
#[test]
fn activation_email_includes_a_link_when_a_base_url_is_configured() {
    let msg = activation_email(
        "aloo@example.com",
        "alice@example.com",
        "alice",
        "123456789012",
        Some("https://chat.example.com:7880"),
    );
    assert!(msg.contains("https://chat.example.com:7880/activate?nickname=alice&code=123456789012"));
}

/// @requirement AC-264
#[test]
fn activation_link_trims_a_trailing_slash_on_the_base_url() {
    assert_eq!(
        activation_link("https://chat.example.com/", "alice", "123456789012"),
        "https://chat.example.com/activate?nickname=alice&code=123456789012"
    );
}
