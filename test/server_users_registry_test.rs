//! Tests for `src/server/users_registry.rs`: account storage, credential
//! checking and activation (docs/PROTOCOL.md §5), independent of any
//! socket.

use aloo::server::users_registry::{
    ACCOUNT_REMOVED_ACTIVATION_REASON, ACTIVATION_CODE_LEN, ACTIVATION_FAIL_LIMIT,
    ACTIVATION_VALIDITY_SECS, ActivationOutcome, AuthCheck, RegisterError, UsersRegistry,
    activation_code_is_well_formed, activation_email, derive_user_key, generate_activation_code,
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

/// One email address cannot back two different nicknames.
/// @requirement AC-389
#[test]
fn a_second_nickname_cannot_register_under_an_email_already_in_use() {
    let registry = temp_registry("register-dup-email");
    registry.register("alice", "hunter2", "shared@example.com", 1_000).unwrap();
    assert_eq!(
        registry.register("mallory", "pw", "shared@example.com", 1_001).unwrap_err(),
        RegisterError::EmailAlreadyRegistered
    );
    assert!(!registry.is_registered("mallory"), "a rejected registration writes nothing");

    // Case differences do not open a loophole.
    assert_eq!(
        registry.register("mallory", "pw", "SHARED@EXAMPLE.COM", 1_002).unwrap_err(),
        RegisterError::EmailAlreadyRegistered
    );
}

/// The check is scoped to *other* nicknames: replacing an expired pending
/// registration under the *same* name and the *same* email it already had
/// is unaffected.
/// @requirement AC-389
#[test]
fn reregistering_the_same_nickname_under_its_own_email_is_unaffected() {
    let registry = temp_registry("register-dup-email-self");
    registry.register("alice", "first", "alice@example.com", 1_000).unwrap();
    let expired_at = 1_000 + ACTIVATION_VALIDITY_SECS + 1;
    registry
        .register("alice", "second", "alice@example.com", expired_at)
        .expect("the same nickname re-registering under its own email is not a collision");
}

/// A registered account's email becomes free again once the account is
/// gone (rather than the email being reserved forever).
/// @requirement AC-389
#[test]
fn an_emails_slot_frees_up_once_its_account_is_removed() {
    let registry = temp_registry("register-dup-email-freed");
    registry.register("alice", "hunter2", "shared@example.com", 1_000).unwrap();
    registry.remove("alice").unwrap();
    registry
        .register("bob", "pw", "shared@example.com", 1_001)
        .expect("the email is free again once the account that held it is gone");
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

/// The login-time counterpart to `a_second_registration_while_pending_is_refused_but_an_expired_one_is_replaced`
/// above: a login attempt against an expired pending activation gets the
/// exact same fresh-code treatment `register` already gives a second
/// registration, without needing a whole new `Register` round trip -
/// `key`/`email.txt` are untouched since a login attempt carries neither.
/// @requirement AC-367
#[test]
fn reissue_activation_replaces_an_expired_pending_code_leaving_credentials_untouched() {
    let registry = temp_registry("reissue");
    let first = registry.register("alice", "hunter2", "alice@example.com", 1_000).unwrap();

    let expired_at = 1_000 + ACTIVATION_VALIDITY_SECS + 1;
    let reissued = registry
        .reissue_activation("alice", expired_at)
        .unwrap()
        .expect("an expired pending activation must be reissued");
    assert_ne!(reissued.code, first.code, "a fresh code, not the stale one reused");
    assert_eq!(reissued.created_at_utc, expired_at);
    assert_eq!(
        registry.email_of("alice").as_deref(),
        Some("alice@example.com"),
        "a login attempt carries no new email to replace it with"
    );
    assert!(matches!(
        registry.check_credentials("alice", "hunter2", expired_at),
        AuthCheck::ActivationPending { expired: false }
    ), "the reissued code must not itself read as already expired");
    assert_eq!(
        registry.activate("alice", &reissued.code, expired_at),
        ActivationOutcome::Activated,
        "the reissued code, not the original stale one, must be what activates the account"
    );
}

/// `reissue_activation` must never fabricate a fresh code out of thin
/// air: a not-yet-expired pending activation, or no pending activation at
/// all, must be left completely untouched.
/// @requirement AC-367
#[test]
fn reissue_activation_is_a_no_op_unless_the_pending_code_has_actually_expired() {
    let registry = temp_registry("reissue-noop");
    assert_eq!(
        registry.reissue_activation("nobody", 0).unwrap(),
        None,
        "no pending activation at all"
    );

    let first = registry.register("alice", "hunter2", "alice@example.com", 1_000).unwrap();
    assert_eq!(
        registry.reissue_activation("alice", 1_001).unwrap(),
        None,
        "not expired yet"
    );
    assert_eq!(
        registry.pending_activation("alice").unwrap().code,
        first.code,
        "the original, still-valid code must be left in place"
    );
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

/// The `ACTIVATION_FAIL_LIMIT`th (5th) wrong code in a row removes the
/// account outright rather than leaving it open to indefinite guessing.
/// @requirement AC-388
#[test]
fn five_wrong_activation_codes_in_a_row_remove_the_account() {
    let registry = temp_registry("activate-fail-limit");
    let registration = registry.register("alice", "pw", "alice@example.com", 0).unwrap();
    assert_eq!(ACTIVATION_FAIL_LIMIT, 5, "test assumes the documented limit");

    for _ in 0..ACTIVATION_FAIL_LIMIT - 1 {
        assert_eq!(
            registry.activate("alice", "000000000000", 0),
            ActivationOutcome::WrongCode
        );
    }
    assert!(registry.is_registered("alice"), "still short of the limit");

    assert_eq!(
        registry.activate("alice", "000000000000", 0),
        ActivationOutcome::TooManyWrongCodesAccountRemoved
    );
    assert!(!registry.is_registered("alice"), "the account is gone");
    assert_eq!(
        registry.activate("alice", &registration.code, 0),
        ActivationOutcome::NothingPending,
        "even the right code finds nothing left to activate"
    );
}

/// Fewer than the limit leaves the account intact, and a fresh (right or
/// wrong) attempt is still checked normally.
/// @requirement AC-388
#[test]
fn fewer_than_the_limit_of_wrong_codes_does_not_remove_the_account() {
    let registry = temp_registry("activate-fail-limit-not-yet");
    let registration = registry.register("bob", "pw", "bob@example.com", 0).unwrap();

    for _ in 0..ACTIVATION_FAIL_LIMIT - 1 {
        registry.activate("bob", "000000000000", 0);
    }
    assert_eq!(
        registry.activate("bob", &registration.code, 0),
        ActivationOutcome::Activated,
        "the right code still works one short of the limit"
    );
    assert!(registry.is_registered("bob"));
}

/// A successful activation clears the wrong-code count, so it does not
/// carry over and (say) remove the account on some unrelated later
/// mistake - there is nothing left to guess against once it's active.
/// @requirement AC-388
#[test]
fn a_successful_activation_clears_the_wrong_code_count() {
    let registry = temp_registry("activate-fail-limit-clears");
    let registration = registry.register("carol", "pw", "carol@example.com", 0).unwrap();
    registry.activate("carol", "000000000000", 0);
    registry.activate("carol", "000000000000", 0);
    assert_eq!(
        registry.activate("carol", &registration.code, 0),
        ActivationOutcome::Activated
    );
    assert!(registry.is_registered("carol"));
}

/// The reason text `handle_connection` sends for this outcome is the exact
/// constant `connect::handshake_as` matches on to stop retrying - a
/// regression here would silently turn back into an infinite activation-
/// popup loop against a nonexistent account, so it is pinned directly.
/// @requirement AC-388
#[test]
fn the_account_removed_reason_constant_is_the_documented_wording() {
    assert_eq!(
        ACCOUNT_REMOVED_ACTIVATION_REASON,
        "too many wrong activation codes - this account has been removed"
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
    let msg = activation_email("aloo@example.com", "alice@example.com", "alice", "123456789012");
    assert!(msg.contains("To: <alice@example.com>"));
    assert!(msg.contains("From: aloo <aloo@example.com>"));
    assert!(msg.contains("123456789012"));
    assert!(msg.contains("alice"));
}

/// @requirement AC-264
#[test]
fn activation_email_tells_a_non_registrant_to_ignore_it() {
    let msg = activation_email("aloo@example.com", "alice@example.com", "alice", "123456789012");
    assert!(msg.contains("If you haven't registered you can ignore this message."));
}

// ---------------------------------------------------------------------
// Superadmin account status (docs/PROTOCOL.md §5.5): deactivate/activate
// ---------------------------------------------------------------------

/// @requirement AC-344
#[test]
fn deactivate_and_deactivation_reason_round_trip() {
    let registry = temp_registry("deactivate");
    registry.register_manual("eve", "hunter2").unwrap();
    assert_eq!(registry.deactivation_reason("eve"), None);
    registry.deactivate("eve", "spamming").unwrap();
    assert_eq!(registry.deactivation_reason("eve"), Some("spamming".to_string()));
}

/// @requirement AC-344, TB-263
#[test]
fn check_credentials_reports_deactivated_even_over_a_pending_activation() {
    let registry = temp_registry("deactivate-over-pending");
    let reg = registry
        .register("eve", "hunter2", "eve@example.com", 1_000_000)
        .unwrap();
    let _ = reg; // still pending - never activated
    registry.deactivate("eve", "abuse").unwrap();
    assert_eq!(
        registry.check_credentials("eve", "hunter2", 1_000_000),
        AuthCheck::Deactivated { reason: "abuse".to_string() }
    );
}

/// @requirement AC-344, TB-263
#[test]
fn check_credentials_deactivated_still_requires_the_right_password() {
    let registry = temp_registry("deactivate-wrong-password");
    registry.register_manual("eve", "hunter2").unwrap();
    registry.deactivate("eve", "abuse").unwrap();
    // The same timing-safety property `ActivationPending` already has:
    // deactivation is only reported once the password is already known
    // to be right, so a wrong password stays indistinguishable from an
    // unknown nickname.
    assert_eq!(
        registry.check_credentials("eve", "wrong", 1_000_000),
        AuthCheck::Rejected
    );
}

/// @requirement AC-344
#[test]
fn admin_force_activate_clears_both_a_pending_code_and_a_deactivation() {
    let registry = temp_registry("force-activate");
    registry
        .register("eve", "hunter2", "eve@example.com", 1_000_000)
        .unwrap();
    registry.deactivate("eve", "abuse").unwrap();
    assert!(registry.pending_activation("eve").is_some());
    assert!(registry.deactivation_reason("eve").is_some());

    registry.admin_force_activate("eve").unwrap();

    assert!(registry.pending_activation("eve").is_none());
    assert!(registry.deactivation_reason("eve").is_none());
    assert_eq!(
        registry.check_credentials("eve", "hunter2", 1_000_000),
        AuthCheck::Ok
    );
}

/// @requirement AC-344
#[test]
fn admin_force_activate_on_an_ordinary_active_account_is_a_harmless_no_op() {
    let registry = temp_registry("force-activate-noop");
    registry.register_manual("eve", "hunter2").unwrap();
    registry.admin_force_activate("eve").unwrap();
    assert_eq!(
        registry.check_credentials("eve", "hunter2", 1_000_000),
        AuthCheck::Ok
    );
}
