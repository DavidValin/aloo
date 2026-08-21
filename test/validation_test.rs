use aloo::validation::{
    CHANNEL_NAME_MAX_LEN, CHANNEL_PASSWORD_MAX_LEN, CHANNEL_PASSWORD_SYMBOLS,
    channel_name_is_valid, channel_password_is_valid, normalize_channel_name,
};

/// @requirement AC-102, TB-150
#[test]
fn channel_name_is_valid_accepts_letters_digits_and_hyphen() {
    assert!(channel_name_is_valid("the-hall"));
    assert!(channel_name_is_valid("Room42"));
    assert!(channel_name_is_valid("a"));
}

/// @requirement AC-102, TB-150
#[test]
fn channel_name_is_valid_rejects_over_the_length_cap() {
    let too_long = "a".repeat(CHANNEL_NAME_MAX_LEN + 1);
    assert!(!channel_name_is_valid(&too_long));
    let exactly = "a".repeat(CHANNEL_NAME_MAX_LEN);
    assert!(channel_name_is_valid(&exactly));
}

/// @requirement AC-102, TB-150
#[test]
fn channel_name_is_valid_rejects_disallowed_characters() {
    assert!(!channel_name_is_valid("has space"));
    assert!(!channel_name_is_valid("has_underscore"));
    assert!(!channel_name_is_valid("has/slash"));
    assert!(!channel_name_is_valid("emoji🌍"));
}

/// @requirement AC-102, TB-150
#[test]
fn channel_name_is_valid_rejects_empty() {
    assert!(!channel_name_is_valid(""));
}

/// @requirement TB-150
#[test]
fn channel_name_is_valid_counts_unicode_scalar_values_not_bytes() {
    // Rejected on charset grounds regardless, but must not panic or
    // miscount a multi-byte character as several chars toward the cap.
    let name: String = std::iter::repeat('é').take(CHANNEL_NAME_MAX_LEN).collect();
    assert_eq!(name.chars().count(), CHANNEL_NAME_MAX_LEN);
    assert!(!channel_name_is_valid(&name));
}

/// @requirement TB-150
#[test]
fn channel_password_is_valid_accepts_the_documented_symbol_set() {
    for &c in CHANNEL_PASSWORD_SYMBOLS {
        let pw = format!("abc{c}123");
        assert!(
            channel_password_is_valid(&pw),
            "expected {c:?} to be accepted"
        );
    }
    assert!(channel_password_is_valid("Sup3r!Secret.Pass,word"));
}

/// @requirement TB-150
#[test]
fn channel_password_is_valid_rejects_a_symbol_outside_the_set() {
    assert!(!channel_password_is_valid("has space"));
    assert!(!channel_password_is_valid("quote\""));
    assert!(!channel_password_is_valid("back\\slash"));
    assert!(!channel_password_is_valid("semi;colon"));
}

/// @requirement TB-150
#[test]
fn channel_password_is_valid_rejects_over_the_length_cap() {
    let too_long = "a".repeat(CHANNEL_PASSWORD_MAX_LEN + 1);
    assert!(!channel_password_is_valid(&too_long));
    let exactly = "a".repeat(CHANNEL_PASSWORD_MAX_LEN);
    assert!(channel_password_is_valid(&exactly));
}

/// @requirement TB-150
#[test]
fn channel_password_is_valid_accepts_empty() {
    assert!(channel_password_is_valid(""));
}

// ---------------------------------------------------------------------
// The decorative `#` a channel is shown with
// ---------------------------------------------------------------------

/// @requirement AC-247
#[test]
fn normalize_channel_name_drops_a_leading_display_prefix() {
    assert_eq!(normalize_channel_name("#general"), "general");
    assert_eq!(normalize_channel_name("general"), "general");
    assert_eq!(normalize_channel_name("  #general  "), "general");
}

/// Only the first one, and only one: `#` is not in the allowed charset, so
/// anywhere else it is a genuine mistake that must still be refused rather
/// than quietly deleted.
/// @requirement AC-247
#[test]
fn normalize_channel_name_leaves_every_other_hash_alone() {
    assert_eq!(normalize_channel_name("##general"), "#general");
    assert!(!channel_name_is_valid(normalize_channel_name("##general")));
    assert_eq!(normalize_channel_name("gen#eral"), "gen#eral");
    assert!(!channel_name_is_valid(normalize_channel_name("gen#eral")));
}

/// The prefix is never part of a name, so it never reaches the server.
/// @requirement AC-247
#[test]
fn a_normalized_name_is_one_the_server_accepts() {
    assert!(channel_name_is_valid(normalize_channel_name("#general")));
    assert!(!channel_name_is_valid("#general"));
}
