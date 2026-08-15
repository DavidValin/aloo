//! Traceability gate and report generator.
//!
//! Run with `cargo test --test traceability`. It is a test target, not a
//! binary, on purpose: a traceability model that CI does not check turns into
//! decorative documentation within a release or two. Each validation rule is
//! its own `#[test]` so a failure names the rule that broke rather than
//! dumping every finding at once.
//!
//! It runs in well under a second - it only reads source files - so it is
//! safe to run on its own even though the full suite is slow.
//!
//! Reports land in `target/traceability/`:
//!   * `report.html`             - browsable story -> requirement -> test tree
//!   * `traceability.json`       - machine-readable, for other tooling
//!   * `traceability-matrix.md`  - review-friendly matrix
//!
//! Set `ALOO_TEST_RESULTS=/path/to/cargo-test-output.txt` to fold real
//! PASS/FAIL results in; without it every requirement reports NOT RUN and the
//! static checks still apply.

mod model;
mod report;
mod validate;

use std::sync::OnceLock;

use validate::{
    Report, Severity, RULE_AC_WITHOUT_SCENARIO, RULE_DUPLICATE_REQUIREMENT_ID, RULE_DUPLICATE_TEST_ID,
    RULE_ONLY_IGNORED_TESTS, RULE_REQUIREMENT_WITHOUT_TEST, RULE_STORY_WITHOUT_CHILDREN,
    RULE_TEST_WITHOUT_REQUIREMENT, RULE_UNKNOWN_REQUIREMENT_ID,
};

struct Loaded {
    model: model::Model,
    report: Report,
}

fn loaded() -> &'static Loaded {
    static CELL: OnceLock<Loaded> = OnceLock::new();
    CELL.get_or_init(|| {
        let model = model::load();
        let report = validate::validate(&model);
        Loaded { model, report }
    })
}

/// Renders `rule`'s findings as an assertion message, or passes.
fn expect_none(rule: &str, explanation: &str) {
    let found = loaded().report.of(rule);
    if found.is_empty() {
        return;
    }
    let mut msg = format!("\n{} finding(s) for `{rule}`\n{explanation}\n\n", found.len());
    for f in &found {
        msg.push_str(&format!("  [{}] {} - {}\n", f.severity.label(), f.subject, f.detail));
    }
    panic!("{msg}");
}

// ---------------------------------------------------------------------
// Errors - these fail the build
// ---------------------------------------------------------------------

#[test]
fn every_requirement_has_at_least_one_executable_test() {
    expect_none(
        RULE_REQUIREMENT_WITHOUT_TEST,
        "Each acceptance criterion and technical behaviour must be linked to at least one\n\
         Gherkin scenario (@AC-xxx tag) or Rust test (/// @requirement marker).\n\
         Either link a test to it, or remove the requirement if it is not real.",
    );
}

#[test]
fn every_referenced_requirement_id_is_defined() {
    expect_none(
        RULE_UNKNOWN_REQUIREMENT_ID,
        "A test or scenario references an id that requirements/requirements.toml does not\n\
         define - usually a typo, or an id that was renamed instead of retired.",
    );
}

#[test]
fn no_requirement_id_is_declared_twice() {
    expect_none(
        RULE_DUPLICATE_REQUIREMENT_ID,
        "Requirement ids are the stable handle everything else points at; two definitions\n\
         of one id make coverage ambiguous.",
    );
}

#[test]
fn no_two_tests_share_a_qualified_id() {
    expect_none(
        RULE_DUPLICATE_TEST_ID,
        "Two tests resolve to the same `source::name`, so the report cannot tell their\n\
         results apart. Rename one of them.",
    );
}

#[test]
fn every_user_story_has_requirements_beneath_it() {
    expect_none(
        RULE_STORY_WITHOUT_CHILDREN,
        "A user story with no acceptance criteria or technical behaviours describes nothing\n\
         executable.",
    );
}

// ---------------------------------------------------------------------
// Warnings - reported, but not build-breaking
// ---------------------------------------------------------------------

/// Prints rather than asserts: every current instance is an accepted
/// trade-off recorded in `docs/TESTING.md`, and turning documented,
/// deliberate gaps into a red build teaches people to ignore the gate.
#[test]
fn warnings_are_reported_for_review() {
    let report = &loaded().report;
    for rule in [RULE_TEST_WITHOUT_REQUIREMENT, RULE_AC_WITHOUT_SCENARIO, RULE_ONLY_IGNORED_TESTS] {
        let found = report.of(rule);
        if found.is_empty() {
            continue;
        }
        println!("\n{} warning(s) for `{rule}`:", found.len());
        for f in &found {
            println!("  {} - {}", f.subject, f.detail);
        }
    }
    let errors = report.errors().len();
    let warnings = report.warnings().len();
    println!("\ntraceability: {errors} error(s), {warnings} warning(s)");
}

// ---------------------------------------------------------------------
// Report generation
// ---------------------------------------------------------------------

#[test]
fn reports_are_generated() {
    let Loaded { model, report } = loaded();
    let dir = report::write_all(model, report);
    let t = report::totals(model);

    println!("traceability reports written to {}", dir.display());
    println!(
        "  {} user stories, {} acceptance criteria, {} technical behaviours",
        t.stories, t.acceptance, t.technical
    );
    println!("  {} rust tests, {} scenarios ({} ignored)", t.rust_tests, t.scenarios, t.ignored);
    for (status, count) in &t.by_status {
        println!("  {status}: {count}");
    }

    assert!(dir.join("report.html").is_file(), "report.html should exist");
    assert!(dir.join("traceability.json").is_file(), "traceability.json should exist");
    assert!(dir.join("traceability-matrix.md").is_file(), "traceability-matrix.md should exist");

    // A model that loaded nothing would make every other check vacuously pass.
    assert!(t.stories >= 1, "requirements.toml should define user stories");
    assert!(
        t.rust_tests + t.scenarios > 0,
        "no executable tests were discovered - the scanners are probably looking in the wrong place"
    );
}

/// Guards the reconstruction rule: a requirement with no `evidence` would be
/// one that was invented during the migration rather than found in the
/// existing documentation, code or tests.
#[test]
fn every_requirement_cites_its_evidence() {
    let model = &loaded().model;
    let missing: Vec<&str> = model
        .requirements
        .values()
        .filter(|r| r.kind != model::ReqKind::Story && r.evidence.trim().is_empty())
        .map(|r| r.id.as_str())
        .collect();
    assert!(
        missing.is_empty(),
        "these requirements cite no evidence, so nothing shows they were reconstructed \
         rather than invented: {missing:?}"
    );
}

/// The severity split is load-bearing: `expect_none` above only fails the
/// build for errors, so a rule silently downgraded to a warning would stop
/// gating without anyone noticing.
#[test]
fn error_rules_keep_error_severity() {
    let report = &loaded().report;
    for rule in [
        RULE_REQUIREMENT_WITHOUT_TEST,
        RULE_UNKNOWN_REQUIREMENT_ID,
        RULE_DUPLICATE_REQUIREMENT_ID,
        RULE_DUPLICATE_TEST_ID,
        RULE_STORY_WITHOUT_CHILDREN,
    ] {
        for f in report.of(rule) {
            assert_eq!(f.severity, Severity::Error, "rule `{rule}` must stay an error");
        }
    }
}
