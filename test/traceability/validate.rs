//! The rules that decide whether the traceability model is healthy.
//!
//! Split from `model.rs` (which only reads) so the report generator and the
//! CI gate apply exactly the same rules rather than two drifting copies.
//!
//! Severity is deliberate:
//!
//! * **Error** - the model is broken or a requirement is unproven. Fails CI.
//! * **Warning** - the model is intact but weaker than it looks. Reported
//!   loudly, does not fail CI, because every current instance is a documented,
//!   accepted trade-off rather than a defect (see `docs/TESTING.md`).

use std::collections::BTreeSet;

use crate::model::{Model, ReqKind, TestKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Error,
    Warning,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Error => "ERROR",
            Severity::Warning => "WARNING",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Finding {
    pub severity: Severity,
    pub rule: &'static str,
    pub subject: String,
    pub detail: String,
}

pub struct Report {
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn of(&self, rule: &str) -> Vec<&Finding> {
        self.findings.iter().filter(|f| f.rule == rule).collect()
    }

    pub fn errors(&self) -> Vec<&Finding> {
        self.findings.iter().filter(|f| f.severity == Severity::Error).collect()
    }

    pub fn warnings(&self) -> Vec<&Finding> {
        self.findings.iter().filter(|f| f.severity == Severity::Warning).collect()
    }
}

pub const RULE_REQUIREMENT_WITHOUT_TEST: &str = "requirement-without-test";
pub const RULE_TEST_WITHOUT_REQUIREMENT: &str = "test-without-requirement";
pub const RULE_UNKNOWN_REQUIREMENT_ID: &str = "unknown-requirement-id";
pub const RULE_DUPLICATE_REQUIREMENT_ID: &str = "duplicate-requirement-id";
pub const RULE_DUPLICATE_TEST_ID: &str = "duplicate-test-id";
pub const RULE_AC_WITHOUT_SCENARIO: &str = "acceptance-criterion-without-scenario";
pub const RULE_ONLY_IGNORED_TESTS: &str = "covered-only-by-ignored-tests";
pub const RULE_STORY_WITHOUT_CHILDREN: &str = "story-without-requirements";

pub fn validate(model: &Model) -> Report {
    let mut findings = Vec::new();

    // -- duplicate definitions ------------------------------------------
    for id in &model.duplicate_ids {
        findings.push(Finding {
            severity: Severity::Error,
            rule: RULE_DUPLICATE_REQUIREMENT_ID,
            subject: id.clone(),
            detail: "declared more than once in requirements/requirements.toml".into(),
        });
    }
    for id in &model.duplicate_tests {
        findings.push(Finding {
            severity: Severity::Error,
            rule: RULE_DUPLICATE_TEST_ID,
            subject: id.clone(),
            detail: "two tests resolve to the same qualified id, so their coverage is ambiguous".into(),
        });
    }

    // -- links pointing at ids that do not exist ------------------------
    for test in &model.tests {
        for id in &test.requirements {
            if !model.requirements.contains_key(id) {
                findings.push(Finding {
                    severity: Severity::Error,
                    rule: RULE_UNKNOWN_REQUIREMENT_ID,
                    subject: id.clone(),
                    detail: format!(
                        "referenced by {} ({}:{}) but not defined in requirements.toml",
                        test.id,
                        test.file.display(),
                        test.line
                    ),
                });
            }
        }
    }

    // -- requirements nothing proves ------------------------------------
    for entry in model.requirements.values() {
        if entry.kind == ReqKind::Story {
            continue; // stories are covered transitively by their children
        }
        let tests = model.tests_for(&entry.id);
        if tests.is_empty() {
            findings.push(Finding {
                severity: Severity::Error,
                rule: RULE_REQUIREMENT_WITHOUT_TEST,
                subject: entry.id.clone(),
                detail: format!("no test or scenario is linked to it - {}", entry.description),
            });
            continue;
        }

        // Covered, but only by tests a plain `cargo test` skips. Real
        // coverage, yet nothing in a default run actually exercises it, so the
        // report must not present it as proven without saying so.
        if tests.iter().all(|t| t.ignored) {
            findings.push(Finding {
                severity: Severity::Warning,
                rule: RULE_ONLY_IGNORED_TESTS,
                subject: entry.id.clone(),
                detail: format!(
                    "covered only by #[ignore]d test(s): {} - run `cargo test -- --ignored` to exercise",
                    tests.iter().map(|t| t.id.as_str()).collect::<Vec<_>>().join(", ")
                ),
            });
        }

        // An acceptance criterion describes observable behaviour, so it should
        // normally have a Gherkin scenario as well as any technical tests.
        if entry.kind == ReqKind::Acceptance
            && !tests.iter().any(|t| t.kind == TestKind::Scenario)
        {
            findings.push(Finding {
                severity: Severity::Warning,
                rule: RULE_AC_WITHOUT_SCENARIO,
                subject: entry.id.clone(),
                detail: "covered by Rust tests but has no executable Gherkin scenario".into(),
            });
        }
    }

    // -- stories with nothing under them --------------------------------
    let owned: BTreeSet<&str> = model.requirements.values().map(|r| r.story.as_str()).collect();
    for story in &model.stories {
        let has_children = model
            .requirements
            .values()
            .any(|r| r.story == story.id && r.kind != ReqKind::Story);
        if !has_children {
            findings.push(Finding {
                severity: Severity::Error,
                rule: RULE_STORY_WITHOUT_CHILDREN,
                subject: story.id.clone(),
                detail: "user story has no acceptance criteria or technical behaviours".into(),
            });
        }
    }
    let _ = owned;

    // -- tests claiming nothing -----------------------------------------
    for test in &model.unlinked {
        findings.push(Finding {
            severity: Severity::Warning,
            rule: RULE_TEST_WITHOUT_REQUIREMENT,
            subject: test.name.clone(),
            detail: format!(
                "{} at {}:{} declares no requirement id",
                test.kind.label(),
                test.file.display(),
                test.line
            ),
        });
    }

    findings.sort();
    Report { findings }
}
