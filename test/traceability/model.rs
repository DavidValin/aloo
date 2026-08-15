//! The requirement model and the two link scanners that bind it to
//! executable tests.
//!
//! Three independent sources are read and cross-checked:
//!
//! 1. `requirements/requirements.toml` - what requirements *exist*.
//! 2. `features/**/*.feature` - `@AC-001`-style tags on Gherkin scenarios.
//! 3. `test/**/*.rs` - `/// @requirement AC-001, TB-051` markers above tests.
//!
//! Nothing here knows how to *judge* the result; `validate.rs` does that.
//! Keeping the reading and the judging apart is what lets the report
//! generator reuse the same model without re-implementing the rules.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

// ---------------------------------------------------------------------
// requirements.toml
// ---------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RequirementFile {
    #[serde(default)]
    pub user_story: Vec<UserStory>,
}

#[derive(Debug, Deserialize)]
pub struct UserStory {
    pub id: String,
    pub title: String,
    pub as_a: String,
    pub i_want: String,
    pub so_that: String,
    #[serde(default)]
    pub acceptance_criteria: Vec<Requirement>,
    #[serde(default)]
    pub technical_behavior: Vec<Requirement>,
}

#[derive(Debug, Deserialize)]
pub struct Requirement {
    pub id: String,
    pub description: String,
    /// Where this requirement was reconstructed from. Present on every entry;
    /// the migration was a reconstruction of existing behaviour, so a
    /// requirement with no evidence would be an invented one.
    #[serde(default)]
    pub evidence: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReqKind {
    Story,
    Acceptance,
    Technical,
}

impl ReqKind {
    pub fn label(self) -> &'static str {
        match self {
            ReqKind::Story => "Story",
            ReqKind::Acceptance => "Acceptance",
            ReqKind::Technical => "Technical",
        }
    }
}

// ---------------------------------------------------------------------
// Links discovered in executable code
// ---------------------------------------------------------------------

/// One executable test that declares which requirements it proves.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TestLink {
    /// `idstore_test::loading_a_missing_file_starts_empty_not_an_error`, or
    /// `cucumber::Send a message to everyone in the channel`. Qualified by its
    /// source because several Rust test names deliberately repeat across
    /// files (both stores test `loading_a_missing_file_starts_empty_not_an_error`).
    pub id: String,
    pub name: String,
    pub source: String,
    pub file: PathBuf,
    pub line: usize,
    pub kind: TestKind,
    pub requirements: Vec<String>,
    /// `#[ignore]`d Rust tests - real coverage, but not exercised by a plain
    /// `cargo test`, so the report must not silently present them as proven.
    pub ignored: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TestKind {
    Rust,
    Scenario,
}

impl TestKind {
    pub fn label(self) -> &'static str {
        match self {
            TestKind::Rust => "rust",
            TestKind::Scenario => "scenario",
        }
    }
}

/// A `fn` in a test file with no `@requirement` marker above it.
#[derive(Debug, Clone)]
pub struct UnlinkedTest {
    pub name: String,
    pub file: PathBuf,
    pub line: usize,
    pub kind: TestKind,
}

// ---------------------------------------------------------------------
// The assembled model
// ---------------------------------------------------------------------

pub struct Model {
    pub stories: Vec<UserStory>,
    /// Every AC/TB id -> (kind, owning story id, description).
    pub requirements: BTreeMap<String, RequirementEntry>,
    pub tests: Vec<TestLink>,
    pub unlinked: Vec<UnlinkedTest>,
    /// Requirement ids declared more than once in requirements.toml.
    pub duplicate_ids: Vec<String>,
    /// Test ids that appeared twice - a scanner-level ambiguity worth
    /// surfacing rather than silently collapsing.
    pub duplicate_tests: Vec<String>,
    pub results: BTreeMap<String, TestOutcome>,
}

pub struct RequirementEntry {
    pub id: String,
    pub kind: ReqKind,
    pub story: String,
    pub description: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestOutcome {
    Passed,
    Failed,
    Ignored,
    /// A Gherkin scenario whose steps found no matching definition. The
    /// scenario is written but not implemented - which must not be reported
    /// as a pass just because nothing failed.
    NotImplemented,
}

impl Model {
    /// Every test that names `id` among its requirements.
    pub fn tests_for(&self, id: &str) -> Vec<&TestLink> {
        self.tests.iter().filter(|t| t.requirements.iter().any(|r| r == id)).collect()
    }

    /// Every requirement id belonging to `story`, acceptance criteria first.
    pub fn requirements_of(&self, story: &str) -> Vec<&RequirementEntry> {
        let mut out: Vec<&RequirementEntry> =
            self.requirements.values().filter(|r| r.story == story).collect();
        out.sort_by_key(|r| (r.kind, r.id.clone()));
        out
    }

    pub fn outcome_of(&self, test: &TestLink) -> Option<TestOutcome> {
        self.results.get(&test.id).copied().or_else(|| {
            // Fall back to the bare name: libtest prints unqualified names, and
            // a name unique across the whole suite is unambiguous anyway.
            self.results.get(&test.name).copied()
        })
    }
}

// ---------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

pub fn load() -> Model {
    let root = repo_root();
    let toml_path = root.join("requirements/requirements.toml");
    let raw = std::fs::read_to_string(&toml_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", toml_path.display()));
    let parsed: RequirementFile = toml::from_str(&raw)
        .unwrap_or_else(|e| panic!("cannot parse {}: {e}", toml_path.display()));

    let mut requirements = BTreeMap::new();
    let mut duplicate_ids = Vec::new();
    for story in &parsed.user_story {
        let mut insert = |id: &str, kind: ReqKind, description: &str, evidence: &str| {
            let entry = RequirementEntry {
                id: id.to_string(),
                kind,
                story: story.id.clone(),
                description: description.to_string(),
                evidence: evidence.to_string(),
            };
            if requirements.insert(id.to_string(), entry).is_some() {
                duplicate_ids.push(id.to_string());
            }
        };
        insert(&story.id, ReqKind::Story, &story.title, "");
        for ac in &story.acceptance_criteria {
            insert(&ac.id, ReqKind::Acceptance, &ac.description, &ac.evidence);
        }
        for tb in &story.technical_behavior {
            insert(&tb.id, ReqKind::Technical, &tb.description, &tb.evidence);
        }
    }

    let mut tests = Vec::new();
    let mut unlinked = Vec::new();
    scan_rust_tests(&root.join("test"), &mut tests, &mut unlinked);
    scan_features(&root.join("features"), &mut tests, &mut unlinked);

    tests.sort();
    let mut duplicate_tests = Vec::new();
    for pair in tests.windows(2) {
        if pair[0].id == pair[1].id {
            duplicate_tests.push(pair[0].id.clone());
        }
    }
    duplicate_tests.dedup();

    Model {
        stories: parsed.user_story,
        requirements,
        tests,
        unlinked,
        duplicate_ids,
        duplicate_tests,
        results: load_results(),
    }
}

/// Walks `dir` recursively, yielding files whose extension matches `ext`.
fn walk(dir: &Path, ext: &str, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    let mut paths: Vec<PathBuf> = entries.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            walk(&path, ext, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some(ext) {
            out.push(path);
        }
    }
}

fn rel(root: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(root).unwrap_or(path).to_path_buf()
}

// ---------------------------------------------------------------------
// Rust marker scanning
// ---------------------------------------------------------------------

/// Parses `/// @requirement AC-001, TB-051` markers and binds each to the
/// `fn` that follows it.
///
/// The marker is a doc comment rather than a real attribute on purpose: an
/// attribute would need a proc-macro crate to exist at all, and this
/// migration is not permitted to change how any existing test compiles or
/// runs. A comment cannot alter test semantics; the cost is that nothing but
/// this scanner enforces the pairing, which is exactly why an unmarked test
/// is reported rather than ignored.
fn scan_rust_tests(dir: &Path, tests: &mut Vec<TestLink>, unlinked: &mut Vec<UnlinkedTest>) {
    let root = repo_root();
    let mut files = Vec::new();
    walk(dir, "rs", &mut files);

    for file in files {
        // The traceability harness and the cucumber runner are tooling, not
        // behaviour under test - their own fns are not suite coverage.
        let relative = rel(&root, &file);
        let s = relative.to_string_lossy().replace('\\', "/");
        if s.starts_with("test/traceability/") || s.starts_with("test/cucumber/") {
            continue;
        }

        let source = file.file_stem().and_then(|s| s.to_str()).unwrap_or("unknown").to_string();
        let text = std::fs::read_to_string(&file).expect("read test file");

        let mut pending: Vec<String> = Vec::new();
        let mut saw_test_attr = false;
        let mut ignored = false;

        for (idx, line) in text.lines().enumerate() {
            let trimmed = line.trim();

            if let Some(ids) = parse_requirement_marker(trimmed) {
                pending.extend(ids);
                continue;
            }
            if trimmed.starts_with("#[test]") || trimmed.starts_with("#[tokio::test]") {
                saw_test_attr = true;
                continue;
            }
            if trimmed.starts_with("#[ignore") {
                ignored = true;
                continue;
            }
            // Attributes and doc comments between the marker and the fn are
            // transparent; anything else resets a dangling marker so a stray
            // comment cannot attach itself to an unrelated fn far below.
            if trimmed.starts_with("#[") || trimmed.starts_with("///") || trimmed.starts_with("//") || trimmed.is_empty() {
                continue;
            }

            if let Some(name) = parse_fn_name(trimmed) {
                if saw_test_attr {
                    if pending.is_empty() {
                        unlinked.push(UnlinkedTest {
                            name,
                            file: relative.clone(),
                            line: idx + 1,
                            kind: TestKind::Rust,
                        });
                    } else {
                        tests.push(TestLink {
                            id: format!("{source}::{name}"),
                            name,
                            source: source.clone(),
                            file: relative.clone(),
                            line: idx + 1,
                            kind: TestKind::Rust,
                            requirements: std::mem::take(&mut pending),
                            ignored,
                        });
                    }
                }
                pending.clear();
                saw_test_attr = false;
                ignored = false;
                continue;
            }

            // A non-fn statement ends any pending marker/attribute run.
            pending.clear();
            saw_test_attr = false;
            ignored = false;
        }
    }
}

/// `/// @requirement AC-001, TB-051` -> `["AC-001", "TB-051"]`.
fn parse_requirement_marker(trimmed: &str) -> Option<Vec<String>> {
    let rest = trimmed
        .strip_prefix("///")
        .or_else(|| trimmed.strip_prefix("//!"))
        .or_else(|| trimmed.strip_prefix("//"))?
        .trim_start();
    let rest = rest.strip_prefix("@requirement")?;
    let rest = rest.trim_start_matches(':').trim();
    let ids: Vec<String> = rest
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    Some(ids)
}

fn parse_fn_name(trimmed: &str) -> Option<String> {
    let rest = trimmed
        .strip_prefix("pub async fn ")
        .or_else(|| trimmed.strip_prefix("async fn "))
        .or_else(|| trimmed.strip_prefix("pub fn "))
        .or_else(|| trimmed.strip_prefix("fn "))?;
    let name: String = rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
    if name.is_empty() { None } else { Some(name) }
}

// ---------------------------------------------------------------------
// Gherkin tag scanning
// ---------------------------------------------------------------------

/// Collects `@AC-001` / `@TB-051` / `@US-001` tags from feature files and
/// binds them to the scenario they sit above. Feature-level tags apply to
/// every scenario in that file, matching cucumber's own tag inheritance.
fn scan_features(dir: &Path, tests: &mut Vec<TestLink>, unlinked: &mut Vec<UnlinkedTest>) {
    let root = repo_root();
    let mut files = Vec::new();
    walk(dir, "feature", &mut files);

    for file in files {
        let relative = rel(&root, &file);
        let text = std::fs::read_to_string(&file).expect("read feature file");
        let source = file.file_stem().and_then(|s| s.to_str()).unwrap_or("feature").to_string();

        let mut feature_tags: Vec<String> = Vec::new();
        let mut pending: Vec<String> = Vec::new();
        let mut seen_feature = false;

        for (idx, line) in text.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with('@') {
                pending.extend(
                    trimmed
                        .split_whitespace()
                        .filter_map(|t| t.strip_prefix('@'))
                        .filter(|t| is_requirement_id(t))
                        .map(|t| t.to_string()),
                );
                continue;
            }
            if trimmed.starts_with("Feature:") {
                feature_tags = std::mem::take(&mut pending);
                seen_feature = true;
                continue;
            }
            let scenario = trimmed
                .strip_prefix("Scenario Outline:")
                .or_else(|| trimmed.strip_prefix("Scenario:"));
            if let Some(name) = scenario {
                let name = name.trim().to_string();
                let mut ids = feature_tags.clone();
                ids.extend(std::mem::take(&mut pending));
                ids.sort();
                ids.dedup();

                if ids.is_empty() {
                    unlinked.push(UnlinkedTest {
                        name,
                        file: relative.clone(),
                        line: idx + 1,
                        kind: TestKind::Scenario,
                    });
                } else {
                    tests.push(TestLink {
                        id: format!("{source}::{name}"),
                        name,
                        source: source.clone(),
                        file: relative.clone(),
                        line: idx + 1,
                        kind: TestKind::Scenario,
                        requirements: ids,
                        ignored: false,
                    });
                }
                continue;
            }
            let _ = seen_feature;
        }
    }
}

fn is_requirement_id(tag: &str) -> bool {
    let Some((prefix, number)) = tag.split_once('-') else { return false };
    matches!(prefix, "US" | "AC" | "TB") && !number.is_empty() && number.chars().all(|c| c.is_ascii_digit())
}

// ---------------------------------------------------------------------
// Optional test results
// ---------------------------------------------------------------------

/// Reads libtest-style output (`test <name> ... ok`) and cucumber's own
/// summary from whatever files `ALOO_TEST_RESULTS` points at
/// (colon-separated). Absent results are not an error - the traceability
/// model is fully checkable statically, and CI reports PASS/FAIL only when it
/// has actually run something.
fn load_results() -> BTreeMap<String, TestOutcome> {
    let mut out = BTreeMap::new();
    let Ok(paths) = std::env::var("ALOO_TEST_RESULTS") else { return out };

    for path in paths.split(':').filter(|p| !p.is_empty()) {
        let Ok(text) = std::fs::read_to_string(path) else { continue };
        let mut current_binary = String::new();
        for line in text.lines() {
            let trimmed = line.trim();

            // `Running tests/idstore_test.rs (target/debug/deps/idstore_test-1a2b)`
            if let Some(rest) = trimmed.strip_prefix("Running ")
                && let Some(open) = rest.find('(')
            {
                let path_part = &rest[..open];
                current_binary = Path::new(path_part.trim())
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_string();
                continue;
            }

            let Some(rest) = trimmed.strip_prefix("test ") else { continue };
            let Some((name, verdict)) = rest.rsplit_once(" ... ") else { continue };
            let name = name.trim();
            let outcome = match verdict.trim() {
                "ok" => TestOutcome::Passed,
                "FAILED" => TestOutcome::Failed,
                "undefined" => TestOutcome::NotImplemented,
                v if v.starts_with("ignored") => TestOutcome::Ignored,
                _ => continue,
            };
            out.insert(name.to_string(), outcome);
            if !current_binary.is_empty() {
                out.insert(format!("{current_binary}::{name}"), outcome);
            }
        }
    }
    out
}
