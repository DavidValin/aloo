//! Keeps the documentation honest about the code it describes.
//!
//! `docs/PROTOCOL.md` deliberately names no Rust, so that a second
//! implementation never has to read this codebase; `docs/SPEC.md` carries
//! the bridge back. Both properties are easy to break by accident and
//! invisible in review, so they are checked here.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("reading {rel}: {e}"))
}

/// The protocol description must stay language-independent: no Rust code
/// blocks, no Rust syntax in prose, no source paths.
/// @requirement AC-130
#[test]
fn the_protocol_document_contains_no_rust() {
    let protocol = read("docs/PROTOCOL.md");

    assert!(
        !protocol.contains("```rust"),
        "PROTOCOL.md must describe the protocol in neutral pseudocode, not Rust"
    );

    for needle in ["Vec<", "Option<", "&mut ", "impl ", "pub fn ", ".rs`", "src/"] {
        assert!(
            !protocol.contains(needle),
            "PROTOCOL.md still contains Rust-specific text: {needle:?}"
        );
    }
}

/// Every Rust item the mapping table promises must actually exist, or the
/// bridge from protocol term to implementation is a dead link.
/// @requirement AC-130
#[test]
fn every_mapped_item_exists_in_the_source() {
    let spec = read("docs/SPEC.md");

    let start = spec
        .find("## Protocol terms, and what implements them")
        .expect("SPEC.md must carry the protocol-to-code mapping table");
    let table = &spec[start..];
    let end = table[1..].find("\n## ").map_or(table.len(), |i| i + 1);
    let table = &table[..end];

    // Collect every backticked identifier from the "implemented by" column.
    let mut identifiers: BTreeSet<String> = BTreeSet::new();
    for line in table.lines().filter(|l| l.starts_with('|')) {
        let Some(implemented_by) = line.split('|').nth(2) else {
            continue;
        };
        let mut rest = implemented_by;
        while let Some(open) = rest.find('`') {
            let after = &rest[open + 1..];
            let Some(close) = after.find('`') else { break };
            let ident = &after[..close];
            rest = &after[close + 1..];
            // Only bare identifiers; paths like `crypto/pq.rs` are prose.
            if !ident.is_empty()
                && ident
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
                && ident.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            {
                identifiers.insert(ident.to_string());
            }
        }
    }

    assert!(
        identifiers.len() > 40,
        "the mapping table looks empty - parsed only {} identifiers",
        identifiers.len()
    );

    let sources = collect_sources(&repo_root().join("src"));
    let haystack: String = sources
        .iter()
        .map(|p| fs::read_to_string(p).unwrap_or_default())
        .collect();

    let missing: Vec<&String> = identifiers
        .iter()
        .filter(|ident| !haystack.contains(ident.as_str()))
        .collect();

    assert!(
        missing.is_empty(),
        "SPEC.md maps protocol terms to items that no longer exist: {missing:?}"
    );
}

fn collect_sources(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(collect_sources(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    out
}

/// The security claims document has to exist and has to be honest about
/// the gaps, not only the strengths.
/// @requirement AC-130
#[test]
fn the_security_document_states_its_limits() {
    let security = read("docs/SECURITY.md");

    for expected in [
        "**not** been independently reviewed",
        "Post-compromise security is partial",
        "trust-on-first-use",
        "No deniability",
    ] {
        assert!(
            security.contains(expected),
            "SECURITY.md must keep stating its limits plainly; missing: {expected:?}"
        );
    }
}

/// Section numbers are load-bearing: requirement evidence strings and
/// source comments reference them, so a section that exists must keep
/// existing. Checked rather than trusted, because renumbering is exactly
/// the kind of tidy-up that looks harmless in a diff.
/// @requirement TB-175
#[test]
fn the_protocol_documents_sections_are_stable() {
    let protocol = read("docs/PROTOCOL.md");

    // Every top-level section other implementations and requirements cite.
    for section in [
        "## 1. Transport",
        "### 1.3 The control channel is encrypted",
        "## 2. Serialization",
        "## 3. Domain types",
        "## 4. Connection lifecycle",
        "## 5. Authentication",
        "## 6. Channels",
        "## 7. Messaging",
        "## 8. Encryption model",
        "### 8.2 RSA signatures",
        "## 10. What the server never sees",
        "## 11. Rotating a peer's key during a session",
        "## 12. Client-side identity pinning",
        "### 12.6 Making a pin worth more",
        "## 13. Post-quantum hybrid encryption",
        "### 13.3 One layout for everything",
        "### 13.10 Rotating encryption keys",
        "## 14. The two encryption layers, side by side",
        "## 15. Sequences",
    ] {
        assert!(
            protocol.contains(section),
            "a referenced section vanished from PROTOCOL.md: {section:?}"
        );
    }
}

/// What a user actually gets has to be laid out in one place: the one
/// peer-to-peer scheme, and the one optional layer over it.
/// @requirement AC-130
#[test]
fn the_encryption_layers_are_compared_in_one_place() {
    let protocol = read("docs/PROTOCOL.md");
    let start = protocol
        .find("## 14. The two encryption layers")
        .expect("section 14 must exist");
    let section = &protocol[start..];

    for layer in ["pq-hybrid", "OTP"] {
        assert!(
            section[..4000].contains(layer),
            "section 14 must cover the {layer} layer"
        );
    }
}

/// The overview table is the first thing a reader meets, so a message
/// added to the protocol without being listed there would mislead from
/// the very top. Checked against the enums themselves.
/// @requirement AC-131
#[test]
fn the_overview_lists_every_message() {
    let protocol = read("docs/PROTOCOL.md");
    let start = protocol
        .find("## Overview: the connections, and what travels on each")
        .expect("PROTOCOL.md must open with the connections overview");
    let end = protocol.find("## 1. Transport").expect("section 1");
    let overview = &protocol[start..end];

    let source = |rel: &str| fs::read_to_string(repo_root().join(rel)).expect(rel);
    let proto = source("src/proto.rs");
    let p2p = source("src/p2p_proto.rs");

    for (enum_name, text) in [
        ("ClientMessage", proto.as_str()),
        ("ServerMessage", proto.as_str()),
        ("PunchDatagram", p2p.as_str()),
        ("P2pPayload", p2p.as_str()),
        ("RendezvousMessage", p2p.as_str()),
    ] {
        for variant in variants_of(text, enum_name) {
            assert!(
                overview.contains(&format!("`{variant}`")),
                "{enum_name}::{variant} is missing from PROTOCOL.md's overview table"
            );
        }
    }
}

/// Variant names of `pub enum <name>`, taken from the source so the test
/// cannot drift from the definition it is checking.
fn variants_of(source: &str, enum_name: &str) -> Vec<String> {
    let header = format!("pub enum {enum_name} {{");
    let Some(start) = source.find(&header) else {
        panic!("no `{header}` in source");
    };
    let body = &source[start + header.len()..];
    let end = body.find("\n}").expect("unterminated enum");
    body[..end]
        .lines()
        .map(str::trim)
        .filter(|l| {
            l.chars().next().is_some_and(|c| c.is_ascii_uppercase())
                && !l.starts_with("///")
        })
        .map(|l| {
            l.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .next()
                .unwrap_or_default()
                .to_string()
        })
        .filter(|v| !v.is_empty())
        .collect()
}

/// The overview has to state the connection shape, and point at the
/// diagrams rather than leaving a reader to find them.
/// @requirement AC-131
#[test]
fn the_overview_states_the_connection_shape_and_links_the_diagrams() {
    let protocol = read("docs/PROTOCOL.md");
    let end = protocol.find("## 1. Transport").expect("section 1");
    let overview = &protocol[..end];

    assert!(
        overview.contains("one continuous connection to the server"),
        "the overview must say there is exactly one server connection"
    );
    assert!(
        overview.contains("one direct connection per peer"),
        "the overview must say peer links are per peer, not per channel"
    );
    assert!(
        overview.contains("§15"),
        "the overview must point at the sequence diagrams"
    );
}

/// Collects `(level, title)` for every heading in a document.
fn headings(doc: &str) -> Vec<(usize, String)> {
    doc.lines()
        .filter_map(|l| {
            let hashes = l.chars().take_while(|c| *c == '#').count();
            if (2..=4).contains(&hashes) && l.chars().nth(hashes) == Some(' ') {
                Some((hashes, l[hashes + 1..].trim().to_string()))
            } else {
                None
            }
        })
        .collect()
}

/// Section numbers are how this document refers to itself, and how
/// requirements and source comments refer into it. A gap means either a
/// section was deleted without a thought for what pointed at it, or one
/// was never written.
/// @requirement AC-132
#[test]
fn section_numbers_run_consecutively_with_no_gaps() {
    let protocol = read("docs/PROTOCOL.md");

    // Every numbered heading, as its dotted path: "7.1.2" -> [7, 1, 2].
    let mut numbered: Vec<Vec<u32>> = Vec::new();
    for (_, title) in headings(&protocol) {
        let Some(first) = title.split_whitespace().next() else {
            continue;
        };
        let digits = first.trim_end_matches('.');
        if digits.chars().all(|c| c.is_ascii_digit() || c == '.')
            && digits.chars().next().is_some_and(|c| c.is_ascii_digit())
        {
            numbered.push(digits.split('.').filter_map(|p| p.parse().ok()).collect());
        }
    }
    assert!(numbered.len() > 50, "expected the numbered sections to be found");

    // Within each parent, children must start at 1 and step by 1.
    let mut seen: std::collections::BTreeMap<Vec<u32>, Vec<u32>> =
        std::collections::BTreeMap::new();
    for path in &numbered {
        let (last, parent) = path.split_last().expect("non-empty");
        seen.entry(parent.to_vec()).or_default().push(*last);
    }
    for (parent, mut children) in seen {
        children.sort_unstable();
        let expected: Vec<u32> = (1..=children.len() as u32).collect();
        assert_eq!(
            children,
            expected,
            "section numbering under {parent:?} is not consecutive from 1"
        );
    }
}

/// A table of contents that has drifted is worse than none: it sends a
/// reader to the wrong place, or to nowhere.
/// @requirement AC-132
#[test]
fn the_contents_list_matches_the_sections() {
    let protocol = read("docs/PROTOCOL.md");
    let start = protocol.find("## Contents").expect("PROTOCOL.md needs a contents list");
    let rest = &protocol[start + "## Contents".len()..];
    let end = rest.find("\n## ").expect("contents must be followed by a section");
    let contents = &rest[..end];

    let listed: Vec<String> = contents
        .lines()
        .filter_map(|l| {
            let l = l.trim_start();
            let open = l.find("- [")? + 3;
            let close = l[open..].find("](")? + open;
            Some(l[open..close].to_string())
        })
        .collect();

    let actual: Vec<String> = headings(&protocol)
        .into_iter()
        .map(|(_, t)| t)
        .filter(|t| t != "Contents")
        .collect();

    assert_eq!(
        listed, actual,
        "the contents list and the document's sections have drifted apart"
    );

    // Anchors must be derivable from the titles, or the links go nowhere.
    for line in contents.lines().map(str::trim_start).filter(|l| l.starts_with("- [")) {
        let title = &line[3..line.find("](").expect("link")];
        let target = &line[line.find("](#").expect("anchor") + 3..line.rfind(')').expect(")")];
        let expected: String = title
            .to_lowercase()
            .replace('`', "")
            .chars()
            .filter(|c| c.is_alphanumeric() || c.is_whitespace() || *c == '-' || *c == '_')
            .collect::<String>()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join("-");
        assert_eq!(target, expected, "anchor for {title:?} will not resolve");
    }
}

/// Every section the codebase, the requirements or the other documents
/// point at must actually exist.
///
/// This is the check that catches the damage a renumbering does: a
/// reference to a section that has moved still *reads* fine in a diff, and
/// only misleads the person who follows it months later. One such
/// reference - to a subsection of the transport section that never
/// existed - survived in this document for a long time before an audit
/// like this one found it.
/// @requirement AC-133
#[test]
fn every_referenced_protocol_section_exists() {
    let protocol = read("docs/PROTOCOL.md");

    let existing: BTreeSet<String> = protocol
        .lines()
        .filter_map(|l| {
            let hashes = l.chars().take_while(|c| *c == '#').count();
            if !(2..=4).contains(&hashes) {
                return None;
            }
            let rest = l[hashes..].trim_start();
            let number: String = rest
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            let number = number.trim_end_matches('.');
            (!number.is_empty() && number.chars().next()?.is_ascii_digit())
                .then(|| number.to_string())
        })
        .collect();

    assert!(
        existing.len() > 50,
        "expected to find the numbered sections, found {}",
        existing.len()
    );

    let mut dangling: Vec<String> = Vec::new();
    for (path, text) in documents_and_sources() {
        for (lineno, line) in text.lines().enumerate() {
            for reference in section_references(line) {
                if !existing.contains(&reference) {
                    dangling.push(format!("{path}:{} -> §{reference}", lineno + 1));
                }
            }
        }
    }

    assert!(
        dangling.is_empty(),
        "these point at PROTOCOL.md sections that do not exist: {dangling:#?}"
    );
}

/// Section numbers cited as `§X.Y` or `PROTOCOL.md X.Y` on one line.
fn section_references(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut push_from = |rest: &str| {
        let number: String = rest
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        let number = number.trim_end_matches('.');
        if !number.is_empty() && number.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            out.push(number.to_string());
        }
    };
    for (i, _) in line.match_indices('§') {
        push_from(&line[i + '§'.len_utf8()..]);
    }
    for (i, _) in line.match_indices("PROTOCOL.md ") {
        push_from(&line[i + "PROTOCOL.md ".len()..]);
    }
    out
}

/// Every file that may reference the protocol: the other documents, all
/// sources, all tests, and the requirements.
fn documents_and_sources() -> Vec<(String, String)> {
    let root = repo_root();
    let mut out = Vec::new();

    for doc in ["docs/SPEC.md", "docs/SECURITY.md", "docs/TESTING.md", "README.md"] {
        if let Ok(text) = fs::read_to_string(root.join(doc)) {
            out.push((doc.to_string(), text));
        }
    }
    if let Ok(text) = fs::read_to_string(root.join("requirements/requirements.toml")) {
        out.push(("requirements/requirements.toml".to_string(), text));
    }
    // PROTOCOL.md references itself constantly; those matter most of all.
    if let Ok(text) = fs::read_to_string(root.join("docs/PROTOCOL.md")) {
        out.push(("docs/PROTOCOL.md".to_string(), text));
    }
    for dir in ["src", "test"] {
        for path in collect_sources(&root.join(dir)) {
            let shown = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .display()
                .to_string();
            if let Ok(text) = fs::read_to_string(&path) {
                out.push((shown, text));
            }
        }
    }
    out
}

/// One reference of the form path-dot-rs-colon-line, or a backticked
/// item name followed by a colon and a line number.
#[derive(Debug, PartialEq)]
enum CodeRef {
    /// A path and a line in it.
    FileLine { file: String, line: usize },
    /// A named item and the line it is declared on - the convention
    /// `docs/HOW.md` asks contributors to keep in sync.
    ItemLine { item: String, line: usize },
}

/// Pulls code references out of one file's text. `fenced` skips fenced
/// code blocks, where shell arguments and image tags of the same shape
/// live and are not references to anything.
fn code_references(text: &str, fenced: bool) -> Vec<(usize, CodeRef)> {
    let mut out = Vec::new();
    let mut in_fence = false;

    for (i, line) in text.lines().enumerate() {
        if fenced && line.trim_start().starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }

        // A path ending in dot-rs, a colon, and a line number.
        let mut rest = line;
        while let Some(at) = rest.find(".rs:") {
            let before = &rest[..at];
            let start = before
                .rfind(|c: char| !(c.is_alphanumeric() || c == '_' || c == '/' || c == '.'))
                .map_or(0, |p| p + 1);
            let file = format!("{}.rs", &before[start..]);
            let after = &rest[at + ".rs:".len()..];
            let digits: String = after.chars().take_while(char::is_ascii_digit).collect();
            if let Ok(line_no) = digits.parse::<usize>()
                && !file.starts_with(".rs")
            {
                out.push((i + 1, CodeRef::FileLine { file, line: line_no }));
            }
            rest = &after[digits.len()..];
        }

        // The item form, only inside backticks - so a struct field
        // initialiser in real code is never mistaken for one.
        let mut rest = line;
        while let Some(open) = rest.find('`') {
            let after = &rest[open + 1..];
            let Some(close) = after.find('`') else { break };
            let inner = &after[..close];
            rest = &after[close + 1..];

            let Some((name, digits)) = inner.split_once(':') else {
                continue;
            };
            if name.is_empty()
                || name.contains('.')
                || !name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
                || !name.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            {
                continue;
            }
            if let Ok(line_no) = digits.parse::<usize>() {
                out.push((
                    i + 1,
                    CodeRef::ItemLine {
                        item: name.to_string(),
                        line: line_no,
                    },
                ));
            }
        }
    }
    out
}

/// Checks one reference against the tree. `Ok(())` or why it is wrong.
fn check_reference(reference: &CodeRef) -> Result<(), String> {
    let root = repo_root();
    match reference {
        CodeRef::FileLine { file, line } => {
            let candidates = [root.join(file), root.join("src").join(file)];
            let Some(path) = candidates.iter().find(|p| p.is_file()) else {
                return Err(format!("{file} does not exist"));
            };
            let text = fs::read_to_string(path).map_err(|e| e.to_string())?;
            let total = text.lines().count();
            if *line == 0 || *line > total {
                return Err(format!("{file} has {total} lines, so :{line} is past its end"));
            }
            if text.lines().nth(line - 1).is_some_and(|l| l.trim().is_empty()) {
                return Err(format!("{file}:{line} is a blank line - the reference has drifted"));
            }
            Ok(())
        }
        CodeRef::ItemLine { item, line } => {
            // Where is this item actually declared?
            let mut declared_at: Vec<(String, usize)> = Vec::new();
            for path in collect_sources(&root.join("src")) {
                let Ok(text) = fs::read_to_string(&path) else {
                    continue;
                };
                for (i, l) in text.lines().enumerate() {
                    let l = l.trim_start();
                    let declares = [
                        "fn ", "struct ", "enum ", "const ", "static ", "trait ", "type ",
                        "mod ", "union ",
                    ]
                    .iter()
                    .any(|kw| {
                        l.strip_prefix("pub ")
                            .unwrap_or(l)
                            .strip_prefix("pub(crate) ")
                            .unwrap_or(l.strip_prefix("pub ").unwrap_or(l))
                            .starts_with(kw)
                    });
                    if declares
                        && l.split(|c: char| !(c.is_alphanumeric() || c == '_'))
                            .any(|w| w == item)
                    {
                        let shown = path
                            .strip_prefix(root)
                            .unwrap_or(&path)
                            .display()
                            .to_string();
                        declared_at.push((shown, i + 1));
                    }
                }
            }
            if declared_at.is_empty() {
                return Err(format!("no item named {item} is declared in src/"));
            }
            if declared_at.iter().any(|(_, at)| at == line) {
                Ok(())
            } else {
                Err(format!(
                    "{item} is declared at {declared_at:?}, not line {line}"
                ))
            }
        }
    }
}

/// `docs/HOW.md` asks for `<function_name>:<line_number>` references to be
/// kept in sync when code moves. A reference like that goes stale the
/// moment anything above it grows a line, and nothing about the diff shows
/// it - so it is checked here rather than remembered.
/// @requirement AC-134
#[test]
fn every_file_and_line_reference_points_somewhere_real() {
    let root = repo_root();
    let mut checked = 0usize;
    let mut broken: Vec<String> = Vec::new();

    let mut documents: Vec<(String, String, bool)> = Vec::new();
    for doc in [
        "README.md",
        "docs/PROTOCOL.md",
        "docs/SPEC.md",
        "docs/SECURITY.md",
        "docs/TESTING.md",
        "docs/HOW.md",
        "docs/BUILDING.md",
        "docs/SERVER_ON_DOCKER.md",
    ] {
        if let Ok(text) = fs::read_to_string(root.join(doc)) {
            documents.push((doc.to_string(), text, true));
        }
    }
    for dir in ["src", "test"] {
        for path in collect_sources(&root.join(dir)) {
            let shown = path.strip_prefix(root).unwrap_or(&path).display().to_string();
            if let Ok(text) = fs::read_to_string(&path) {
                documents.push((shown, text, false));
            }
        }
    }

    for (name, text, fenced) in &documents {
        for (lineno, reference) in code_references(text, *fenced) {
            checked += 1;
            if let Err(why) = check_reference(&reference) {
                broken.push(format!("{name}:{lineno} - {why}"));
            }
        }
    }

    assert!(
        broken.is_empty(),
        "{} of {checked} code references have drifted:\n{}",
        broken.len(),
        broken.join("\n")
    );
}

/// Proves the check above can actually fail.
///
/// With no such references in the tree right now, the test above passes
/// whether or not it works - so this pins the behaviour directly. Without
/// it, a broken scanner and a clean tree look identical.
/// @requirement AC-134
#[test]
fn the_reference_check_detects_a_broken_reference() {
    // Extraction: real references are found, fenced ones are not. The
    // fixtures are assembled at runtime so this file does not itself
    // contain the patterns it is testing for - the scanner reads its own
    // source like any other.
    let file_form = format!("proto.rs:{}", 1);
    let item_form = format!("some_item:{}", 7);
    let sample = format!("see `{file_form}` and `{item_form}`");
    let found = code_references(&sample, true);
    assert_eq!(found.len(), 2, "both forms must be recognised: {found:?}");

    let fenced = code_references("```sh\nopenssl -pkeyopt rsa_keygen_bits:4096\n```", true);
    assert!(
        fenced.is_empty(),
        "shell arguments inside a fence are not code references: {fenced:?}"
    );

    // Validation: a file that does not exist, and a line past the end.
    assert!(
        check_reference(&CodeRef::FileLine {
            file: "no/such/file.rs".into(),
            line: 1
        })
        .is_err()
    );
    assert!(
        check_reference(&CodeRef::FileLine {
            file: "proto.rs".into(),
            line: 900_000
        })
        .is_err(),
        "a line past the end of a real file must be caught"
    );
    assert!(
        check_reference(&CodeRef::FileLine {
            file: "proto.rs".into(),
            line: 1
        })
        .is_ok(),
        "a real file and a real line must pass"
    );

    // An item that exists, at the wrong line, must be rejected; at the
    // right line, accepted.
    let source = fs::read_to_string(repo_root().join("src/proto.rs")).expect("proto.rs");
    let (line, _) = source
        .lines()
        .enumerate()
        .find(|(_, l)| l.trim_start().starts_with("pub fn encode"))
        .expect("proto.rs declares encode");
    assert!(
        check_reference(&CodeRef::ItemLine {
            item: "encode".into(),
            line: line + 1
        })
        .is_ok(),
        "the real declaration line of `encode` must pass"
    );
    assert!(
        check_reference(&CodeRef::ItemLine {
            item: "encode".into(),
            line: line + 500
        })
        .is_err(),
        "a stale line number for a real item must be caught"
    );
    assert!(
        check_reference(&CodeRef::ItemLine {
            item: "definitely_not_a_real_item".into(),
            line: 1
        })
        .is_err()
    );
}
