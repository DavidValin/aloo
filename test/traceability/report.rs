//! Renders the traceability model into the three artefacts CI publishes:
//! a browsable HTML report, a JSON dump for other tooling, and a Markdown
//! matrix for review in a pull request.
//!
//! All three are generated from the same `Model` + `Report` the CI gate uses,
//! so the matrix cannot disagree with the thing that decides whether the
//! build passes.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;

use crate::model::{Model, ReqKind, TestKind, TestLink, TestOutcome};
use crate::validate::{Report, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pass,
    Fail,
    Skipped,
    NotImplemented,
    NoTestLinked,
    NotRun,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Fail => "FAIL",
            Status::Skipped => "SKIPPED",
            Status::NotImplemented => "NOT IMPLEMENTED",
            Status::NoTestLinked => "NO TEST LINKED",
            Status::NotRun => "NOT RUN",
        }
    }

    fn css(self) -> &'static str {
        match self {
            Status::Pass => "pass",
            Status::Fail => "fail",
            Status::Skipped => "skip",
            Status::NotImplemented => "notimpl",
            Status::NoTestLinked => "notest",
            Status::NotRun => "notrun",
        }
    }

    /// Worst-wins, so a story is only green when everything under it is.
    fn rank(self) -> u8 {
        match self {
            Status::Fail => 0,
            Status::NoTestLinked => 1,
            Status::NotImplemented => 2,
            Status::Skipped => 3,
            Status::NotRun => 4,
            Status::Pass => 5,
        }
    }
}

pub fn status_of_requirement(model: &Model, id: &str) -> Status {
    reduce(model, &model.tests_for(id)).0
}

fn status_of_test(model: &Model, test: &TestLink) -> Status {
    match model.outcome_of(test) {
        Some(TestOutcome::Passed) => Status::Pass,
        Some(TestOutcome::Failed) => Status::Fail,
        Some(TestOutcome::Ignored) => Status::Skipped,
        Some(TestOutcome::NotImplemented) => Status::NotImplemented,
        None if test.ignored => Status::Skipped,
        None => Status::NotRun,
    }
}

/// Worst-wins status plus pass/fail/other tallies over an arbitrary slice of
/// tests - shared by `status_of_requirement` (all tests for one id) and the
/// feature/story/requirement tree (a bucket-scoped subset of those tests).
fn reduce(model: &Model, tests: &[&TestLink]) -> (Status, usize, usize, usize) {
    if tests.is_empty() {
        return (Status::NoTestLinked, 0, 0, 0);
    }
    let outcomes: Vec<Option<TestOutcome>> = tests.iter().map(|t| model.outcome_of(t)).collect();
    let mut pass = 0;
    let mut fail = 0;
    let mut other = 0;
    for t in tests {
        match status_of_test(model, t) {
            Status::Pass => pass += 1,
            Status::Fail => fail += 1,
            _ => other += 1,
        }
    }
    let status = if outcomes.iter().any(|o| *o == Some(TestOutcome::Failed)) {
        Status::Fail
    } else if outcomes
        .iter()
        .any(|o| *o == Some(TestOutcome::NotImplemented))
    {
        // A scenario with no matching steps is worse than an untested
        // requirement dressed up as a passing one, so it outranks any
        // sibling that did pass.
        Status::NotImplemented
    } else if outcomes.iter().any(|o| *o == Some(TestOutcome::Passed)) {
        Status::Pass
    } else if tests.iter().all(|t| t.ignored) {
        Status::Skipped
    } else if outcomes.iter().all(|o| o.is_none()) {
        Status::NotRun
    } else {
        Status::Skipped
    };
    (status, pass, fail, other)
}

fn story_status(model: &Model, story: &str) -> Status {
    model
        .requirements_of(story)
        .iter()
        .filter(|r| r.kind != ReqKind::Story)
        .map(|r| status_of_requirement(model, &r.id))
        .min_by_key(|s| s.rank())
        .unwrap_or(Status::NoTestLinked)
}

/// Label for the synthetic top-level bucket holding requirements with no
/// Gherkin scenario at all - Rust-only tests, or no test whatsoever.
const NO_FEATURE_LABEL: &str = "No Gherkin feature (Rust tests / untested)";

/// Every distinct Gherkin `Feature:` title in the model, alphabetical,
/// followed by the synthetic `None` bucket (always last).
fn feature_buckets(model: &Model) -> Vec<Option<String>> {
    let names: std::collections::BTreeSet<String> =
        model.tests.iter().filter_map(|t| t.feature.clone()).collect();
    let mut out: Vec<Option<String>> = names.into_iter().map(Some).collect();
    out.push(None);
    out
}

/// The tests linked to `entry_id` that belong to `bucket` - `Some(name)` for
/// a real Gherkin feature, or `None` for the synthetic bucket (which selects
/// every test with no feature, i.e. Rust tests).
fn tests_in_bucket<'m>(
    model: &'m Model,
    entry_id: &str,
    bucket: &Option<String>,
) -> Vec<&'m TestLink> {
    model
        .tests_for(entry_id)
        .into_iter()
        .filter(|t| t.feature == *bucket)
        .collect()
}

/// Distinct free-form tags on tests in this feature bucket, sorted, plus a
/// trailing `None` if any of them carry no tag at all. `vec![None]` (the
/// single implicit group) means this feature uses no such tags, so the tag
/// level is skipped entirely when rendering.
fn tag_groups_for_feature(model: &Model, bucket: &Option<String>) -> Vec<Option<String>> {
    let mut tags = std::collections::BTreeSet::new();
    let mut has_untagged = false;
    for test in &model.tests {
        if test.feature != *bucket {
            continue;
        }
        if test.tags.is_empty() {
            has_untagged = true;
        } else {
            tags.extend(test.tags.iter().cloned());
        }
    }
    if tags.is_empty() {
        return vec![None];
    }
    let mut out: Vec<Option<String>> = tags.into_iter().map(Some).collect();
    if has_untagged {
        out.push(None);
    }
    out
}

fn test_matches_tag(test: &TestLink, tag: &Option<String>) -> bool {
    match tag {
        Some(t) => test.tags.iter().any(|x| x == t),
        None => test.tags.is_empty(),
    }
}

/// Renders the pass/fail(/other) counts shown at every level of the tree.
fn counts_html(pass: usize, fail: usize, other: usize) -> String {
    if pass + fail + other == 0 {
        return "<span class=\"tag-none\">NO TEST LINKED</span>".to_string();
    }
    let fail_class = if fail == 0 {
        "tag tag-fail-zero"
    } else {
        "tag tag-fail"
    };
    let mut s = format!(
        "<span class=\"tag tag-pass\">{pass} PASS</span><span class=\"{fail_class}\">{fail} FAIL</span>"
    );
    if other > 0 {
        let _ = write!(s, "<span class=\"tag tag-other\">{other} OTHER</span>");
    }
    s
}

pub fn out_dir() -> PathBuf {
    crate::model::repo_root().join("target/traceability")
}

pub fn write_all(model: &Model, report: &Report) -> PathBuf {
    let dir = out_dir();
    std::fs::create_dir_all(&dir).expect("create target/traceability");
    std::fs::write(dir.join("report.html"), html(model, report)).expect("write report.html");
    std::fs::write(dir.join("traceability.json"), json(model, report)).expect("write json");
    std::fs::write(dir.join("traceability-matrix.md"), matrix(model, report))
        .expect("write matrix");
    dir
}

// ---------------------------------------------------------------------
// Counters shared by every output
// ---------------------------------------------------------------------

pub struct Totals {
    pub stories: usize,
    pub acceptance: usize,
    pub technical: usize,
    pub rust_tests: usize,
    pub scenarios: usize,
    pub ignored: usize,
    pub by_status: BTreeMap<&'static str, usize>,
}

pub fn totals(model: &Model) -> Totals {
    let mut by_status: BTreeMap<&'static str, usize> = BTreeMap::new();
    for entry in model.requirements.values() {
        if entry.kind == ReqKind::Story {
            continue;
        }
        *by_status
            .entry(status_of_requirement(model, &entry.id).label())
            .or_insert(0) += 1;
    }
    Totals {
        stories: model.stories.len(),
        acceptance: model
            .requirements
            .values()
            .filter(|r| r.kind == ReqKind::Acceptance)
            .count(),
        technical: model
            .requirements
            .values()
            .filter(|r| r.kind == ReqKind::Technical)
            .count(),
        rust_tests: model
            .tests
            .iter()
            .filter(|t| t.kind == TestKind::Rust)
            .count(),
        scenarios: model
            .tests
            .iter()
            .filter(|t| t.kind == TestKind::Scenario)
            .count(),
        ignored: model.tests.iter().filter(|t| t.ignored).count(),
        by_status,
    }
}

// ---------------------------------------------------------------------
// HTML
// ---------------------------------------------------------------------

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn html(model: &Model, report: &Report) -> String {
    let t = totals(model);
    let mut h = String::new();

    h.push_str(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>aloo traceability</title>
<style>
:root{--bg:#fbfbfd;--fg:#1c1c22;--muted:#6b6b78;--card:#fff;--line:#e3e3ea;
--pass:#137a3f;--fail:#b3261e;--skip:#8a6100;--notest:#b3261e;--notrun:#5b5b6b;--notimpl:#8a6100;}
@media (prefers-color-scheme:dark){:root{--bg:#131318;--fg:#eceef2;--muted:#9a9aa8;--card:#1c1c23;--line:#2e2e38;
--pass:#5ed69a;--fail:#ff8a80;--skip:#ffcf6b;--notest:#ff8a80;--notrun:#a0a0b0;--notimpl:#ffcf6b;}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;padding:32px 20px 80px}
.wrap{max-width:1080px;margin:0 auto}
h1{font-size:26px;margin:0 0 4px}
.sub{color:var(--muted);margin:0 0 24px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:24px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.card b{display:block;font-size:22px;line-height:1.2}
.card span{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.controls{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px;align-items:center}
input,select{background:var(--card);color:var(--fg);border:1px solid var(--line);
border-radius:8px;padding:8px 10px;font:inherit;font-size:14px}
input{flex:1;min-width:220px}
.feature{background:var(--card);border:1px solid var(--line);border-radius:10px;margin-bottom:16px;overflow:hidden}
.feature>summary{cursor:pointer;padding:14px 16px;display:flex;gap:12px;align-items:center;font-weight:700;font-size:16px;list-style:none}
.feature>summary::-webkit-details-marker{display:none}
.feature>summary::before{content:"\25B8";color:var(--muted);transition:transform .15s}
.feature[open]>summary::before{transform:rotate(90deg)}
.feature .story{margin:0 12px 12px}
.feature .mode{margin:0 12px 12px}
.mode{background:var(--card);border:1px solid var(--line);border-radius:9px;margin-bottom:14px;overflow:hidden}
.mode>summary{cursor:pointer;padding:12px 14px;display:flex;gap:12px;align-items:center;font-weight:650;font-size:14.5px;list-style:none;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.mode>summary::-webkit-details-marker{display:none}
.mode>summary::before{content:"\25B8";color:var(--muted);transition:transform .15s}
.mode[open]>summary::before{transform:rotate(90deg)}
.mode .story{margin:0 10px 10px}
.story{background:var(--card);border:1px solid var(--line);border-radius:10px;margin-bottom:14px;overflow:hidden}
.story>summary{cursor:pointer;padding:13px 16px;display:flex;gap:12px;align-items:center;font-weight:600;list-style:none}
.story>summary::-webkit-details-marker{display:none}
.story>summary::before{content:"\25B8";color:var(--muted);transition:transform .15s}
.story[open]>summary::before{transform:rotate(90deg)}
.id{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;color:var(--muted)}
.role{padding:0 16px 10px;margin:0;color:var(--muted);font-size:13px}
.req{border-top:1px solid var(--line)}
.req>summary{cursor:pointer;padding:11px 16px;list-style:none;display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
.req>summary::-webkit-details-marker{display:none}
.req>summary::before{content:"\25B8";color:var(--muted);transition:transform .15s}
.req[open]>summary::before{transform:rotate(90deg)}
.req-body{padding:0 16px 11px}
.req-head{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
.desc{flex:1;min-width:240px}
.kind{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);
border:1px solid var(--line);border-radius:5px;padding:1px 6px}
.badge{font-size:11px;font-weight:700;letter-spacing:.04em;padding:2px 8px;border-radius:20px;
border:1px solid currentColor;white-space:nowrap}
.pass{color:var(--pass)}.fail{color:var(--fail)}.skip{color:var(--skip)}
.notest{color:var(--notest)}.notrun{color:var(--notrun)}.notimpl{color:var(--notimpl)}
.tag{font-size:11px;font-weight:700;letter-spacing:.03em;padding:2px 8px;border-radius:20px;white-space:nowrap}
.tag-pass{background:var(--pass);color:#fff}
.tag-fail{background:var(--fail);color:#fff}
.tag-fail-zero{background:transparent;color:var(--fg)}
.tag-other{background:var(--line);color:var(--muted)}
.tag-none{color:var(--muted);font-weight:600;font-size:12px;white-space:nowrap}
ul.tests{list-style:none;margin:8px 0 0;padding:0 0 0 14px;border-left:2px solid var(--line)}
ul.tests li{padding:3px 0;font-size:13.5px;display:flex;gap:8px;align-items:baseline;flex-wrap:wrap}
.tname{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.tsrc{color:var(--muted);font-size:12px}
.none{color:var(--fail);font-size:13.5px;padding-top:6px}
.ev{color:var(--muted);font-size:12px;margin-top:5px}
table{width:100%;border-collapse:collapse;font-size:13.5px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.findings{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:4px 16px 12px;margin-bottom:24px}
.scroll{overflow-x:auto}
.hidden{display:none!important}
footer{color:var(--muted);font-size:12px;margin-top:32px}
</style>
</head>
<body><div class="wrap">
"#,
    );

    let _ = write!(
        h,
        "<h1>aloo traceability</h1>\n<p class=\"sub\">User stories &rarr; acceptance criteria &amp; technical behaviours &rarr; executable tests. Generated by <code>cargo test --test traceability</code>.</p>\n"
    );

    // summary cards
    h.push_str("<div class=\"cards\">");
    let card = |h: &mut String, n: usize, l: &str, cls: &str| {
        let _ = write!(
            h,
            "<div class=\"card\"><b class=\"{cls}\">{n}</b><span>{l}</span></div>"
        );
    };
    card(&mut h, t.stories, "user stories", "");
    card(&mut h, t.acceptance, "acceptance criteria", "");
    card(&mut h, t.technical, "technical behaviours", "");
    card(&mut h, t.rust_tests, "rust tests", "");
    card(&mut h, t.scenarios, "scenarios", "");
    for (label, n) in &t.by_status {
        let cls = match *label {
            "PASS" => "pass",
            "FAIL" => "fail",
            "SKIPPED" => "skip",
            "NO TEST LINKED" => "notest",
            "NOT IMPLEMENTED" => "notimpl",
            _ => "notrun",
        };
        card(&mut h, *n, label, cls);
    }
    h.push_str("</div>");

    // findings
    if !report.findings.is_empty() {
        h.push_str("<div class=\"findings\"><h2 style=\"font-size:17px\">Validation findings</h2><div class=\"scroll\"><table><tr><th>Severity</th><th>Rule</th><th>Subject</th><th>Detail</th></tr>");
        for f in &report.findings {
            let cls = if f.severity == Severity::Error {
                "fail"
            } else {
                "skip"
            };
            let _ = write!(
                h,
                "<tr><td><span class=\"badge {cls}\">{}</span></td><td class=\"id\">{}</td><td class=\"id\">{}</td><td>{}</td></tr>",
                f.severity.label(),
                esc(f.rule),
                esc(&f.subject),
                esc(&f.detail)
            );
        }
        h.push_str("</table></div></div>");
    }

    // controls
    h.push_str(
        r#"<div class="controls">
<input id="q" type="search" placeholder="Filter by id, description or test name…">
<select id="st">
<option value="">All statuses</option>
<option value="PASS">PASS</option>
<option value="FAIL">FAIL</option>
<option value="SKIPPED">SKIPPED</option>
<option value="NO TEST LINKED">NO TEST LINKED</option>
<option value="NOT RUN">NOT RUN</option>
</select>
<select id="kd">
<option value="">All kinds</option>
<option value="Acceptance">Acceptance only</option>
<option value="Technical">Technical only</option>
</select>
</div>
"#,
    );

    // the tree: Gherkin feature -> encryption-mode tag (if any) -> user story -> acceptance criteria -> scenario
    for bucket in feature_buckets(model) {
        let tag_groups = tag_groups_for_feature(model, &bucket);
        let show_tags = !(tag_groups.len() == 1 && tag_groups[0].is_none());

        let mut tag_sections = Vec::new();
        for tag in &tag_groups {
            let mut story_sections = Vec::new();
            for story in &model.stories {
                let mut matched = Vec::new();
                for entry in model.requirements_of(&story.id) {
                    if entry.kind == ReqKind::Story {
                        continue;
                    }
                    let mut tests = tests_in_bucket(model, &entry.id, &bucket);
                    tests.retain(|t| test_matches_tag(t, tag));
                    let include = if bucket.is_some() {
                        !tests.is_empty()
                    } else {
                        !tests.is_empty() || model.tests_for(&entry.id).is_empty()
                    };
                    if include {
                        matched.push((entry, tests));
                    }
                }
                if !matched.is_empty() {
                    story_sections.push((story, matched));
                }
            }
            if !story_sections.is_empty() {
                tag_sections.push((tag.clone(), story_sections));
            }
        }
        if tag_sections.is_empty() {
            continue;
        }

        let feature_tests: Vec<&TestLink> = tag_sections
            .iter()
            .flat_map(|(_, story_sections): &(_, Vec<_>)| {
                story_sections.iter().flat_map(|(_, matched): &(_, Vec<_>)| {
                    matched
                        .iter()
                        .flat_map(|(_, tests): &(_, Vec<&TestLink>)| tests.iter().copied())
                })
            })
            .collect();
        let (_, fpass, ffail, fother) = reduce(model, &feature_tests);
        let feature_name = bucket.clone().unwrap_or_else(|| NO_FEATURE_LABEL.to_string());
        let _ = write!(
            h,
            "<details class=\"feature\"><summary><span style=\"flex:1\">{}</span>{}</summary>\n",
            esc(&feature_name),
            counts_html(fpass, ffail, fother),
        );

        for (tag, story_sections) in tag_sections {
            if show_tags {
                let tag_tests: Vec<&TestLink> = story_sections
                    .iter()
                    .flat_map(|(_, matched): &(_, Vec<_>)| {
                        matched
                            .iter()
                            .flat_map(|(_, tests): &(_, Vec<&TestLink>)| tests.iter().copied())
                    })
                    .collect();
                let (_, mpass, mfail, mother) = reduce(model, &tag_tests);
                let tag_heading = match &tag {
                    Some(t) => format!("@{t}"),
                    None => "untagged".to_string(),
                };
                let _ = write!(
                    h,
                    "<details class=\"mode\"><summary><span style=\"flex:1\">{}</span>{}</summary>\n",
                    esc(&tag_heading),
                    counts_html(mpass, mfail, mother),
                );
            }

        for (story, matched) in story_sections {
            let story_tests: Vec<&TestLink> = matched
                .iter()
                .flat_map(|(_, tests): &(_, Vec<&TestLink>)| tests.iter().copied())
                .collect();
            let (_, spass, sfail, sother) = reduce(model, &story_tests);
            let _ = write!(
                h,
                "<details class=\"story\"><summary><span class=\"id\">{}</span><span style=\"flex:1\">{}</span>{}</summary>\n<p class=\"role\">As {}, I want {} so that {}.</p>\n",
                esc(&story.id),
                esc(&story.title),
                counts_html(spass, sfail, sother),
                esc(&story.as_a),
                esc(&story.i_want),
                esc(&story.so_that),
            );

            for (entry, tests) in matched {
                let (status, rpass, rfail, rother) = reduce(model, &tests);
                let haystack = format!(
                    "{} {} {}",
                    entry.id,
                    entry.description,
                    tests
                        .iter()
                        .map(|t| t.name.as_str())
                        .collect::<Vec<_>>()
                        .join(" ")
                );
                let _ = write!(
                    h,
                    "<details class=\"req\" data-status=\"{}\" data-kind=\"{}\" data-search=\"{}\">\n<summary class=\"req-head\"><span class=\"id\">{}</span><span class=\"kind\">{}</span><span class=\"desc\">{}</span>{}</summary>\n<div class=\"req-body\">\n",
                    status.label(),
                    entry.kind.label(),
                    esc(&haystack.to_lowercase()),
                    esc(&entry.id),
                    entry.kind.label(),
                    esc(&entry.description),
                    counts_html(rpass, rfail, rother),
                );

                if tests.is_empty() {
                    h.push_str(
                        "<p class=\"none\">No executable test is linked to this requirement.</p>",
                    );
                } else {
                    h.push_str("<ul class=\"tests\">");
                    for test in tests {
                        let ts = status_of_test(model, test);
                        let _ = write!(
                            h,
                            "<li><span class=\"badge {}\">{}</span><span class=\"tname\">{}</span><span class=\"tsrc\">{} &middot; {}:{}{}</span></li>",
                            ts.css(),
                            ts.label(),
                            esc(&test.name),
                            test.kind.label(),
                            esc(&test.file.display().to_string()),
                            test.line,
                            if test.ignored {
                                " &middot; #[ignore]"
                            } else {
                                ""
                            },
                        );
                    }
                    h.push_str("</ul>");
                }
                if !entry.evidence.is_empty() {
                    let _ = write!(h, "<p class=\"ev\">Evidence: {}</p>", esc(&entry.evidence));
                }
                h.push_str("</div>\n</details>\n");
            }
            h.push_str("</details>\n");
        }
            if show_tags {
                h.push_str("</details>\n");
            }
        }
        h.push_str("</details>\n");
    }

    let _ = write!(
        h,
        "<footer>{} requirement links across {} rust tests and {} scenarios; {} test(s) are <code>#[ignore]</code>d.</footer>",
        model
            .tests
            .iter()
            .map(|t| t.requirements.len())
            .sum::<usize>(),
        t.rust_tests,
        t.scenarios,
        t.ignored
    );

    h.push_str(
        r#"</div>
<script>
const q=document.getElementById('q'),st=document.getElementById('st'),kd=document.getElementById('kd');
function apply(){
  const term=q.value.trim().toLowerCase(), s=st.value, k=kd.value;
  const filtering=term||s||k;
  function applyStory(story){
    let shown=0;
    story.querySelectorAll('.req').forEach(r=>{
      const ok=(!term||r.dataset.search.includes(term))
            &&(!s||r.dataset.status===s)
            &&(!k||r.dataset.kind===k);
      r.classList.toggle('hidden',!ok); if(ok)shown++;
      if(filtering)r.open=ok;
    });
    story.classList.toggle('hidden',shown===0);
    if(filtering)story.open=shown>0;
    return shown>0;
  }
  document.querySelectorAll('details.feature').forEach(feature=>{
    let featureShown=0;
    feature.querySelectorAll(':scope > details.mode').forEach(mode=>{
      let modeShown=0;
      mode.querySelectorAll(':scope > details.story').forEach(story=>{
        if(applyStory(story))modeShown++;
      });
      mode.classList.toggle('hidden',modeShown===0);
      if(filtering)mode.open=modeShown>0;
      if(modeShown>0)featureShown++;
    });
    feature.querySelectorAll(':scope > details.story').forEach(story=>{
      if(applyStory(story))featureShown++;
    });
    feature.classList.toggle('hidden',featureShown===0);
    if(filtering)feature.open=featureShown>0;
  });
}
[q,st,kd].forEach(el=>el.addEventListener('input',apply));
</script>
</body></html>"#,
    );
    h
}

// ---------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------

fn jstr(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn json(model: &Model, report: &Report) -> String {
    let t = totals(model);
    let mut j = String::new();
    j.push_str("{\n  \"summary\": {");
    let _ = write!(
        j,
        "\"user_stories\":{},\"acceptance_criteria\":{},\"technical_behaviors\":{},\"rust_tests\":{},\"scenarios\":{},\"ignored_tests\":{},\"errors\":{},\"warnings\":{}",
        t.stories,
        t.acceptance,
        t.technical,
        t.rust_tests,
        t.scenarios,
        t.ignored,
        report.errors().len(),
        report.warnings().len()
    );
    j.push_str("},\n  \"user_stories\": [\n");

    for (si, story) in model.stories.iter().enumerate() {
        let _ = write!(
            j,
            "    {{\"id\":{},\"title\":{},\"as_a\":{},\"i_want\":{},\"so_that\":{},\"status\":{},\"requirements\":[\n",
            jstr(&story.id),
            jstr(&story.title),
            jstr(&story.as_a),
            jstr(&story.i_want),
            jstr(&story.so_that),
            jstr(story_status(model, &story.id).label())
        );
        let reqs: Vec<_> = model
            .requirements_of(&story.id)
            .into_iter()
            .filter(|r| r.kind != ReqKind::Story)
            .collect();
        for (ri, entry) in reqs.iter().enumerate() {
            let tests = model.tests_for(&entry.id);
            let _ = write!(
                j,
                "      {{\"id\":{},\"type\":{},\"description\":{},\"evidence\":{},\"status\":{},\"tests\":[",
                jstr(&entry.id),
                jstr(entry.kind.label()),
                jstr(&entry.description),
                jstr(&entry.evidence),
                jstr(status_of_requirement(model, &entry.id).label())
            );
            for (ti, test) in tests.iter().enumerate() {
                let _ = write!(
                    j,
                    "{{\"id\":{},\"name\":{},\"kind\":{},\"file\":{},\"line\":{},\"ignored\":{},\"status\":{}}}",
                    jstr(&test.id),
                    jstr(&test.name),
                    jstr(test.kind.label()),
                    jstr(&test.file.display().to_string()),
                    test.line,
                    test.ignored,
                    jstr(status_of_test(model, test).label())
                );
                if ti + 1 < tests.len() {
                    j.push(',');
                }
            }
            j.push_str("]}");
            if ri + 1 < reqs.len() {
                j.push(',');
            }
            j.push('\n');
        }
        j.push_str("    ]}");
        if si + 1 < model.stories.len() {
            j.push(',');
        }
        j.push('\n');
    }

    j.push_str("  ],\n  \"findings\": [\n");
    for (i, f) in report.findings.iter().enumerate() {
        let _ = write!(
            j,
            "    {{\"severity\":{},\"rule\":{},\"subject\":{},\"detail\":{}}}",
            jstr(f.severity.label()),
            jstr(f.rule),
            jstr(&f.subject),
            jstr(&f.detail)
        );
        if i + 1 < report.findings.len() {
            j.push(',');
        }
        j.push('\n');
    }
    j.push_str("  ]\n}\n");
    j
}

// ---------------------------------------------------------------------
// Markdown matrix
// ---------------------------------------------------------------------

fn matrix(model: &Model, report: &Report) -> String {
    let t = totals(model);
    let mut m = String::new();
    m.push_str("# Traceability matrix\n\n");
    m.push_str("> Generated by `cargo test --test traceability`. Do not edit by hand -\n");
    m.push_str("> edit `requirements/requirements.toml` or the `@requirement` / `@AC-…` links in the tests.\n\n");

    let _ = write!(
        m,
        "| User stories | Acceptance criteria | Technical behaviours | Rust tests | Scenarios | Errors | Warnings |\n|---:|---:|---:|---:|---:|---:|---:|\n| {} | {} | {} | {} | {} | {} | {} |\n\n",
        t.stories,
        t.acceptance,
        t.technical,
        t.rust_tests,
        t.scenarios,
        report.errors().len(),
        report.warnings().len()
    );

    m.push_str("## Requirement coverage\n\n");
    m.push_str("| Requirement | Type | Description | Tests | Status |\n|---|---|---|---:|---|\n");
    for story in &model.stories {
        let _ = write!(
            m,
            "| **{}** | Story | **{}** | {} | {} |\n",
            story.id,
            story.title.replace('|', "\\|"),
            model
                .requirements_of(&story.id)
                .iter()
                .filter(|r| r.kind != ReqKind::Story)
                .map(|r| model.tests_for(&r.id).len())
                .sum::<usize>(),
            story_status(model, &story.id).label()
        );
        for entry in model.requirements_of(&story.id) {
            if entry.kind == ReqKind::Story {
                continue;
            }
            let _ = write!(
                m,
                "| {} | {} | {} | {} | {} |\n",
                entry.id,
                entry.kind.label(),
                entry.description.replace('|', "\\|"),
                model.tests_for(&entry.id).len(),
                status_of_requirement(model, &entry.id).label()
            );
        }
    }

    m.push_str("\n## Test index\n\n");
    m.push_str("Every executable test and the requirements it proves.\n\n");
    m.push_str("| Test | Kind | Location | Requirements |\n|---|---|---|---|\n");
    for test in &model.tests {
        let _ = write!(
            m,
            "| `{}`{} | {} | {}:{} | {} |\n",
            test.name.replace('|', "\\|"),
            if test.ignored { " *(ignored)*" } else { "" },
            test.kind.label(),
            test.file.display(),
            test.line,
            test.requirements.join(", ")
        );
    }

    if !report.findings.is_empty() {
        m.push_str("\n## Findings\n\n| Severity | Rule | Subject | Detail |\n|---|---|---|---|\n");
        for f in &report.findings {
            let _ = write!(
                m,
                "| {} | {} | {} | {} |\n",
                f.severity.label(),
                f.rule,
                f.subject,
                f.detail.replace('|', "\\|")
            );
        }
    }
    m
}
