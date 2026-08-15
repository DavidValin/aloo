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
    let tests = model.tests_for(id);
    if tests.is_empty() {
        return Status::NoTestLinked;
    }
    let outcomes: Vec<Option<TestOutcome>> = tests.iter().map(|t| model.outcome_of(t)).collect();
    if outcomes.iter().any(|o| *o == Some(TestOutcome::Failed)) {
        return Status::Fail;
    }
    // A scenario with no matching steps is worse than an untested requirement
    // dressed up as a passing one, so it outranks any sibling that did pass.
    if outcomes.iter().any(|o| *o == Some(TestOutcome::NotImplemented)) {
        return Status::NotImplemented;
    }
    if outcomes.iter().any(|o| *o == Some(TestOutcome::Passed)) {
        return Status::Pass;
    }
    if tests.iter().all(|t| t.ignored) {
        return Status::Skipped;
    }
    if outcomes.iter().all(|o| o.is_none()) {
        return Status::NotRun;
    }
    Status::Skipped
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

fn story_status(model: &Model, story: &str) -> Status {
    model
        .requirements_of(story)
        .iter()
        .filter(|r| r.kind != ReqKind::Story)
        .map(|r| status_of_requirement(model, &r.id))
        .min_by_key(|s| s.rank())
        .unwrap_or(Status::NoTestLinked)
}

pub fn out_dir() -> PathBuf {
    crate::model::repo_root().join("target/traceability")
}

pub fn write_all(model: &Model, report: &Report) -> PathBuf {
    let dir = out_dir();
    std::fs::create_dir_all(&dir).expect("create target/traceability");
    std::fs::write(dir.join("report.html"), html(model, report)).expect("write report.html");
    std::fs::write(dir.join("traceability.json"), json(model, report)).expect("write json");
    std::fs::write(dir.join("traceability-matrix.md"), matrix(model, report)).expect("write matrix");
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
        *by_status.entry(status_of_requirement(model, &entry.id).label()).or_insert(0) += 1;
    }
    Totals {
        stories: model.stories.len(),
        acceptance: model.requirements.values().filter(|r| r.kind == ReqKind::Acceptance).count(),
        technical: model.requirements.values().filter(|r| r.kind == ReqKind::Technical).count(),
        rust_tests: model.tests.iter().filter(|t| t.kind == TestKind::Rust).count(),
        scenarios: model.tests.iter().filter(|t| t.kind == TestKind::Scenario).count(),
        ignored: model.tests.iter().filter(|t| t.ignored).count(),
        by_status,
    }
}

// ---------------------------------------------------------------------
// HTML
// ---------------------------------------------------------------------

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
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
.story{background:var(--card);border:1px solid var(--line);border-radius:10px;margin-bottom:14px;overflow:hidden}
.story>summary{cursor:pointer;padding:13px 16px;display:flex;gap:12px;align-items:center;font-weight:600;list-style:none}
.story>summary::-webkit-details-marker{display:none}
.story>summary::before{content:"\25B8";color:var(--muted);transition:transform .15s}
.story[open]>summary::before{transform:rotate(90deg)}
.id{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;color:var(--muted)}
.role{padding:0 16px 10px;margin:0;color:var(--muted);font-size:13px}
.req{border-top:1px solid var(--line);padding:11px 16px}
.req-head{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
.desc{flex:1;min-width:240px}
.kind{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);
border:1px solid var(--line);border-radius:5px;padding:1px 6px}
.badge{font-size:11px;font-weight:700;letter-spacing:.04em;padding:2px 8px;border-radius:20px;
border:1px solid currentColor;white-space:nowrap}
.pass{color:var(--pass)}.fail{color:var(--fail)}.skip{color:var(--skip)}
.notest{color:var(--notest)}.notrun{color:var(--notrun)}.notimpl{color:var(--notimpl)}
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
        let _ = write!(h, "<div class=\"card\"><b class=\"{cls}\">{n}</b><span>{l}</span></div>");
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
            let cls = if f.severity == Severity::Error { "fail" } else { "skip" };
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

    // the tree
    for story in &model.stories {
        let st = story_status(model, &story.id);
        let _ = write!(
            h,
            "<details class=\"story\" open><summary><span class=\"id\">{}</span><span style=\"flex:1\">{}</span><span class=\"badge {}\">{}</span></summary>\n<p class=\"role\">As {}, I want {} so that {}.</p>\n",
            esc(&story.id),
            esc(&story.title),
            st.css(),
            st.label(),
            esc(&story.as_a),
            esc(&story.i_want),
            esc(&story.so_that),
        );

        for entry in model.requirements_of(&story.id) {
            if entry.kind == ReqKind::Story {
                continue;
            }
            let status = status_of_requirement(model, &entry.id);
            let tests = model.tests_for(&entry.id);
            let haystack = format!(
                "{} {} {}",
                entry.id,
                entry.description,
                tests.iter().map(|t| t.name.as_str()).collect::<Vec<_>>().join(" ")
            );
            let _ = write!(
                h,
                "<div class=\"req\" data-status=\"{}\" data-kind=\"{}\" data-search=\"{}\">\n<div class=\"req-head\"><span class=\"id\">{}</span><span class=\"kind\">{}</span><span class=\"desc\">{}</span><span class=\"badge {}\">{}</span></div>\n",
                status.label(),
                entry.kind.label(),
                esc(&haystack.to_lowercase()),
                esc(&entry.id),
                entry.kind.label(),
                esc(&entry.description),
                status.css(),
                status.label(),
            );

            if tests.is_empty() {
                h.push_str("<p class=\"none\">No executable test is linked to this requirement.</p>");
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
                        if test.ignored { " &middot; #[ignore]" } else { "" },
                    );
                }
                h.push_str("</ul>");
            }
            if !entry.evidence.is_empty() {
                let _ = write!(h, "<p class=\"ev\">Evidence: {}</p>", esc(&entry.evidence));
            }
            h.push_str("</div>\n");
        }
        h.push_str("</details>\n");
    }

    let _ = write!(
        h,
        "<footer>{} requirement links across {} rust tests and {} scenarios; {} test(s) are <code>#[ignore]</code>d.</footer>",
        model.tests.iter().map(|t| t.requirements.len()).sum::<usize>(),
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
  document.querySelectorAll('details.story').forEach(story=>{
    let shown=0;
    story.querySelectorAll('.req').forEach(r=>{
      const ok=(!term||r.dataset.search.includes(term))
            &&(!s||r.dataset.status===s)
            &&(!k||r.dataset.kind===k);
      r.classList.toggle('hidden',!ok); if(ok)shown++;
    });
    story.classList.toggle('hidden',shown===0);
    if(term||s||k)story.open=true;
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
        let reqs: Vec<_> =
            model.requirements_of(&story.id).into_iter().filter(|r| r.kind != ReqKind::Story).collect();
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
