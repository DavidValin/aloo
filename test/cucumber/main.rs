//! Cucumber runner for the acceptance layer.
//!
//! Executes every `.feature` under `features/`. Each scenario is tagged with
//! the requirement ids it proves (`@AC-024`, `@TB-029`, ...); those tags are
//! what `cargo test --test traceability` reads to build the traceability
//! model, so a scenario without a tag is reported rather than silently
//! uncounted.
//!
//! Run just this layer with `cargo test --test cucumber`. It is deliberately
//! cheap - the only real RSA keygen happens once, into `world::key_pool()`.

mod steps;
mod support;
mod world;

use std::io::Write as _;
use std::sync::Mutex;

use cucumber::{World as _, event::ScenarioFinished};

use world::AlooWorld;

/// Per-scenario outcomes, written out for the traceability report once the
/// run finishes. Recorded in libtest's own `test <name> ... <verdict>` shape
/// so the report reads Rust tests and scenarios through one parser instead of
/// two.
static OUTCOMES: Mutex<Vec<String>> = Mutex::new(Vec::new());

#[tokio::main]
async fn main() {
    AlooWorld::cucumber()
        .after(|feature, _rule, scenario, ev, _world| {
            let stem = feature
                .path
                .as_ref()
                .and_then(|p| p.file_stem())
                .and_then(|s| s.to_str())
                .unwrap_or("feature")
                .to_string();
            let name = scenario.name.clone();
            let verdict = match ev {
                ScenarioFinished::StepPassed => "ok",
                // A skipped step means no step definition matched it: the
                // scenario is written but not implemented, which the report
                // shows as NOT IMPLEMENTED rather than quietly as a pass.
                ScenarioFinished::StepSkipped => "undefined",
                ScenarioFinished::StepFailed(..) | ScenarioFinished::BeforeHookFailed(..) => {
                    "FAILED"
                }
            };
            let mut out = OUTCOMES.lock().expect("outcomes lock");
            out.push(format!("test {name} ... {verdict}"));
            out.push(format!("test {stem}::{name} ... {verdict}"));
            Box::pin(async {})
        })
        // An unmatched step is a hole in the acceptance layer, not a pass.
        .fail_on_skipped()
        .run("features")
        .await;

    write_outcomes();
}

fn write_outcomes() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/traceability");
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let path = dir.join("cucumber-results.txt");
    let Ok(mut file) = std::fs::File::create(&path) else {
        return;
    };
    let out = OUTCOMES.lock().expect("outcomes lock");
    for line in out.iter() {
        let _ = writeln!(file, "{line}");
    }
    println!(
        "\ncucumber: {} scenario outcome(s) written to {}",
        out.len() / 2,
        path.display()
    );
}
