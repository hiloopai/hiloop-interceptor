//! `inspect` subcommand: load a captured events file and report it.
//!
//! IO and presentation only; the rollup logic lives in
//! [`hiloop_interceptor::inspect`] so it can be unit-tested without files.

use std::{path::Path, process::ExitCode};

use anyhow::{Context, Result};
use hiloop_core::event::Event;
use hiloop_interceptor::inspect::{InspectSummary, diff_event_names, summarize};

pub(crate) fn run(events_jsonl: &Path, diff: Option<(&str, &str)>) -> Result<ExitCode> {
    let events = read_events(events_jsonl)?;
    let summary = summarize(&events);

    let mut out = String::new();
    match diff {
        Some((path_a, path_b)) => render_diff(&mut out, &summary, path_a, path_b),
        None => render_summary(&mut out, &summary),
    }
    print!("{out}");

    Ok(ExitCode::SUCCESS)
}

fn read_events(path: &Path) -> Result<Vec<Event>> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read events file `{}`", path.display()))?;

    let mut events = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let event = serde_json::from_str::<Event>(line)
            .with_context(|| format!("invalid event JSON on line {}", index + 1))?;
        events.push(event);
    }
    Ok(events)
}

fn render_summary(out: &mut String, summary: &InspectSummary) {
    use std::fmt::Write as _;

    let _ = writeln!(
        out,
        "{} events across {} fork path(s)",
        summary.total_events,
        summary.paths.len()
    );
    for path in &summary.paths {
        let _ = writeln!(
            out,
            "\n  {} — {} event(s)",
            display_path(&path.fork_path),
            path.events
        );
        let signals = path
            .by_signal
            .iter()
            .map(|(label, count)| format!("{label}={count}"))
            .collect::<Vec<_>>()
            .join(" ");
        let _ = writeln!(out, "    signals: {signals}");
        for (name, count) in &path.by_name {
            let _ = writeln!(out, "    {name}: {count}");
        }
    }
}

fn render_diff(out: &mut String, summary: &InspectSummary, path_a: &str, path_b: &str) {
    use std::fmt::Write as _;

    let deltas = diff_event_names(summary, path_a, path_b);
    let _ = writeln!(
        out,
        "event-name divergence: {} (a) vs {} (b)",
        display_path(path_a),
        display_path(path_b)
    );
    if deltas.is_empty() {
        let _ = writeln!(out, "  (no divergence)");
        return;
    }
    for delta in deltas {
        let _ = writeln!(out, "  {}: a={} b={}", delta.name, delta.a, delta.b);
    }
}

fn display_path(fork_path: &str) -> &str {
    if fork_path.is_empty() {
        "(root)"
    } else {
        fork_path
    }
}
