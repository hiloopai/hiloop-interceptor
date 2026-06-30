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
        Some((path_a, path_b)) => render_diff(&mut out, &summary, path_a, path_b)?,
        None => render_summary(&mut out, &summary)?,
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

fn render_summary(out: &mut String, summary: &InspectSummary) -> Result<()> {
    use std::fmt::Write as _;

    writeln!(
        out,
        "{} events across {} run lineage path(s)",
        summary.total_events,
        summary.paths.len()
    )
    .context("failed to format summary header")?;
    for path in &summary.paths {
        writeln!(
            out,
            "\n  {} \u{2014} {} event(s)",
            path.lineage_path, path.events
        )
        .context("failed to format path summary")?;
        let signals = path
            .by_signal
            .iter()
            .map(|(label, count)| format!("{label}={count}"))
            .collect::<Vec<_>>()
            .join(" ");
        writeln!(out, "    signals: {signals}").context("failed to format signals")?;
        for (name, count) in &path.by_name {
            writeln!(out, "    {name}: {count}").context("failed to format event name")?;
        }
    }
    Ok(())
}

fn render_diff(
    out: &mut String,
    summary: &InspectSummary,
    path_a: &str,
    path_b: &str,
) -> Result<()> {
    use std::fmt::Write as _;

    let deltas = diff_event_names(summary, path_a, path_b);
    writeln!(out, "event-name divergence: {path_a} (a) vs {path_b} (b)")
        .context("failed to format diff header")?;
    if deltas.is_empty() {
        writeln!(out, "  (no divergence)").context("failed to format diff")?;
        return Ok(());
    }
    for delta in deltas {
        writeln!(out, "  {}: a={} b={}", delta.name, delta.a, delta.b)
            .context("failed to format diff delta")?;
    }
    Ok(())
}
