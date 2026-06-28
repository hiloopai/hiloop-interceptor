//! Read-side inspection of captured events.
//!
//! Groups a run's events by fork-tree node so a dogfooding session can see what
//! was captured per branch, and compares two branches' event-name distributions
//! — the first taste of the branch-diff observability the system is built for.
//!
//! This module is pure analysis over already-parsed [`Event`]s. File IO and
//! presentation live in the binary so the rollup logic stays unit-testable.

use std::collections::BTreeMap;

use hiloop_core::event::{Event, SignalType};

/// Per-fork-path rollup of captured events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathSummary {
    /// Fork path as serialized; the empty string is the run root.
    pub fork_path: String,
    pub events: usize,
    /// Event count per signal family, keyed by the family's canonical label.
    pub by_signal: BTreeMap<&'static str, usize>,
    /// Event count per event name.
    pub by_name: BTreeMap<String, usize>,
}

impl PathSummary {
    fn new(fork_path: String) -> Self {
        Self {
            fork_path,
            events: 0,
            by_signal: BTreeMap::new(),
            by_name: BTreeMap::new(),
        }
    }
}

/// A captured event set summarized and grouped by fork path.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InspectSummary {
    pub total_events: usize,
    /// Per-path summaries, ordered by fork path.
    pub paths: Vec<PathSummary>,
}

impl InspectSummary {
    /// Find the summary for one fork path, if it has any events.
    pub fn path(&self, fork_path: &str) -> Option<&PathSummary> {
        self.paths.iter().find(|path| path.fork_path == fork_path)
    }
}

/// One event name's count in each of two compared fork paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameDelta {
    pub name: String,
    pub a: usize,
    pub b: usize,
}

/// Roll events up by fork path. Paths and names are ordered deterministically.
#[must_use]
pub fn summarize(events: &[Event]) -> InspectSummary {
    let mut by_path: BTreeMap<String, PathSummary> = BTreeMap::new();
    for event in events {
        let key = event.fork_path.to_string();
        let summary = by_path
            .entry(key.clone())
            .or_insert_with(|| PathSummary::new(key));
        summary.events += 1;
        *summary
            .by_signal
            .entry(signal_label(event.signal))
            .or_default() += 1;
        *summary.by_name.entry(event.name.to_string()).or_default() += 1;
    }

    InspectSummary {
        total_events: events.len(),
        paths: by_path.into_values().collect(),
    }
}

/// Compare event-name counts between two fork paths.
///
/// Returns one [`NameDelta`] per event name that appears in either path with a
/// different count, ordered by name. Names that occur equally in both are
/// omitted, so the result is exactly where the two branches diverged.
#[must_use]
pub fn diff_event_names(summary: &InspectSummary, path_a: &str, path_b: &str) -> Vec<NameDelta> {
    let empty = BTreeMap::new();
    let a = summary.path(path_a).map_or(&empty, |path| &path.by_name);
    let b = summary.path(path_b).map_or(&empty, |path| &path.by_name);

    a.keys()
        .chain(b.keys())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .filter_map(|name| {
            let a_count = a.get(name).copied().unwrap_or(0);
            let b_count = b.get(name).copied().unwrap_or(0);
            (a_count != b_count).then(|| NameDelta {
                name: name.clone(),
                a: a_count,
                b: b_count,
            })
        })
        .collect()
}

const fn signal_label(signal: SignalType) -> &'static str {
    match signal {
        SignalType::Span => "span",
        SignalType::Log => "log",
        SignalType::Metric => "metric",
        SignalType::Net => "net",
        SignalType::Exec => "exec",
        SignalType::Llm => "llm",
        SignalType::Annotation => "annotation",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hiloop_core::event::{EventName, SignalType};
    use hiloop_core::identity::{ForkContext, ForkOrdinal, Hlc};

    fn event(context: &ForkContext, signal: SignalType, name: &str) -> Event {
        Event::new(
            context,
            Hlc {
                wall_ns: 1,
                logical: 0,
            },
            signal,
            EventName::new(name).expect("event name"),
        )
    }

    #[test]
    fn summarize_groups_events_by_fork_path() {
        let root = ForkContext::new_local_root();
        let child = root.child(ForkOrdinal::new(0)).expect("child");
        let events = vec![
            event(&root, SignalType::Log, "process.stdout"),
            event(&root, SignalType::Log, "process.stdout"),
            event(&root, SignalType::Net, "http.request"),
            event(&child, SignalType::Log, "process.stdout"),
        ];

        let summary = summarize(&events);

        assert_eq!(summary.total_events, 4);
        assert_eq!(summary.paths.len(), 2);

        let root_summary = summary.path("").expect("root summary");
        assert_eq!(root_summary.events, 3);
        assert_eq!(root_summary.by_signal.get("log"), Some(&2));
        assert_eq!(root_summary.by_signal.get("net"), Some(&1));
        assert_eq!(root_summary.by_name.get("process.stdout"), Some(&2));

        let child_summary = summary.path("/0").expect("child summary");
        assert_eq!(child_summary.events, 1);
    }

    #[test]
    fn diff_reports_only_diverging_event_names() {
        let a = ForkContext::new_local_root();
        let b = a.child(ForkOrdinal::new(0)).expect("child");
        let events = vec![
            // Shared name with equal counts is omitted from the diff.
            event(&a, SignalType::Log, "process.stdout"),
            event(&b, SignalType::Log, "process.stdout"),
            // Diverging names.
            event(&a, SignalType::Net, "http.request"),
            event(&b, SignalType::Llm, "llm.completion"),
            event(&b, SignalType::Llm, "llm.completion"),
        ];
        let summary = summarize(&events);

        let deltas = diff_event_names(&summary, "", "/0");

        assert_eq!(
            deltas,
            vec![
                NameDelta {
                    name: "http.request".to_owned(),
                    a: 1,
                    b: 0,
                },
                NameDelta {
                    name: "llm.completion".to_owned(),
                    a: 0,
                    b: 2,
                },
            ]
        );
    }

    #[test]
    fn summarize_handles_no_events() {
        let summary = summarize(&[]);
        assert_eq!(summary, InspectSummary::default());
        assert!(diff_event_names(&summary, "", "/0").is_empty());
    }
}
