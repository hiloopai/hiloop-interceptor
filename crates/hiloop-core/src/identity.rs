//! Run-lineage identity: the join key for telemetry, snapshots, and state.
//!
//! IDs are minted locally so a run never has to round-trip the control plane to
//! stamp telemetry. A run's lineage path is the materialized, prefix-addressable
//! position of the run in its tree — the dotted sequence of run ULIDs from the
//! root run to this run. Hybrid logical timestamps keep events causally ordered
//! across skewed machines.

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::{
    fmt::{self, Write as _},
    str::FromStr,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use ulid::Ulid;

/// Maximum supported materialized-path depth, in run segments.
///
/// This bounds storage and index key growth while leaving enough room for deep
/// experimental run trees.
pub const MAX_LINEAGE_PATH_DEPTH: usize = 128;

/// The run-segment separator in a serialized lineage path.
///
/// Dotted run ULIDs, matching the control plane's materialized lineage path.
const LINEAGE_SEPARATOR: char = '.';

/// Errors returned by identity parsing and allocation helpers.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IdentityError {
    #[error("invalid {field} ULID: {value}")]
    InvalidUlid { field: &'static str, value: String },
    #[error("invalid lineage path `{value}`: {reason}")]
    InvalidLineagePath { value: String, reason: &'static str },
    #[error("lineage path depth limit exceeded: {depth} > {max}")]
    LineagePathTooDeep { depth: usize, max: usize },
}

/// Identifier shared by every event in one run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RunId(Ulid);

impl RunId {
    /// Mint a locally unique run id.
    pub fn new() -> Self {
        Self(Ulid::new())
    }

    pub fn from_ulid(value: Ulid) -> Self {
        Self(value)
    }

    pub fn as_ulid(self) -> Ulid {
        self.0
    }
}

impl Default for RunId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for RunId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl FromStr for RunId {
    type Err = IdentityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ulid::from_string(value)
            .map(Self)
            .map_err(|_| IdentityError::InvalidUlid {
                field: "run_id",
                value: value.to_owned(),
            })
    }
}

/// Stable identity for a single telemetry event, minted at capture time.
///
/// Lets the ingest path dedup idempotently: the backend uses this when present and otherwise
/// derives a deterministic fallback, so re-delivering an event maps to the same row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EventId(Ulid);

impl EventId {
    /// Mint a locally unique event id.
    pub fn new() -> Self {
        Self(Ulid::new())
    }

    pub fn from_ulid(value: Ulid) -> Self {
        Self(value)
    }

    pub fn as_ulid(self) -> Ulid {
        self.0
    }
}

impl Default for EventId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl FromStr for EventId {
    type Err = IdentityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ulid::from_string(value)
            .map(Self)
            .map_err(|_| IdentityError::InvalidUlid {
                field: "event_id",
                value: value.to_owned(),
            })
    }
}

/// The materialized lineage path of a run: the dotted run ULIDs from the root run
/// to this run, e.g. `01ARZ….01BX5…`.
///
/// A root run's path is its own run ULID — never empty. Every segment is a valid
/// run ULID, and the last segment is this run's own id.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LineagePath(Vec<RunId>);

impl LineagePath {
    /// The lineage path of a root run: a single segment, the run's own id.
    pub fn root(run_id: RunId) -> Self {
        Self(vec![run_id])
    }

    /// Parse a dotted sequence of run ULIDs. Rejects an empty path: a run always
    /// has at least its own id in the path.
    pub fn parse(value: impl Into<String>) -> Result<Self, IdentityError> {
        let value = value.into();
        parse_lineage_path(&value).map(Self)
    }

    /// Append a child run, unless that would exceed the depth limit. The child's
    /// path is this path plus the child's run id.
    pub fn child(&self, child: RunId) -> Result<Self, IdentityError> {
        let depth = self.depth() + 1;
        if depth > MAX_LINEAGE_PATH_DEPTH {
            return Err(IdentityError::LineagePathTooDeep {
                depth,
                max: MAX_LINEAGE_PATH_DEPTH,
            });
        }

        let mut segments = self.0.clone();
        segments.push(child);
        Ok(Self(segments))
    }

    /// Root-to-leaf run-id sequence.
    pub fn segments(&self) -> &[RunId] {
        &self.0
    }

    /// The run this path addresses — the last segment.
    pub fn run_id(&self) -> RunId {
        // Invariant: the constructors keep the vector non-empty.
        *self.0.last().expect("lineage path is never empty")
    }

    /// Tree depth, with a root run = 1.
    pub fn depth(&self) -> usize {
        self.0.len()
    }

    /// True if `self` is an ancestor of, or equal to, `other`.
    pub fn is_ancestor_of(&self, other: &LineagePath) -> bool {
        other.0.starts_with(&self.0)
    }
}

impl fmt::Display for LineagePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, run_id) in self.0.iter().enumerate() {
            if index > 0 {
                f.write_char(LINEAGE_SEPARATOR)?;
            }
            fmt::Display::fmt(run_id, f)?;
        }
        Ok(())
    }
}

impl FromStr for LineagePath {
    type Err = IdentityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for LineagePath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for LineagePath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(de::Error::custom)
    }
}

/// Fully resolved run context stamped onto child environment and telemetry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunContext {
    pub run_id: RunId,
    pub lineage_path: LineagePath,
}

impl RunContext {
    /// Use when no upstream run context was provided: a fresh root run whose
    /// lineage path is its own id.
    pub fn new_local_root() -> Self {
        let run_id = RunId::new();
        Self {
            run_id,
            lineage_path: LineagePath::root(run_id),
        }
    }

    /// Build a context from a resolved run id and its lineage path. The path's
    /// leaf must be `run_id`, so they describe the same run.
    pub fn new(run_id: RunId, lineage_path: LineagePath) -> Result<Self, IdentityError> {
        if lineage_path.run_id() != run_id {
            return Err(IdentityError::InvalidLineagePath {
                value: lineage_path.to_string(),
                reason: "lineage path leaf must equal run_id",
            });
        }
        Ok(Self {
            run_id,
            lineage_path,
        })
    }

    /// Derive a child run from this run: a freshly minted [`RunId`] whose lineage
    /// path extends this run's path. Fails only if the child would exceed
    /// [`MAX_LINEAGE_PATH_DEPTH`].
    pub fn child(&self) -> Result<Self, IdentityError> {
        let run_id = RunId::new();
        Ok(Self {
            run_id,
            lineage_path: self.lineage_path.child(run_id)?,
        })
    }
}

/// Hybrid logical timestamp for causal event ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Hlc {
    pub wall_ns: u64,
    pub logical: u32,
}

/// Process-local hybrid logical clock.
#[derive(Debug, Default)]
pub struct HlcClock {
    last: Mutex<Option<Hlc>>,
}

impl HlcClock {
    /// Create a clock with no previous timestamp.
    pub fn new() -> Self {
        Self::default()
    }

    /// Advance the clock for a local event.
    pub fn tick(&self) -> Hlc {
        self.tick_with_wall_ns(unix_time_ns())
    }

    fn tick_with_wall_ns(&self, wall_ns: u64) -> Hlc {
        let mut last = self
            .last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let next = match *last {
            Some(last) if wall_ns > last.wall_ns => Hlc {
                wall_ns,
                logical: 0,
            },
            Some(last) => increment_logical(last),
            None => Hlc {
                wall_ns,
                logical: 0,
            },
        };
        *last = Some(next);
        next
    }

    /// Merge a remote timestamp and advance for the receive event.
    pub fn observe(&self, remote: Hlc) -> Hlc {
        self.observe_with_wall_ns(remote, unix_time_ns())
    }

    fn observe_with_wall_ns(&self, remote: Hlc, wall_ns: u64) -> Hlc {
        let mut last = self
            .last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let next = match *last {
            Some(last) => {
                let max_wall = wall_ns.max(last.wall_ns).max(remote.wall_ns);
                if max_wall == last.wall_ns && max_wall == remote.wall_ns {
                    increment_at_wall(max_wall, last.logical.max(remote.logical))
                } else if max_wall == last.wall_ns {
                    increment_at_wall(max_wall, last.logical)
                } else if max_wall == remote.wall_ns {
                    increment_at_wall(max_wall, remote.logical)
                } else {
                    Hlc {
                        wall_ns: max_wall,
                        logical: 0,
                    }
                }
            }
            None if wall_ns > remote.wall_ns => Hlc {
                wall_ns,
                logical: 0,
            },
            None => increment_at_wall(remote.wall_ns, remote.logical),
        };
        *last = Some(next);
        next
    }
}

fn parse_lineage_path(value: &str) -> Result<Vec<RunId>, IdentityError> {
    if value.is_empty() {
        return invalid_path(value, "lineage path must not be empty");
    }
    if value.starts_with(LINEAGE_SEPARATOR) || value.ends_with(LINEAGE_SEPARATOR) {
        return invalid_path(
            value,
            "lineage path must not have leading or trailing separators",
        );
    }

    let mut segments = Vec::new();
    for component in value.split(LINEAGE_SEPARATOR) {
        let depth = segments.len() + 1;
        if depth > MAX_LINEAGE_PATH_DEPTH {
            return Err(IdentityError::LineagePathTooDeep {
                depth,
                max: MAX_LINEAGE_PATH_DEPTH,
            });
        }
        if component.is_empty() {
            return invalid_path(value, "lineage path segments must not be empty");
        }
        let run_id = Ulid::from_string(component)
            .map(RunId::from_ulid)
            .map_err(|_| IdentityError::InvalidLineagePath {
                value: value.to_owned(),
                reason: "lineage path segments must be run ULIDs",
            })?;
        segments.push(run_id);
    }

    Ok(segments)
}

fn invalid_path<T>(value: &str, reason: &'static str) -> Result<T, IdentityError> {
    Err(IdentityError::InvalidLineagePath {
        value: value.to_owned(),
        reason,
    })
}

fn increment_logical(hlc: Hlc) -> Hlc {
    increment_at_wall(hlc.wall_ns, hlc.logical)
}

fn increment_at_wall(wall_ns: u64, logical: u32) -> Hlc {
    if logical == u32::MAX {
        Hlc {
            wall_ns: wall_ns.saturating_add(1),
            logical: 0,
        }
    } else {
        Hlc {
            wall_ns,
            logical: logical + 1,
        }
    }
}

fn unix_time_ns() -> u64 {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::BTreeSet;

    fn run(byte: u8) -> RunId {
        RunId::from_ulid(Ulid::from_bytes([byte; 16]))
    }

    #[test]
    fn lineage_path_prefix_is_ancestor() {
        let root = LineagePath::root(run(1));
        let a = root.child(run(2)).expect("child path");
        let b = a.child(run(3)).expect("child path");

        assert!(root.is_ancestor_of(&b));
        assert!(a.is_ancestor_of(&b));
        assert!(!b.is_ancestor_of(&a));
        assert_eq!(b.depth(), 3);
        assert_eq!(b.segments(), &[run(1), run(2), run(3)]);
        assert_eq!(b.run_id(), run(3));
        assert_eq!(b.to_string(), format!("{}.{}.{}", run(1), run(2), run(3)));
    }

    #[test]
    fn lineage_path_serializes_as_dotted_run_ulids() {
        let path = LineagePath::root(run(1)).child(run(2)).expect("child path");
        let serialized = serde_json::to_string(&path).expect("serialize path");
        let deserialized: LineagePath =
            serde_json::from_str(&serialized).expect("deserialize path");

        assert_eq!(serialized, format!("\"{}.{}\"", run(1), run(2)));
        assert_eq!(deserialized, path);
    }

    #[test]
    fn root_lineage_path_is_its_own_run_id() {
        let path = LineagePath::root(run(7));
        let serialized = serde_json::to_string(&path).expect("serialize path");
        let deserialized: LineagePath =
            serde_json::from_str(&serialized).expect("deserialize path");

        assert_eq!(path.segments(), &[run(7)]);
        assert_eq!(serialized, format!("\"{}\"", run(7)));
        assert_eq!(deserialized, path);
    }

    #[test]
    fn sibling_prefix_is_not_ancestor() {
        let root = LineagePath::root(run(1));
        let one = root.child(run(2)).expect("child path");
        let ten = root.child(run(3)).expect("child path");

        assert!(!one.is_ancestor_of(&ten));
    }

    #[test]
    fn lineage_path_parser_rejects_malformed_paths() {
        for value in [
            "",
            ".",
            "..",
            "not-a-ulid",
            &format!(".{}", run(1)),
            &format!("{}.", run(1)),
        ] {
            assert!(LineagePath::parse(value).is_err(), "{value}");
        }
    }

    #[test]
    fn run_context_child_extends_path_and_keeps_root() {
        let parent = RunContext::new_local_root();
        let child = parent.child().expect("child context");

        assert_ne!(child.run_id, parent.run_id);
        assert!(parent.lineage_path.is_ancestor_of(&child.lineage_path));
        assert_eq!(child.lineage_path.depth(), parent.lineage_path.depth() + 1);
        assert_eq!(child.lineage_path.run_id(), child.run_id);
        assert_eq!(child.lineage_path.segments().first(), Some(&parent.run_id));
    }

    #[test]
    fn run_context_new_rejects_path_leaf_mismatch() {
        let path = LineagePath::root(run(1));
        assert!(RunContext::new(run(2), path).is_err());
    }

    #[test]
    fn run_context_new_accepts_matching_leaf() {
        let path = LineagePath::root(run(1)).child(run(2)).expect("child path");
        let ctx = RunContext::new(run(2), path.clone()).expect("context");
        assert_eq!(ctx.run_id, run(2));
        assert_eq!(ctx.lineage_path, path);
    }

    #[test]
    fn hlc_tick_preserves_monotonicity_when_wall_clock_stalls_or_moves_back() {
        let clock = HlcClock::new();

        let first = clock.tick_with_wall_ns(100);
        let stalled = clock.tick_with_wall_ns(100);
        let moved_back = clock.tick_with_wall_ns(90);

        assert_eq!(
            first,
            Hlc {
                wall_ns: 100,
                logical: 0,
            }
        );
        assert_eq!(
            stalled,
            Hlc {
                wall_ns: 100,
                logical: 1,
            }
        );
        assert_eq!(
            moved_back,
            Hlc {
                wall_ns: 100,
                logical: 2,
            }
        );
    }

    #[test]
    fn hlc_observe_merges_remote_causality() {
        let clock = HlcClock::new();
        clock.tick_with_wall_ns(100);

        let observed = clock.observe_with_wall_ns(
            Hlc {
                wall_ns: 110,
                logical: 7,
            },
            105,
        );

        assert_eq!(
            observed,
            Hlc {
                wall_ns: 110,
                logical: 8,
            }
        );
        assert!(clock.tick_with_wall_ns(106) > observed);
    }

    proptest! {
        #[test]
        fn parsed_child_paths_round_trip(depth in 0usize..16) {
            let mut path = LineagePath::root(RunId::new());
            let mut seen = BTreeSet::new();
            seen.insert(path.to_string());

            for _ in 0..depth {
                path = path.child(RunId::new())?;
                let parsed = LineagePath::parse(path.to_string())?;
                prop_assert_eq!(&parsed, &path);
                let ancestors_valid = seen.iter().all(|ancestor| {
                    LineagePath::parse(ancestor).is_ok_and(|ancestor| ancestor.is_ancestor_of(&path))
                });
                prop_assert!(ancestors_valid);
                seen.insert(path.to_string());
            }
        }
    }
}
