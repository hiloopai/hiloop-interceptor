//! Fork-tree identity: the join key for telemetry, snapshots, and state.
//!
//! IDs are minted locally so fork fan-out never hits the control plane. Paths
//! are parent-owned and gap-free. Hybrid logical timestamps keep events causally
//! ordered across skewed machines.

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::{
    fmt,
    str::FromStr,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use ulid::Ulid;

/// Maximum supported materialized-path depth.
///
/// This bounds storage and index key growth while leaving enough room for deep
/// experimental fork trees.
pub const MAX_FORK_PATH_DEPTH: usize = 128;

/// Errors returned by identity parsing and allocation helpers.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IdentityError {
    #[error("invalid {field} ULID: {value}")]
    InvalidUlid { field: &'static str, value: String },
    #[error("invalid fork path `{value}`: {reason}")]
    InvalidForkPath { value: String, reason: &'static str },
    #[error("fork path depth limit exceeded: {depth} > {max}")]
    ForkPathTooDeep { depth: usize, max: usize },
}

/// Identifier shared by every node and event in one run tree.
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

/// Opaque identifier for one fork-tree node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ForkNodeId(Ulid);

impl ForkNodeId {
    /// Mint a node-local fork node id.
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

impl Default for ForkNodeId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ForkNodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl FromStr for ForkNodeId {
    type Err = IdentityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ulid::from_string(value)
            .map(Self)
            .map_err(|_| IdentityError::InvalidUlid {
                field: "fork_node_id",
                value: value.to_owned(),
            })
    }
}

/// Parent-assigned ordinal of a child fork.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ForkOrdinal(u64);

impl ForkOrdinal {
    /// The first child ordinal for a parent node.
    pub const ZERO: Self = Self(0);

    /// Convert from the storage and wire representation.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Convert into the storage and wire representation.
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for ForkOrdinal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl From<u64> for ForkOrdinal {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

/// The materialized path of gap-free child ordinals, e.g. `/0/3/1`.
///
/// Root is represented internally as an empty ordinal sequence and serialized
/// as the empty string. Every non-root path serializes as slash-delimited
/// ordinals.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ForkPath(Vec<ForkOrdinal>);

impl ForkPath {
    /// Depth-zero path.
    pub fn root() -> Self {
        Self(Vec::new())
    }

    /// Accepts `""` for root or slash-delimited decimal ordinals like `/0/3`.
    pub fn parse(value: impl Into<String>) -> Result<Self, IdentityError> {
        let value = value.into();
        parse_fork_path(&value).map(Self)
    }

    /// Appends a parent-assigned ordinal, unless that would exceed the depth limit.
    pub fn child(&self, ordinal: ForkOrdinal) -> Result<Self, IdentityError> {
        let depth = self.depth() + 1;
        if depth > MAX_FORK_PATH_DEPTH {
            return Err(IdentityError::ForkPathTooDeep {
                depth,
                max: MAX_FORK_PATH_DEPTH,
            });
        }

        let mut ordinals = self.0.clone();
        ordinals.push(ordinal);
        Ok(Self(ordinals))
    }

    /// Root-to-leaf ordinal sequence.
    pub fn ordinals(&self) -> &[ForkOrdinal] {
        &self.0
    }

    /// Tree depth, with root = 0.
    pub fn depth(&self) -> usize {
        self.0.len()
    }

    /// True if `self` is an ancestor of, or equal to, `other`.
    pub fn is_ancestor_of(&self, other: &ForkPath) -> bool {
        other.0.starts_with(&self.0)
    }
}

impl Default for ForkPath {
    fn default() -> Self {
        Self::root()
    }
}

impl fmt::Display for ForkPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for ordinal in &self.0 {
            write!(f, "/{ordinal}")?;
        }
        Ok(())
    }
}

impl FromStr for ForkPath {
    type Err = IdentityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for ForkPath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ForkPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(de::Error::custom)
    }
}

/// Fully resolved fork context stamped onto child environment and telemetry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkContext {
    pub run_id: RunId,
    pub fork_node_id: ForkNodeId,
    pub fork_path: ForkPath,
}

impl ForkContext {
    /// Use when no upstream fork context was provided.
    pub fn new_local_root() -> Self {
        Self {
            run_id: RunId::new(),
            fork_node_id: ForkNodeId::new(),
            fork_path: ForkPath::root(),
        }
    }

    pub fn new(run_id: RunId, fork_node_id: ForkNodeId, fork_path: ForkPath) -> Self {
        Self {
            run_id,
            fork_node_id,
            fork_path,
        }
    }
}

/// Parent-owned atomic allocator for sibling fork ordinals.
///
/// This allocator is intentionally local to the process that owns the parent
/// node. `Relaxed` ordering is sufficient because the contract is uniqueness and
/// gap freedom of the counter itself, not synchronization of child metadata.
#[derive(Debug)]
pub struct ChildOrdinalAllocator {
    next: AtomicU64,
}

impl ChildOrdinalAllocator {
    /// Start at [`ForkOrdinal::ZERO`].
    pub fn new() -> Self {
        Self::with_next(ForkOrdinal::ZERO)
    }

    /// Resume from the next ordinal that has not been committed.
    pub fn with_next(next: ForkOrdinal) -> Self {
        Self {
            next: AtomicU64::new(next.as_u64()),
        }
    }

    /// Allocate one sibling ordinal.
    pub fn next(&self) -> ForkOrdinal {
        ForkOrdinal::new(self.next.fetch_add(1, Ordering::Relaxed))
    }

    /// Inspect the next ordinal without advancing the allocator.
    pub fn peek(&self) -> ForkOrdinal {
        ForkOrdinal::new(self.next.load(Ordering::Relaxed))
    }
}

impl Default for ChildOrdinalAllocator {
    fn default() -> Self {
        Self::new()
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

fn parse_fork_path(value: &str) -> Result<Vec<ForkOrdinal>, IdentityError> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    if !value.starts_with('/') {
        return invalid_path(value, "non-root paths must start with `/`");
    }
    if value.ends_with('/') {
        return invalid_path(value, "non-root paths must not end with `/`");
    }

    let mut ordinals = Vec::new();
    for component in value[1..].split('/') {
        let depth = ordinals.len() + 1;
        if depth > MAX_FORK_PATH_DEPTH {
            return Err(IdentityError::ForkPathTooDeep {
                depth,
                max: MAX_FORK_PATH_DEPTH,
            });
        }
        if component.is_empty() {
            return invalid_path(value, "path components must not be empty");
        }
        if component.len() > 1 && component.starts_with('0') {
            return invalid_path(value, "path ordinals must be canonical decimals");
        }
        let ordinal = component
            .parse::<u64>()
            .map(ForkOrdinal::new)
            .map_err(|_| IdentityError::InvalidForkPath {
                value: value.to_owned(),
                reason: "path components must be u64 ordinals",
            })?;
        ordinals.push(ordinal);
    }

    Ok(ordinals)
}

fn invalid_path<T>(value: &str, reason: &'static str) -> Result<T, IdentityError> {
    Err(IdentityError::InvalidForkPath {
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
    use std::{collections::BTreeSet, sync::Arc, thread};

    const fn ordinal(value: u64) -> ForkOrdinal {
        ForkOrdinal::new(value)
    }

    #[test]
    fn fork_path_prefix_is_ancestor() {
        let root = ForkPath::root();
        let a = root.child(ordinal(0)).expect("child path");
        let b = a.child(ordinal(3)).expect("child path");

        assert!(root.is_ancestor_of(&b));
        assert!(a.is_ancestor_of(&b));
        assert!(!b.is_ancestor_of(&a));
        assert_eq!(b.depth(), 2);
        assert_eq!(b.ordinals(), &[ordinal(0), ordinal(3)]);
        assert_eq!(b.to_string(), "/0/3");
    }

    #[test]
    fn fork_path_serializes_as_canonical_string() {
        let path = ForkPath::root()
            .child(ordinal(0))
            .and_then(|path| path.child(ordinal(3)))
            .expect("child path");
        let serialized = serde_json::to_string(&path).expect("serialize path");
        let deserialized: ForkPath = serde_json::from_str(&serialized).expect("deserialize path");

        assert_eq!(serialized, "\"/0/3\"");
        assert_eq!(deserialized, path);
    }

    #[test]
    fn root_fork_path_serializes_as_empty_string() {
        let path = ForkPath::root();
        let serialized = serde_json::to_string(&path).expect("serialize path");
        let deserialized: ForkPath = serde_json::from_str(&serialized).expect("deserialize path");

        assert!(path.ordinals().is_empty());
        assert_eq!(serialized, "\"\"");
        assert_eq!(deserialized, path);
    }

    #[test]
    fn sibling_prefix_is_not_ancestor() {
        let root = ForkPath::root();
        let one = root
            .child(ordinal(0))
            .and_then(|path| path.child(ordinal(1)))
            .expect("child path");
        let ten = root
            .child(ordinal(0))
            .and_then(|path| path.child(ordinal(10)))
            .expect("child path");

        assert!(!one.is_ancestor_of(&ten));
    }

    #[test]
    fn fork_path_parser_rejects_non_canonical_paths() {
        for value in ["0", "/", "/01", "/0//1", "/x", "/0/"] {
            assert!(ForkPath::parse(value).is_err(), "{value}");
        }
    }

    #[test]
    fn child_ordinals_are_gap_free_under_concurrency() {
        const THREADS: u64 = 8;
        const PER_THREAD: u64 = 256;

        let allocator = Arc::new(ChildOrdinalAllocator::new());
        let handles = (0..THREADS)
            .map(|_| {
                let allocator = Arc::clone(&allocator);
                thread::spawn(move || {
                    (0..PER_THREAD)
                        .map(|_| allocator.next())
                        .collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>();

        let mut ordinals = handles
            .into_iter()
            .flat_map(|handle| handle.join().expect("thread should finish"))
            .collect::<Vec<_>>();
        ordinals.sort_unstable();

        assert_eq!(
            ordinals,
            (0..THREADS * PER_THREAD)
                .map(ForkOrdinal::new)
                .collect::<Vec<_>>()
        );
        assert_eq!(allocator.peek(), ForkOrdinal::new(THREADS * PER_THREAD));
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
        fn parsed_child_paths_round_trip(ordinals in prop::collection::vec(0u64..1_000_000, 0..16)) {
            let mut path = ForkPath::root();
            let mut seen = BTreeSet::new();
            seen.insert(path.to_string());

            for ordinal in ordinals {
                path = path.child(ForkOrdinal::new(ordinal))?;
                let parsed = ForkPath::parse(path.to_string())?;
                prop_assert_eq!(&parsed, &path);
                let ancestors_valid = seen.iter().all(|ancestor| {
                    ForkPath::parse(ancestor).is_ok_and(|ancestor| ancestor.is_ancestor_of(&path))
                });
                prop_assert!(ancestors_valid);
                seen.insert(path.to_string());
            }
        }
    }
}
