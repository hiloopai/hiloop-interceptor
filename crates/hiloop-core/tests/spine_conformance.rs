//! Cross-cutting conformance for the fork-tree spine and the event schema.
//!
//! These tests run against the public crate API only, and they encode the
//! invariants the rest of hiloop (and the private control plane) relies on.
//!
//! `event_v1_schema_is_locked` is the executable form of the "Event v1 is
//! frozen" policy: the serialized shape of an [`Event`] is a persisted/wire
//! contract, so a change that trips this test must be a deliberate, reviewed
//! schema decision (and a coordinated migration), never an accident.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::thread;

use hiloop_core::event::{AttributeKey, Event, EventName, SignalType};
use hiloop_core::identity::{ChildOrdinalAllocator, ForkContext, Hlc};

#[test]
fn concurrent_children_have_unique_gap_free_descendant_paths() {
    const THREADS: u64 = 8;
    const PER_THREAD: u64 = 64;

    let parent = ForkContext::new_local_root();
    let allocator = Arc::new(ChildOrdinalAllocator::new());

    let handles = (0..THREADS)
        .map(|_| {
            let allocator = Arc::clone(&allocator);
            let parent = parent.clone();
            thread::spawn(move || {
                (0..PER_THREAD)
                    .map(|_| parent.child(allocator.next()).expect("child context"))
                    .collect::<Vec<_>>()
            })
        })
        .collect::<Vec<_>>();

    let children = handles
        .into_iter()
        .flat_map(|handle| handle.join().expect("thread should finish"))
        .collect::<Vec<_>>();

    let total = (THREADS * PER_THREAD) as usize;
    assert_eq!(children.len(), total);

    // Every node id is unique.
    let node_ids = children
        .iter()
        .map(|child| child.fork_node_id.to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(node_ids.len(), total, "fork_node_id values must be unique");

    // Every fork path is unique.
    let paths = children
        .iter()
        .map(|child| child.fork_path.to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(paths.len(), total, "fork_path values must be unique");

    // Every child stays in the run and descends from the parent at depth 1.
    for child in &children {
        assert_eq!(child.run_id, parent.run_id);
        assert!(parent.fork_path.is_ancestor_of(&child.fork_path));
        assert_eq!(child.fork_path.depth(), 1);
    }

    // Sibling ordinals are gap-free over `0..total`.
    let mut ordinals = children
        .iter()
        .map(|child| child.fork_path.ordinals()[0].as_u64())
        .collect::<Vec<_>>();
    ordinals.sort_unstable();
    assert_eq!(ordinals, (0..THREADS * PER_THREAD).collect::<Vec<_>>());
}

#[test]
fn event_v1_schema_is_locked() {
    let context = ForkContext::new_local_root();
    let event = Event::new(
        &context,
        Hlc {
            wall_ns: 1,
            logical: 0,
        },
        SignalType::Log,
        EventName::new("process.stdout").expect("event name"),
    )
    .with_attribute(AttributeKey::new("message").expect("attribute key"), "hi");

    let value = serde_json::to_value(&event).expect("serialize event");
    let object = value
        .as_object()
        .expect("event serializes as a JSON object");

    // The top-level field set is the v1 contract. payload_ref is always present
    // (serialized as null when absent) so storage projections can rely on it.
    let mut keys = object.keys().map(String::as_str).collect::<Vec<_>>();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "attributes",
            "event_id",
            "fork_node_id",
            "fork_path",
            "name",
            "payload_ref",
            "run_id",
            "signal",
            "ts",
        ],
        "Event v1 top-level fields changed; this is a contract/migration decision"
    );
    assert!(object["payload_ref"].is_null());
    // event_id is a minted ULID string and is always present on freshly captured events.
    assert!(object["event_id"].as_str().is_some_and(|id| !id.is_empty()));

    // The timestamp is a hybrid logical clock with a stable two-field shape.
    let mut ts_keys = object["ts"]
        .as_object()
        .expect("ts serializes as a JSON object")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    ts_keys.sort_unstable();
    assert_eq!(ts_keys, ["logical", "wall_ns"]);

    // Signal families serialize as snake_case discriminants.
    assert_eq!(value["signal"], serde_json::json!("log"));
    // Attributes are a flat map keyed by the attribute name.
    assert_eq!(value["attributes"]["message"], serde_json::json!("hi"));
    // Root fork path serializes as the empty string.
    assert_eq!(value["fork_path"], serde_json::json!(""));
}
