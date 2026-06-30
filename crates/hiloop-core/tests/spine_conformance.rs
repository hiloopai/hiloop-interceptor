//! Cross-cutting conformance for the run-lineage spine and the event schema.
//!
//! These tests run against the public crate API only, and they encode the
//! invariants the rest of hiloop (and the private control plane) relies on.
//!
//! `event_v1_schema_is_locked` is the executable form of the "Event v1 is
//! frozen" policy: the serialized shape of an [`Event`] is a persisted/wire
//! contract, so a change that trips this test must be a deliberate, reviewed
//! schema decision (and a coordinated migration), never an accident.

use std::collections::BTreeSet;
use std::thread;

use hiloop_core::event::{AttributeKey, Event, EventName, SignalType};
use hiloop_core::identity::{Hlc, RunContext};

#[test]
fn concurrent_children_have_unique_descendant_paths_under_one_root() {
    const THREADS: u64 = 8;
    const PER_THREAD: u64 = 64;

    let parent = RunContext::new_local_root();

    let handles = (0..THREADS)
        .map(|_| {
            let parent = parent.clone();
            thread::spawn(move || {
                (0..PER_THREAD)
                    .map(|_| parent.child().expect("child context"))
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

    // Every child run id is unique.
    let run_ids = children
        .iter()
        .map(|child| child.run_id.to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(run_ids.len(), total, "child run_id values must be unique");

    // Every lineage path is unique.
    let paths = children
        .iter()
        .map(|child| child.lineage_path.to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(paths.len(), total, "lineage_path values must be unique");

    // Every child descends from the parent root at depth 2 (root + child) and its
    // path leaf is its own run id.
    for child in &children {
        assert!(parent.lineage_path.is_ancestor_of(&child.lineage_path));
        assert_eq!(child.lineage_path.depth(), parent.lineage_path.depth() + 1);
        assert_eq!(child.lineage_path.run_id(), child.run_id);
        assert_eq!(child.lineage_path.segments().first(), Some(&parent.run_id));
    }
}

#[test]
fn event_v1_schema_is_locked() {
    let context = RunContext::new_local_root();
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
            "lineage_path",
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
    // A root run's lineage path is its own run id.
    assert_eq!(
        value["lineage_path"],
        serde_json::json!(context.run_id.to_string())
    );
}
