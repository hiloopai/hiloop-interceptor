use std::str::FromStr;

use hiloop_core::capture::NetCaptureMode;
use hiloop_interceptor::net_capture::{
    CompatibilityRegistry, CompatibilityRegistryEntry, RegistryError,
};

#[test]
fn net_capture_mode_accepts_only_contract_values() {
    assert_eq!(NetCaptureMode::from_str("auto"), Ok(NetCaptureMode::Auto));
    assert_eq!(NetCaptureMode::from_str("netns"), Ok(NetCaptureMode::Netns));
    assert_eq!(NetCaptureMode::from_str("proxy"), Ok(NetCaptureMode::Proxy));
    assert_eq!(NetCaptureMode::from_str("off"), Ok(NetCaptureMode::Off));

    for invalid in ["", "automatic", "none", "AUTO", "proxy,off"] {
        assert!(NetCaptureMode::from_str(invalid).is_err(), "{invalid:?}");
    }
}

#[test]
fn compatibility_registry_schema_is_versioned_and_exact() {
    let entry = CompatibilityRegistryEntry::new(
        "api.modal.com",
        443,
        "clean-environment Modal pinning fixture",
        "capture-runtime",
        "2026-10-14",
    )
    .expect("valid registry entry");
    let registry = CompatibilityRegistry::new(1, vec![entry]).expect("valid registry");

    assert_eq!(registry.version(), 1);
    assert_eq!(registry.entries().len(), 1);
    let entry = &registry.entries()[0];
    assert_eq!(entry.host().to_string(), "api.modal.com");
    assert_eq!(entry.port(), 443);
    assert_eq!(entry.evidence(), "clean-environment Modal pinning fixture");
    assert_eq!(entry.owner(), "capture-runtime");
    assert_eq!(entry.revalidate_on(), "2026-10-14");
}

#[test]
fn compatibility_registry_rejects_wildcards_ports_blanks_and_duplicates() {
    assert!(matches!(
        CompatibilityRegistryEntry::new("*.modal.com", 443, "fixture", "owner", "2026-10-14"),
        Err(RegistryError::Host { .. })
    ));
    assert!(matches!(
        CompatibilityRegistryEntry::new("api.modal.com:443", 443, "fixture", "owner", "2026-10-14"),
        Err(RegistryError::Host { .. })
    ));
    assert!(matches!(
        CompatibilityRegistryEntry::new("api.modal.com", 0, "fixture", "owner", "2026-10-14"),
        Err(RegistryError::Port)
    ));
    assert!(matches!(
        CompatibilityRegistryEntry::new("api.modal.com", 443, " ", "owner", "2026-10-14"),
        Err(RegistryError::Blank { field: "evidence" })
    ));
    assert!(matches!(
        CompatibilityRegistryEntry::new("api.modal.com", 443, "fixture", "owner", "2026-02-29"),
        Err(RegistryError::RevalidationDate { .. })
    ));
    assert!(matches!(
        CompatibilityRegistryEntry::new("api.modal.com", 443, "fixture", "owner", "2026-0é-29"),
        Err(RegistryError::RevalidationDate { .. })
    ));

    let entry =
        CompatibilityRegistryEntry::new("api.modal.com", 443, "fixture", "owner", "2026-10-14")
            .expect("valid entry");
    assert!(matches!(
        CompatibilityRegistry::new(0, vec![entry.clone()]),
        Err(RegistryError::Version)
    ));
    assert!(matches!(
        CompatibilityRegistry::new(1, vec![entry.clone(), entry]),
        Err(RegistryError::Duplicate { .. })
    ));
}
