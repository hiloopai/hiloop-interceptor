//! Configuration contracts for transparent network capture.

use std::collections::BTreeSet;

use thiserror::Error;

use crate::egress::{CanonicalHost, canonicalize_host};

/// Invalid compatibility-registry configuration.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RegistryError {
    /// Registry versions start at one so an absent/uninitialized version is invalid.
    #[error("compatibility registry version must be greater than zero")]
    Version,
    /// Entry hosts are exact canonical hosts without a port or wildcard.
    #[error("invalid exact compatibility-registry host `{value}`")]
    Host { value: String },
    /// Port zero is not a routable destination port.
    #[error("compatibility-registry port must be greater than zero")]
    Port,
    /// Evidence, ownership, and revalidation metadata must be present.
    #[error("compatibility-registry {field} must not be blank")]
    Blank { field: &'static str },
    /// Revalidation dates use the unambiguous ISO-8601 calendar form.
    #[error("invalid compatibility-registry revalidation date `{value}`; expected YYYY-MM-DD")]
    RevalidationDate { value: String },
    /// Every version contains at most one row per exact host and port.
    #[error("duplicate compatibility-registry endpoint `{host}:{port}`")]
    Duplicate { host: String, port: u16 },
}

/// One reviewed first-connection TLS compatibility entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatibilityRegistryEntry {
    host: CanonicalHost,
    port: u16,
    evidence: String,
    owner: String,
    revalidate_on: String,
}

impl CompatibilityRegistryEntry {
    /// Validate an exact host/port row and its review metadata.
    pub fn new(
        host: impl Into<String>,
        port: u16,
        evidence: impl Into<String>,
        owner: impl Into<String>,
        revalidate_on: impl Into<String>,
    ) -> Result<Self, RegistryError> {
        let host = host.into();
        if host.contains('*') {
            return Err(RegistryError::Host { value: host });
        }
        let destination = canonicalize_host(&host).map_err(|_| RegistryError::Host {
            value: host.clone(),
        })?;
        if destination.port().is_some() {
            return Err(RegistryError::Host { value: host });
        }
        if port == 0 {
            return Err(RegistryError::Port);
        }
        Ok(Self {
            host: destination.host().clone(),
            port,
            evidence: nonblank("evidence", evidence)?,
            owner: nonblank("owner", owner)?,
            revalidate_on: revalidation_date(revalidate_on)?,
        })
    }

    /// Exact canonical host.
    pub fn host(&self) -> &CanonicalHost {
        &self.host
    }

    /// Exact destination port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Reproducible evidence that justifies first-connection passthrough.
    pub fn evidence(&self) -> &str {
        &self.evidence
    }

    /// Team or component responsible for revalidating the entry.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// ISO-8601 calendar date by which the entry must be revalidated.
    pub fn revalidate_on(&self) -> &str {
        &self.revalidate_on
    }
}

/// Versioned exact-endpoint compatibility registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatibilityRegistry {
    version: u32,
    entries: Vec<CompatibilityRegistryEntry>,
}

impl CompatibilityRegistry {
    /// Validate registry identity and exact-endpoint uniqueness.
    pub fn new(
        version: u32,
        entries: Vec<CompatibilityRegistryEntry>,
    ) -> Result<Self, RegistryError> {
        if version == 0 {
            return Err(RegistryError::Version);
        }
        let mut endpoints = BTreeSet::new();
        for entry in &entries {
            let host = entry.host.to_string();
            if !endpoints.insert((host.clone(), entry.port)) {
                return Err(RegistryError::Duplicate {
                    host,
                    port: entry.port,
                });
            }
        }
        Ok(Self { version, entries })
    }

    /// Registry schema version.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Reviewed exact endpoint rows.
    pub fn entries(&self) -> &[CompatibilityRegistryEntry] {
        &self.entries
    }
}

fn nonblank(field: &'static str, value: impl Into<String>) -> Result<String, RegistryError> {
    let value = value.into();
    if value.trim().is_empty() {
        Err(RegistryError::Blank { field })
    } else {
        Ok(value)
    }
}

fn revalidation_date(value: impl Into<String>) -> Result<String, RegistryError> {
    let value = nonblank("revalidate_on", value)?;
    let bytes = value.as_bytes();
    let valid = bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[..4].iter().all(u8::is_ascii_digit)
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[8..].iter().all(u8::is_ascii_digit);
    if !valid {
        return Err(RegistryError::RevalidationDate { value });
    }

    let year = value[..4]
        .parse::<u16>()
        .map_err(|_| RegistryError::RevalidationDate {
            value: value.clone(),
        })?;
    let month = value[5..7]
        .parse::<u8>()
        .map_err(|_| RegistryError::RevalidationDate {
            value: value.clone(),
        })?;
    let day = value[8..]
        .parse::<u8>()
        .map_err(|_| RegistryError::RevalidationDate {
            value: value.clone(),
        })?;
    let leap_year =
        year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year => 29,
        2 => 28,
        _ => 0,
    };
    if day == 0 || day > days_in_month {
        return Err(RegistryError::RevalidationDate { value });
    }
    Ok(value)
}
