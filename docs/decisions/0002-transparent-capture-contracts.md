# 0002 — Ratify transparent-capture contracts before the runtime

Status: accepted (2026-07-14)

## Context

The product is adding rootless, transparent network capture for wrapped processes. The public
interceptor will own the provisioner and dataplane while the product CLI owns run configuration and
transport selection. Those pieces need one compatibility boundary before namespace, forwarding, or
TLS-policy implementation begins.

Transparent capture also introduces honest degradation states. TLS that cannot be terminated, raw
TCP or UDP flows, transport fallback, and strict-mode failures must remain queryable without log
parsing and without inventing request bodies that were never observed.

## Decision

1. Extend the existing `hiloop_core::event::Event` v1 envelope. Do not add a parallel event type or
   change its locked top-level field set.
2. Provide typed constructors for `tls.interception_failed`, `tls.passthrough`, `net.passthrough`,
   `capture.transport`, and `capture.fatal`. Their reason values are closed enums, their booleans and
   byte counts retain scalar types, and their APIs cannot accept bodies, certificates, or secret
   identifiers and values.
3. Share one exact transport-selection value type: `auto`, `netns`, `proxy`, or `off`. The product
   CLI will expose and enforce the selector in the integration wave; this decision only establishes
   the contract.
4. Represent first-connection TLS compatibility as a versioned registry of exact canonical
   host-and-port rows. Every row carries reproducible evidence, an owner, and an ISO-8601
   revalidation date. Wildcards and user-provided bypass rows are not part of the contract.
5. The public interceptor owns transparent provisioner and dataplane behavior. The product CLI owns
   selection and run-policy configuration. Later implementation must preserve unprivileged,
   child-scoped isolation and must not require host-global network or trust-store mutation.
6. The selected rootless forwarder is a version-pinned, separately executed `pasta` binary. If
   distribution policy prohibits its GPL artifacts, investigate a native host-dial broker; use a
   gVisor carrier only if generic L3 or ICMP becomes a requirement.

This foundation contains no network-namespace or forwarder runtime. Those capabilities land behind
the contracts in later work.

## Consequences

- Event-shape tests lock every new event name, attribute set, scalar type, and closed reason value.
- Transport parsing rejects aliases, capitalization, and combined values.
- Compatibility entries are reviewable data with an explicit revalidation lifecycle rather than a
  broad host-bypass mechanism.
- Strict-mode dataplane shutdown, transport preflight, fallback policy, helper packaging, and the
  CLI migration remain separate implementation work.

The executable boundary and ownership rules are summarized in
[`../INTERFACES.md`](../INTERFACES.md#transparent-capture-contracts).
