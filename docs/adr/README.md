# Architecture Decision Records

Significant, hard-to-reverse design decisions for pygrindvakt, in the
lightweight ADR format (Status / Context / Decision / Consequences). Each record
is immutable once accepted; a later decision that changes course is added as a
new record that supersedes the old one.

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-sync-api-over-embedded-tokio-runtime.md) | Synchronous Python API over an embedded, PID-keyed tokio runtime | Accepted |
| [0002](0002-python-protocol-adapters.md) | Python protocol adapters for stores and outbound HTTP, failing closed | Accepted |
| [0003](0003-fail-closed-hardening.md) | Fail-closed hardening added at the binding boundary | Accepted |
