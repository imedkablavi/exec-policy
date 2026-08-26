# Changelog

All notable changes to this project are documented here.

## [0.1.0] - 2026-08-27

### Added

- explicit command allowlisting with optional absolute executable pinning
- shell-free argv execution through `child_process.spawn()`
- canonical cwd root enforcement with symlink-aware containment checks
- optional trusted executable roots
- argument count/size limits, deny patterns and custom validators
- `read`, `write` and `destructive` risk classification
- configurable approval gates with fail-closed behavior
- explicit environment inheritance and override allowlists
- preview and dry-run authorization flows
- timeout, AbortSignal and captured-output limits
- structured audit events that omit raw argv and environment values
- typed error classes for authorization and execution failures
- fail-closed `destructive` risk for commands without an explicit classifier/default
- null-prototype command storage plus own-property checks to prevent prototype-name allowlist bypasses
- relative `PATH` entry rejection for bare executable resolution
- Windows shell-script refusal to preserve `shell: false` semantics
- approval-handler exception handling that fails closed with `ApprovalDeniedError`
- first-wins termination reasons to avoid timeout/abort/output-limit race misclassification
- combined argv and child-environment byte ceilings
- per-policy direct-child concurrency limits
- tighten-only per-execution timeout/output overrides so callers cannot weaken policy budgets
- child environment snapshotting before approval to prevent post-approval `process.env` drift
- non-blocking best-effort audit delivery so logging outages cannot stall authorization
- runtime rejection of async argument validators and non-boolean approval results
- bounded logical command identifiers and early argv-count rejection before cloning untrusted arrays
- pre-aborted executions are rejected before approval callbacks are invoked
- invalid command identifiers are sanitized in denial audit events
- streaming UTF-8 decoding preserves multibyte output split across child-process chunks
