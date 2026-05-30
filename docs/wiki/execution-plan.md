# Cross-Platform Execution Plan

This plan maps research to implementation milestones for `dfx`.

## Current Build Status

- Milestone 1 is complete: `inspect --verbose` exposes normalized provider capability flags, while `profile template` and `profile validate` provide provider-free profile generation and validation before mutation workflows.
- Milestone 2 is complete for the tracked Linux matrix: all 30 Linux issues have detection, remediation guidance or mutation behavior, and tests.
- Milestone 3 is complete for macOS read/detect/remediation coverage. Direct writes are implemented through LaunchServices public APIs when available, with `duti` as a fallback.
- Milestone 4 is complete for Windows read/detect/remediation coverage. Direct `UserChoice` mutation remains intentionally unsupported; writes are routed through managed default-association XML policy. `windows-policy` also provides ProgID capability discovery/audits, target coverage planning, self-contained deployment/removal bundles, zip archives, and bundle inspection, domain GPO create/configure/link artifacts, Backup-GPO safety backups, Restore-GPO rollback, Get-GPOReport settings reports, Get-GPRegistryValue policy-value inspection, local gpupdate refresh, remote Invoke-GPUpdate scheduling, gpresult/RSoP evidence collection, machine `Registry.pol`, offline `.reg`, LGPO text, and PowerShell policy pointer artifacts, active policy backup/restore, optional app-query-to-ProgID resolution, profile compilation/deployment and XML-to-profile round trips, direct profile-to-ApplicationDefaults CSP replace/delete payload generation, Intune custom OMA-URI setting generation, DISM image/default-user servicing wrappers, XML normalization and diff/drift checks, export, merge, Windows 11 suggested/version policy controls with validation visibility, status, validation, template generation, policy install, and policy uninstall helpers for enterprise workflows.
- Milestone 5 is implemented for open-test: `open-test` provides a safe handler-resolution preflight with structured evidence, explicit `launched=false` status by default, and an opt-in `--launch` mode with launcher command evidence, with platform-backed integration fixtures now added for GNOME, KDE, WM-only Linux, recent macOS, and Windows 11 scenarios.
- Milestone 6 is complete: every issue in the 90-issue catalog is mapped in [issue-matrix.md](./issue-matrix.md). macOS and Windows items are marked `safe` where remediation is constrained to guided, non-mutating flows.

## Milestone 1: Unified Domain Model

Goal: define one internal model that can represent OS-specific association semantics.

- Add target categories:
- `browser` (bundle concept)
- `scheme` (protocol)
- `content_type` (MIME on Linux, UTI on macOS, extension/ProgID abstraction on Windows)
- Add capability flags per provider:
- `can_read_current`
- `can_write_user_default`
- `can_write_system_default`
- `policy_restricted`

Acceptance:
- CLI can print normalized support matrix per host (`dfx inspect --verbose`).

## Milestone 2: Linux Deep Adapter

Goal: implement deterministic Linux behavior across DE and portal scenarios.

- Read/resolve according to MIME Apps spec precedence.
- Write browser bundle consistently:
- `x-scheme-handler/http`
- `x-scheme-handler/https`
- `text/html`
- `application/xhtml+xml`
- optional `xdg-settings default-web-browser` sync
- Add `dfx doctor linux` checks for portal backend, stale desktop ids, and cross-tool consistency (`xdg-mime` vs `gio`).

Acceptance:
- Linux issue list coverage >= 24/30 with explicit detection or remediation guidance.

## Milestone 3: macOS Adapter

Goal: safe read-first support, then controlled write support.

- Implement read support for URL scheme and content-role defaults.
- Implement write support using Launch Services public APIs first, with explicit fallback behavior when native APIs are unavailable.
- Validate bundle id registration and declaration coverage before mutation.
- Add `dfx doctor macos` for stale handler and declaration mismatch checks.

Acceptance:
- macOS issue list coverage >= 20/30 in detection, >= 12/30 in direct remediation.

## Milestone 4: Windows Adapter

Goal: policy-aware, truthful behavior with explicit limits.

- Implement read support for effective defaults and candidate capabilities.
- Implement policy detection for managed default associations (GPO/MDM).
- Provide guided remediation output when direct writes are unsupported.
- Support enterprise workflow helpers for ProgID capability audits and for validating/generating default-association XML without bypassing `UserChoice`.

Acceptance:
- Windows issue list coverage >= 22/30 in detection, >= 10/30 in direct remediation.

## Milestone 5: Verification Harness

Goal: prove open-path behavior, not just config state.

- Add `dfx open-test` for:
- URL scheme handler resolution
- content/MIME handler resolution
- callback scheme handler resolution via `DFX_CALLBACK_SCHEME`
- expected handler comparison with machine-readable pass/fail status
- optional launch execution with launcher command/argument evidence

Acceptance:
- Repro tests for OAuth/browser callback scenarios across at least:
- GNOME + KDE + WM-only Linux
- recent macOS release
- recent Windows 11 release

## Milestone 6: Issue-Driven Roadmap

Goal: use the 90-issue catalog as a public tracking matrix.

- Add an issue matrix file with columns:
- `Issue`
- `Detect`
- `Remediate`
- `OS`
- `Status`
- `Tests`
- `Notes`
- Track each issue as one or more adapter tasks.

Acceptance:
- Every issue in [top-issues-by-os.md](./top-issues-by-os.md) mapped to backlog items.

## Immediate Next Engineering Tasks

1. Integration fixture coverage is now in place across the three OS families for mixed WM/desktop-transition and duplicate-handler edge cases, including mismatch, fallback, duplicate-handler, browser-path, callback mismatch, and launch-skip-on-mismatch scenarios.
2. Evaluate safe macOS LaunchServices write flows behind explicit capability gates before enabling non-dry-run writes.
3. Keep the issue matrix, remediation guide, README command contract notes, and JSON automation documentation synchronized as adapter behavior changes.
