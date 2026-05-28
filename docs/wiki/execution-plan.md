# Cross-Platform Execution Plan

This plan maps research to implementation milestones for `dfx`.

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
- Implement write support using Launch Services public APIs only.
- Validate bundle id registration and declaration coverage before mutation.
- Add `dfx doctor macos` for stale handler and declaration mismatch checks.

Acceptance:
- macOS issue list coverage >= 20/30 in detection, >= 12/30 in direct remediation.

## Milestone 4: Windows Adapter

Goal: policy-aware, truthful behavior with explicit limits.

- Implement read support for effective defaults and candidate capabilities.
- Implement policy detection for managed default associations (GPO/MDM).
- Provide guided remediation output when direct writes are unsupported.
- Support enterprise workflow helpers (export/validate XML, capability audit).

Acceptance:
- Windows issue list coverage >= 22/30 in detection, >= 10/30 in direct remediation.

## Milestone 5: Verification Harness

Goal: prove open-path behavior, not just config state.

- Add `dfx open-test` for:
- URL scheme open
- file type open
- callback scheme open
- Capture launcher path evidence (where available) and expected handler id.

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

1. Implement Linux precedence-aware reader instead of command-only reader.
2. Add `dfx doctor --browser` with structured output.
3. Add machine-readable result format (`--json`) for CI and enterprise automation.
4. Add provider test fixtures for synthetic config precedence cases.
