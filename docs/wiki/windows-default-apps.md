# Windows Default Applications Reference

## Core Model

Windows default apps are based on registered capabilities plus protected user choice assignment for file types and protocols.

- App registration advertises supported file extensions, MIME types, and protocols.
- User-selected defaults are protected and not intended for silent arbitrary rewrites.
- Enterprise policy can pre-stage or suggest defaults via XML/CSP paths.

References:
- Default Programs (Win32): https://learn.microsoft.com/en-us/windows/win32/shell/default-programs
- File type/URI model: https://learn.microsoft.com/en-us/windows/compatibility/file-type-and-protocol-associations-model

## Critical Concepts

- `ProgID` and capability registration determine candidate handlers.
- `UserChoice` protections make direct registry forcing brittle and unsupported.
- Modern flows prefer Settings UI, app-driven prompts, or managed policy.

References:
- Default apps platform: https://learn.microsoft.com/en-us/windows/apps/develop/windows-integration/default-apps-platform
- User support path: https://support.microsoft.com/windows/e5d82cad-17d1-c53b-3505-f10a32e1894d

## Policy and Fleet Paths

- Export defaults to XML with DISM.
- Import defaults in image provisioning or through policy.
- MDM policy (`ApplicationDefaults` CSP) supports managed assignment behavior.

References:
- DISM XML import/export: https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/export-or-import-default-application-associations?view=windows-11
- Policy CSP: https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-applicationdefaults

## Launch Behavior Notes

- URI launch path can be platform-specific (`LaunchUriAsync`, Shell execution, protocol activation).
- Some system URIs can intentionally bypass user browser defaults (for platform reasons).

Reference:
- Launch default app for URI: https://learn.microsoft.com/en-us/windows/apps/develop/launch/launch-default-app

## Operational Constraints For dfx

- `dfx` should not promise unsupported forced changes to protected defaults.
- Verification should distinguish:
- Declared capabilities
- Current user defaults
- Policy-enforced defaults
- Fallback behavior when no valid handler is present

## dfx implementation status (current build)

- On Windows hosts, `inspect` reports policy constraints and native registry-read capability.
- `get` performs best-effort native default lookups for scheme and common MIME mappings (`text/html`, `application/xhtml+xml`) from user/system association paths.
- `doctor --browser` inspects protocol and MIME mappings, surface-level scope divergence between HKCU/HKLM, and UserChoice hash presence for browser-related protocols.
- `doctor --browser` also validates that selected defaults resolve to a usable command registration, surfacing `W19` for mappings that cannot be launched from registry command entries.
- `doctor --browser` also surfaces `W22` when a selected handler is missing a discoverable capabilities block in registry compatibility locations.
- `doctor --browser` also checks handler launch command templates for URI payload placeholders (`%1`, `%u`, etc.) and reports `W20` when a browser registration looks to be scheme-incompatible.
- `doctor --browser` also validates shell verb defaults and icon registration for selected handlers, surfacing `W24` when masking defaults or discoverability issues exist.
- `doctor --browser` now includes a per-family extension consistency pass for web MIME families and reports `W25` when `text/html` or `application/xhtml+xml` handler coverage is partial or diverges across extensions.
- `doctor --browser` now reports `W02` when the selected default appears in registry defaults but does not declare a target-specific URL/MIME capability mapping.
- `W02` accepts both MIME capability declarations and file-extension capability declarations for web MIME targets, because many browser registrations advertise `.html`/`.htm` under `FileAssociations` rather than `text/html` under `MIMEAssociations`.
- `doctor --browser` now reports `W11` when a selected handler appears orphaned (no discoverable registration key under expected ProgID/Application classes).
- `doctor --browser` now reports `W12` when both user and machine association sources report different handler candidates for the same web target, which can indicate Store+desktop duplicate/default-race situations.
- `doctor --browser` now inspects common policy locations for default-association settings and reports `W06` when policy configuration is detected or when policy-declared ProgIDs differ from current user defaults.
- `doctor --browser` now reports `W09` when policy-driven web defaults appear machine-scoped (`HKLM`) without a usable HKCU binding.
- `doctor --browser` now reports `W10` when policy-declared web `ProgID` values no longer resolve while current defaults point to newer identifiers.
- `doctor --browser` now reports `W28` when feature-update markers are present and required web defaults are not policy-mandatory, since upgrades can reassert defaults.
- `doctor --browser` now reports `W17` when remote-session indicators are present (for example, RDP/RemoteApp signals), indicating launch semantics can differ from local sessions.
- `doctor --browser` now reports `W18` when selected web defaults look AppX/AppContainer-like and may require Store-style activation flows.
- `doctor --browser` now reports `W07` when managed policy association XML is unreadable or malformed.
- `doctor --browser` now reports `W08` when managed policy association mappings omit required defaults (`http`, `https`, `text/html`, `application/xhtml+xml`, plus the normalized `DFX_CALLBACK_SCHEME` when configured).
- `doctor --browser` now flags `W15` when selected handler command registrations are likely bound to 32-bit install paths on non-32-bit runtimes.
- `doctor --browser` now reports `W23` when the active handlers appear to mix stable and channel variants (stable/beta/dev/canary) for the same browser family.
- `doctor --browser` now reports `W14` when legacy `assoc`/`ftype` tooling is available but not a reliable model for modern default-app controls.
- `doctor --browser` now reports `W16` when registry hardening settings (such as `SettingsPageVisibility`/prompt-disabling policies) may block default-app remediation flows.
- `doctor --browser` now reports `W26` when policy associations for required web defaults are mandatory and likely to reapply on sign-in.
- `doctor --browser` now reports `W29` when registry startup/run entries or similar local repair tooling indicate a likely conflict with managed defaults.
- `doctor --browser` now reports `W13` when hash-backed `UserChoice` entries suggest likely reset or policy notification behavior.
- `doctor --browser` now reports `W27` when policy and user-scope values conflict for managed policy-assisted default assignments.
- `doctor --browser` now supports `DFX_CALLBACK_SCHEME`; when set to either a scheme (`myapp`) or callback URI (`myapp://oauth/callback`), it checks for missing callback mappings and when callback defaults still resolve to the browser default, reporting `W30`.
- `set --dry-run` and `doctor --browser --fix --dry-run` now return explicit Settings/policy remediation plans, including deduplicated finding-specific `doctor` remediation lines and default-association XML templates where applicable; actual writes remain unsupported because direct `UserChoice` registry mutation is intentionally avoided.
- Non-dry-run `set` refuses Windows writes with an explicit `UserChoice` hash-protection error and keeps the safe Settings/XML/CSP plan in the result so automation can present the correct remediation path.
- `windows-policy audit --prog-id <ProgID>` audits Windows ProgID registration, declared browser capabilities, open command placeholders, icon metadata, and optional callback scheme coverage without writing `UserChoice`.
- `windows-policy validate --file DefaultAssociations.xml` validates enterprise default-association XML for required browser targets and optional callback schemes without reading or writing registry state. It treats missing `ProgId` values and conflicting ProgIDs across equivalent web extensions as policy issues, not merely cosmetic XML differences.
- `windows-policy template --prog-id <ProgID>` emits a browser-focused default-association XML starter for enterprise policy/CSP review.
- On non-Windows hosts, all runtime operations are surfaced as unsupported with explicit remediation guidance.

### `windows` detection edge cases

`W10` is triggered only when policy declares web `ProgID` targets that are still configured for required protocol/MIME values but no longer resolve to registered handler keys.
This avoids reporting transient hash churn unless policy mapping targets are stale and the policy-managed current value still points elsewhere.

Policy XML source paths are expanded using both Go-style (`$VAR`, `${VAR}`) and Windows-style (`%VAR%`) environment variables before `W07`/`W08`/`W10` analysis reads the referenced file. Windows-style variable names are resolved case-insensitively.

`W28` is reported when Windows feature-update/state keys are present and web policy bindings are managed-but-recommended rather than mandatory.
That signal is intentionally limited to likely reset signals (upgrade state, reboot-pending setup state, and pending image states) to reduce false positives.

`W29` now checks a broader startup surface for browser-repair-style automation:
- `Run`, `RunOnce`, `RunOnceEx`, `RunServices`, and policy-defined startup override hives under both 64-bit and WOW6432Node namespaces
- repair signatures in startup values only when a reset/defaulting intent is present and browser context can be inferred from the same value/key

Because repair tooling varies across enterprise images, these findings should be treated as high-confidence hints and validated in staging before rollout.

`W16` treats `SettingsPageVisibility` according to policy direction: `hide:defaultapps` blocks the remediation UI, `showonly:defaultapps` keeps it available, and `showonly:` values without the Default Apps page block guided remediation. `appsfeatures` alone is not enough for the Default Apps flow.
