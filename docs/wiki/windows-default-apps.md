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

- `dfx` should not edit protected UserChoice values directly.
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
- `set --dry-run` and `doctor --browser --fix --dry-run` return explicit Settings/policy remediation plans, including deduplicated finding-specific `doctor` remediation lines and default-association XML templates where applicable.
- Non-dry-run `set` writes through default-association XML policy. It merges target associations into the configured XML file, sets `HKLM\Software\Policies\Microsoft\Windows\System/DefaultAssociationsConfiguration`, and leaves hash-protected `UserChoice` registry keys untouched.
- `windows-policy backup --file <xml>` reads the active Group Policy/CSP policy XML source, validates it, and writes a backup copy before install/deploy/uninstall operations.
- `windows-policy bundle --file <xml> --output <dir>` packages reviewed XML with `.reg`, LGPO text, `Registry.pol`, local PowerShell, SyncML, Intune JSON, manifest, and operator notes. `--profile <dfx.json>` can compile a profile into the bundled XML, GPO flags add a domain GPO script, and `--archive <zip>` writes a portable archive of the same bundle. `--delete` creates the matching removal bundle for registry, LGPO, `Registry.pol`, CSP Delete SyncML, local PowerShell, and optional domain GPO removal.
- `windows-policy bundle-inspect --path <dir>` and `windows-policy bundle-inspect --archive <zip>` inspect generated bundle folders or archives, check required artifacts, read the manifest type, and validate bundled deployment XML.
- `windows-policy compile --profile <dfx.json> --file <xml>` compiles a dfx profile into deterministic Windows policy XML, treating profile `app` values as ProgIDs so the output can be generated offline.
- `--resolve-apps` on profile-backed policy commands resolves profile app queries to ProgIDs using Windows registered-application metadata. Ambiguous or missing matches fail instead of guessing.
- `windows-policy csp --file <xml>` validates policy XML, base64-encodes it for the ApplicationDefaults CSP, and can emit a SyncML `Replace` payload for MDM deployment. `windows-policy csp --profile <dfx.json>` compiles a profile directly into that payload. `windows-policy csp --delete --syncml` emits the matching CSP delete payload for MDM removal workflows.
- `windows-policy intune --file <xml>` emits the same ApplicationDefaults payload as Intune custom OMA-URI fields: name, description, OMA-URI, data type, and base64 value. `windows-policy intune --profile <dfx.json>` compiles a profile directly into that Intune-ready setting.
- `windows-policy deploy --profile <dfx.json> --file <xml>` compiles a profile, writes the staging XML, installs the policy pointer, and optionally runs `gpupdate` in one dry-runnable workflow.
- `windows-policy diff --file <xml>` compares desired policy targets against the installed policy by default, or against `--current <xml>` for offline drift checks. It exits non-zero when target ProgIDs differ.
- `windows-policy export --file <xml>` runs DISM's online default-association export, then validates the exported XML so it can be reviewed, edited, and installed through the policy workflow.
- `windows-policy import --file <xml>`, `windows-policy list`, and `windows-policy remove` wrap DISM default-association servicing commands for online or offline Windows images. This targets image/default-user association baselines and does not rewrite existing per-user `UserChoice` values.
- `windows-policy merge --file <xml> --prog-id <ProgID> --browser` updates a policy XML file offline for browser/protocol/MIME targets, including optional callback schemes, without installing the policy.
- `windows-policy normalize --file <xml>` parses, deduplicates, sorts, preserves or overrides root `Version`, validates, and writes stable policy XML for review or source control.
- `windows-policy profile --file <xml>` converts Windows policy XML back into a dfx profile, coalescing complete browser target coverage into a single browser profile entry where possible.
- `windows-policy registered --query <text>` lists registered Windows default-app capability metadata and associated ProgIDs so policy authors can discover exact identifiers before template, merge, compile, or deploy.
- `windows-policy gpo --gpo-name <name> --policy-path <xml>` emits a GroupPolicy PowerShell artifact that sets the documented Computer Configuration registry policy value in a domain GPO. `--create` adds `New-GPO`, `--link-target <DN>` adds `New-GPLink`, and `--delete` emits `Set-GPRegistryValue -Disable` so clients remove the policy value when the GPO applies.
- `windows-policy gpo-backup --gpo-name <name> --path <dir>` wraps `Backup-GPO` so administrators can capture a domain GPO backup before changing default-app policy. `--all`, `--gpo-guid`, `--comment`, `--what-if`, `--script`, and `--output` are supported.
- `windows-policy gpo-restore (--gpo-name <name> | --gpo-guid <guid>) --path <dir>` restores a domain GPO from an existing backup directory using `Restore-GPO`. `--domain`, `--server`, `--what-if`, `--script`, and `--output` are also supported.
- `windows-policy gpo-report --gpo-name <name> --format html --file <report.html>` wraps `Get-GPOReport` for domain GPO settings evidence. `--gpo-guid` and `--all` are also supported, and `--script`/`--output` emit reviewed PowerShell.
- `windows-policy gpo-status --gpo-name <name>` wraps `Get-GPRegistryValue` to read the `DefaultAssociationsConfiguration` registry policy value from a domain GPO.
- `windows-policy gpresult` wraps Windows `gpresult` for post-rollout Group Policy evidence. Use `--scope computer --format html --file <report.html>` for a reviewable RSoP report, or `--format summary` for text output.
- `windows-policy refresh --target computer --force` wraps `gpupdate` for explicit post-deployment policy refresh. `--wait`, `--logoff`, `--boot`, and `--sync` expose the documented lifecycle controls.
- `windows-policy invoke-refresh --computer <host> --random-delay 0 --force` wraps the GroupPolicy module's `Invoke-GPUpdate` for remote refresh scheduling. `--script` and `--output` generate a reviewed PowerShell artifact instead of running it.
- `windows-policy reg --policy-path <xml>` emits an offline `.reg` artifact that sets the documented machine policy pointer. `--delete` emits the matching value-delete artifact.
- `windows-policy lgpo --policy-path <xml>` emits LGPO text for the same Computer Configuration policy pointer. `--delete` emits the matching value-removal action for local Group Policy tooling.
- `windows-policy pol --output Registry.pol --policy-path <xml>` emits a machine `Registry.pol` artifact for direct local or domain Group Policy packaging. Without `--output`, the command exposes base64 content for package systems.
- `windows-policy script --file <xml>` emits a PowerShell deployment artifact that can copy XML, set or remove the machine policy pointer, and optionally run `gpupdate` without executing anything locally.
- `windows-policy template`, `merge`, `compile`, and `deploy` support `--suggested` and `--version` for Windows 11 22H2+ policy timing controls. Suggested associations apply once for the current `DefaultAssociations Version`; increment the version to re-apply them.
- `windows-policy validate`, `status`, and `diff` expose the detected root `Version` and suggested-association state so mandatory versus one-time policy behavior is visible to automation.
- `windows-policy restore --file <xml>` restores a backed-up policy payload through the same validation, copy, policy-pointer, optional `gpupdate`, and sign-in semantics as install.
- `windows-policy status` reads known default-association policy registry locations, resolves inline XML or XML file paths, and validates the active policy payload against browser/callback requirements.
- `windows-policy targets --callback-scheme <scheme>` prints the browser/callback target set and the concrete XML identifiers used for policy generation and validation.
- `windows-policy install --file <xml>` validates a reviewed XML file, copies it to the configured policy path when needed, and sets the documented Group Policy registry value. Use `--gpupdate` to request `gpupdate /target:computer /force`, `--dry-run` to preview the copy/registry/refresh operations, and `--allow-incomplete` only for intentionally partial policies.
- `windows-policy uninstall` removes the documented machine policy value without touching `UserChoice`. Use `--delete-file` only when the XML file should also be removed, and `--gpupdate` to request a computer-policy refresh after uninstall.
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
