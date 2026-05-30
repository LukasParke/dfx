# macOS Default Applications Reference

## Core Model

macOS defaults are managed by Launch Services and type systems based on UTI/UTType and URL schemes.

- URL scheme defaults: per-scheme handler bundle identifiers.
- Content type defaults: role handler for UTI/content type.
- User preference and system registration both affect resolution.

References:
- Launch Services: https://developer.apple.com/documentation/coreservices/launch_services
- Uniform Type Identifiers: https://developer.apple.com/documentation/uniformtypeidentifiers

## Association Axes

- Protocol handlers: `http`, `https`, custom schemes.
- File/content handlers: extensions mapped to UTIs, then UTIs mapped to apps by role.
- Role-specific handlers: viewer/editor/shell roles can differ.

`dfx --mime` accepts MIME identifiers such as `text/html` for cross-platform
content defaults. It intentionally rejects filename extensions such as `.html`
and raw UTI strings, because those require platform-specific resolution before
they can be compared safely.

References:
- `LSCopyDefaultHandlerForURLScheme`: https://developer.apple.com/documentation/coreservices/1441725-lscopydefaulthandlerforurlscheme
- `LSCopyDefaultRoleHandlerForContentType`: https://developer.apple.com/documentation/coreservices/1442793-lscopydefaultrolehandlerforconte

## Registration Inputs

- Application `Info.plist` contributes declared document and URL capabilities:
- `CFBundleDocumentTypes`
- `CFBundleURLTypes`

References:
- `CFBundleDocumentTypes`: https://developer.apple.com/documentation/bundleresources/information_property_list/cfbundledocumenttypes
- `CFBundleURLTypes`: https://developer.apple.com/documentation/bundleresources/information_property_list/cfbundleurltypes

## Operational Constraints For dfx

- Some Launch Services APIs have deprecation notes, but they remain the published interface for many association tasks.
- Direct database manipulation is unsafe and not supported.
- Bundle ID correctness and app registration timing matter for deterministic results.

References:
- `LSSetDefaultHandlerForURLScheme`: https://developer.apple.com/documentation/coreservices/1447760-lssetdefaulthandlerforurlscheme
- `LSSetDefaultRoleHandlerForContentType`: https://developer.apple.com/documentation/coreservices/1440042-lssetdefaultrolehandlerforcontent

## Practical Verification Axes

- Current URL scheme handler by bundle id.
- Current content-role handler by UTI.
- Installed app declaration coverage (scheme + UTI + role).
- Post-install/post-update re-registration behavior.
- Role consistency across launch handlers (`LSHandlerRoleAll`, `LSHandlerRoleViewer`, `LSHandlerRoleEditor`, `LSHandlerRoleShell`) for web targets.

## dfx implementation status (current build)

- On macOS hosts, `inspect` now reports cache-read readiness and command capability.
- `get` and read-only `doctor` for browser/path consistency checks are available in cache-backed mode for the current user.
- `doctor --browser` now flags role mismatches for web-related schemes/types when role-specific handlers differ.
- `doctor --browser` also surfaces `M24` when multiple cached role handlers collide for the same web scheme/content target, which can indicate stale or duplicated LaunchServices registration.
- `doctor --browser` now reads each selected app’s `Info.plist` and:
  - reports `M03` when required URL schemes for current defaults are missing from `CFBundleURLTypes`.
  - reports `M17` for incomplete, missing, or malformed URL-type declarations (`CFBundleURLTypes` / `CFBundleURLSchemes`).
  - reports `M18` when required document type coverage (`CFBundleDocumentTypes` / `LSItemContentTypes`) is missing or malformed for `text/html` or `application/xhtml+xml`.
- `doctor --browser` now reports `M19` when `osascript` is unavailable; cache-backed LaunchServices checks still run, but manifest and bundle-id validation are skipped in that environment.
- `doctor --browser` also surfaces `M26` when the currently selected handler cannot be resolved to an installed app bundle identifier.
- `doctor --browser` now reports `M04` when stable/beta/dev channel variants of the same browser family are mixed across web targets.
- `doctor --browser` now reports `M09` when selected browser defaults still resolve to uninstallable bundle IDs.
- `doctor --browser` now reports `M14` when user and system LaunchServices cache handlers diverge for the same web targets.
- `doctor --browser` now reports `M08` when web content aliases (`public.html`, `public.xhtml*`) diverge from canonical `text/html` / `application/xhtml+xml` handler resolution.
- `doctor --browser` now reports `M21` when environment variables suggest execution in terminal/non-Finder contexts that can affect launch behavior.
- `doctor --browser` now reports `M22` when SSH/headless session signals suggest the diagnostic is running outside the target interactive session.
- `doctor --browser` now reports `M23` when LaunchServices cache parsing fails, is unreadable, or is malformed.
- `doctor --browser` now supports `DFX_CALLBACK_SCHEME`; if set to either a scheme (`myapp`) or callback URI (`myapp://oauth/callback`), it checks for missing callback scheme mapping and reports `M30` when callback defaults still point to the browser default.
- `doctor --browser` now reports `M11` when selected browser bundles are sandboxed without direct file-access entitlements and may route file-path URL handoff differently from Finder behavior.
- `doctor --browser` now reports `M12` when managed LaunchServices policy payloads are detected and may override user browser defaults.
- `doctor --browser` now reports `M28` when application signing or notarization checks fail for a selected browser default.
- `doctor --browser` now reports `M29` when selected browser handler declarations differ in declared web content UTI signatures between active defaults.
- `doctor --browser` now reports `M10` when LaunchServices cache appears stale relative to a selected browser bundle’s Info.plist write time after recent install/update.
- `doctor --browser` now reports `M15` when selected browser handlers resolve from cloud/provider-synced paths (for example, Mobile Documents or other synced application roots).
- `doctor --browser` now reports `M16` when the selected browser’s executable architecture slice does not match the host architecture and may require translation compatibility.
- `doctor --browser` now reports `M27` when system extensions/filters are detected that may intercept URL/file routing for launched browser defaults.
- `doctor --browser` now reports `M05` when mixed/partial web defaults coincide with browser updater metadata, updater-named bundle components, updater agents, or recent bundle-change signals that may have reclaimed defaults.
- `doctor --browser` now reports `M13` when `http`/`https` point to one browser but web content UTIs are missing or assigned elsewhere, matching partial browser-prompt behavior.
- `doctor --browser` now reports `M20` when OS version checks indicate LaunchServices behavior should be treated as release/API-sensitive.
- `doctor --browser` now reports `M25` when common browser profile stores indicate multiple profiles can influence deep-link routing.
- `set --dry-run` and `doctor --browser --fix --dry-run` now return explicit LaunchServices/System Settings remediation plans, including deduplicated finding-specific `doctor` remediation lines and `duti`-style preview commands for CLI review; actual writes remain unsupported until Launch Services write workflows are implemented safely.
- On non-macOS hosts, all runtime operations are surfaced as unsupported with explicit remediation guidance.
