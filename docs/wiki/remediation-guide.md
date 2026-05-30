# Remediation Guide

`dfx` distinguishes safe remediation from unsafe platform mutation.

- Linux can apply default-app changes through supported user-level tools.
- macOS remediation is currently guided and dry-run only; direct LaunchServices writes are not enabled.
- Windows remediation is currently guided and dry-run only; direct `UserChoice` registry writes are intentionally avoided.

Use this guide with:

```sh
dfx doctor --browser
dfx doctor --browser --fix --dry-run
dfx set --browser --app <app-id> --dry-run
```

## macOS

Use `doctor --browser --fix --dry-run` to get:

- System Settings actions for the default browser.
- Scheme/content consistency checks for `http`, `https`, `text/html`, and `application/xhtml+xml`.
- Finding-specific remediation lines.
- `duti`-style preview commands when an app target is provided.

Recommended operator flow:

1. Confirm the intended browser bundle ID.
2. Set the default browser through System Settings or the browser's supported prompt.
3. Re-register or reinstall the browser if LaunchServices cache entries are stale.
4. Re-run `dfx doctor --browser`.
5. If `DFX_CALLBACK_SCHEME` is relevant, set it to the callback scheme or URI and re-run doctor.

Finding groups:

- `M01`, `M06`, `M08`, `M13`: apply the same intended browser across URL schemes and web content types, then re-run doctor.
- `M02`, `M09`, `M26`: remove stale bundle references by reinstalling or clearing the old app registration.
- `M03`, `M17`, `M18`, `M29`: repair the app `Info.plist` declarations or reinstall a browser build with correct URL/document declarations.
- `M04`, `M05`, `M10`, `M16`: align the selected browser channel/build and reapply defaults after updates.
- `M11`, `M15`, `M25`, `M27`, `M28`: validate the launch environment, profile, path, sandbox/signing, and interception layers before treating OS defaults as the only cause.
- `M12`, `M14`, `M21`, `M22`, `M23`: run diagnostics in the target user session and resolve policy/cache/domain conflicts first.
- `M30`: point the callback scheme at the native app handler, not the browser.

## Windows

Use `doctor --browser --fix --dry-run` to get:

- Windows Settings actions for browser protocols and file extensions.
- Enterprise default-association XML/CSP guidance.
- Finding-specific remediation lines.
- A direct warning that `UserChoice` registry edits are not used.

Recommended operator flow:

1. Confirm the intended ProgID/Application registration.
2. Use Windows Settings for individual user remediation.
3. Use default-association XML/CSP for managed fleets.
4. Avoid direct writes to `UserChoice` keys.
5. Re-run `dfx doctor --browser` in the target user profile after sign-in, policy refresh, or feature updates.

Finding groups:

- `W01`, `W13`: use Settings or policy; do not edit hash-protected `UserChoice` values.
- `W02`, `W11`, `W19`, `W20`, `W22`, `W24`: repair or reinstall the app registration so capabilities, commands, icons, verbs, and URI placeholders are valid.
- `W03`, `W04`, `W05`, `W12`, `W21`, `W25`: align protocol, MIME, extension, user, and machine-scope defaults as one target set.
- `W06`, `W07`, `W08`, `W09`, `W10`, `W26`, `W27`, `W28`, `W29`: refresh enterprise policy XML/CSP, resolve mandatory/suggested policy behavior, and gate browser repair tooling.
- `W14`, `W16`, `W17`, `W18`: verify legacy tooling, hardening, remote-session, and AppContainer activation constraints before changing defaults.
- `W15`, `W23`: align architecture and channel-specific browser registrations.
- `W30`: register the OAuth/deep-link callback protocol to the native app handler instead of the browser.

## JSON automation

For automation, prefer JSON output:

```sh
dfx doctor --browser --json
dfx doctor --browser --fix --dry-run --json
dfx open-test --callback --expected <app-id> --json
dfx windows-policy audit --prog-id <ProgID> --json
dfx windows-policy validate --file DefaultAssociations.xml --json
dfx profile template --app <browser-app-id> --json
dfx profile validate --json dfx.json
dfx apply --dry-run --json dfx.json
```

Read `status.exit_code` for control flow. `doctor` and JSON error payloads also
include `status.would_fail`. Mutation-style outputs include `status.changed` and
`status.dry_run` where applicable, including validation failures after command
flags have parsed successfully. `--json=false` (or equivalent false value forms,
including `-json=0` and `-json=false`) force non-JSON diagnostics even when
JSON-capable paths are used.
`open-test` is a safe handler-resolution preflight by default: it reports the
current provider-resolved handler, expected-handler match status when
`--expected` is provided, and `status.launched:false`. Add `--launch` only when
the automation is allowed to start the platform opener; `dfx` still skips launch
when the expected handler check fails.
`windows-policy validate` checks enterprise default-association XML for required
browser targets and optional callback schemes. It is registry-free and safe to
run from CI on non-Windows hosts. Treat `valid:false` as a policy authoring
problem and `complete:false` as missing browser/callback coverage.
`windows-policy audit` is Windows-host-only and reads ProgID registration,
capability, command, and icon metadata. Use it before publishing XML/CSP defaults
to catch stale or incomplete browser registrations without writing `UserChoice`.
`profile validate` is provider-free and safe for CI on any host; use it before
`apply` to catch malformed, duplicate, or browser-overlapping profile entries.
`profile template` is also provider-free and emits a minimal valid browser
profile. If a deep-link callback should be part of the profile, pass both
`--callback-scheme` and `--callback-app` so the callback can point at the native
app instead of accidentally reusing the browser handler.
For `doctor --browser --fix --json`, the same `changed` and `dry_run` fields are
also mirrored into `status`, so automation can decide whether the remediation
plan changed state without parsing human-readable operation strings.
`set`, `apply`, and `doctor --fix` operation results use lowercase `changed` and
`operations` fields.
When a provider can describe a safe remediation plan but cannot apply it, JSON
output preserves returned operation plans alongside the error. For `doctor
--fix`, that means output can contain both `fix` and `fix_error`. For `set` and
`apply`, error payloads can include a `result` object with `operations`.
Consumers should show the operations and treat the non-zero `status.exit_code`
as the failed apply signal.
If `status.changed` is true alongside `fix_error`, the provider reported that
some state changed before the failure and the operator should re-run diagnostics
before retrying.
For `apply --json`, `status.changed` also includes successful entries completed
before a later entry failed; use `failed_index` and any returned `results` to
identify what happened before retrying.
Plain text mutation output includes `dry_run` and `changed` markers. Doctor fix
text output follows the same shape with `fix:` operation lines, `fix.dry_run`,
`fix.changed`, and `fix.error` when an attempted fix cannot be applied.
