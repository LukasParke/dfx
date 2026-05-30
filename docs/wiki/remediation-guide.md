# Remediation Guide

`dfx` distinguishes safe remediation from unsafe platform mutation.

- Linux can apply default-app changes through supported user-level tools.
- macOS remediation uses LaunchServices public APIs when available and `duti` as a CLI fallback; dry-run remains the recommended preview path.
- Windows remediation uses default-association XML plus the machine policy pointer; direct `UserChoice` registry writes are intentionally avoided.

For Windows fleets, `dfx windows-policy install --file <xml>` validates a
reviewed default-association XML file, places it at the policy path when needed,
and configures the Group Policy registry pointer without touching `UserChoice`.
Add `--gpupdate` when the CLI should request an immediate computer-policy
refresh; default-app associations can still require sign-out/sign-in to observe.
Use `dfx windows-policy backup --file <xml>` before replacing or removing a
managed policy so the currently configured policy payload can be restored.
Use `dfx windows-policy restore --file <xml>` to roll back to that backup
through the same validation and policy install path.
Use `dfx windows-policy gpo-restore --gpo-name <name> --path <dir>` to restore
an existing domain GPO backup created by `gpo-backup` with a reviewed PowerShell
script or dry-run flow.
Use `dfx windows-policy bundle --file <xml> --output <dir>` when change control
expects one reviewed folder containing XML, local policy artifacts, MDM payloads,
operator notes, and a manifest. Add GPO flags to include a domain GPO script.
Add `--archive <zip>` when the deployment workflow expects a single portable
bundle instead of a folder.
Use `dfx windows-policy bundle --delete --output <dir>` to create a reviewed
removal bundle for the same deployment channels. Add `--delete-file` only when
the local removal script should also remove the staged policy XML file.
Use `dfx windows-policy bundle-inspect --path <dir>` or `--archive <zip>` before
handoff to confirm the bundle manifest, required artifacts, and bundled
deployment XML are valid.
Use `dfx windows-policy registered --query <text>` on a representative Windows
machine to discover exact ProgIDs and capability mappings before generating
policy XML.
Use `--resolve-apps` on profile-backed policy commands only when compiling on a
representative Windows machine and you want profile app names resolved to exact
ProgIDs through registry metadata.
Use `dfx windows-policy compile --profile <dfx.json> --file <xml>` when the
source of truth is a dfx profile; profile app identifiers are interpreted as
Windows ProgIDs in this offline policy workflow.
Use `--suggested --version <value>` with compile/merge/template/deploy when
associations should be applied as Windows 11 suggested defaults instead of
mandatory every-sign-in mappings.
Use validate/status/diff output to confirm the policy's detected `Version` and
whether required associations are mandatory or suggested before rollout.
Use `dfx windows-policy csp --file <xml> --syncml` when the deployment target is
an MDM provider that consumes the ApplicationDefaults CSP rather than a local
Group Policy registry pointer.
Use `dfx windows-policy csp --profile <dfx.json> --syncml` to generate that MDM
payload directly from a dfx profile without staging XML first.
Use `dfx windows-policy intune --file <xml>` when the deployment target is
Intune custom OMA-URI and the operator needs the setting name, description,
OMA-URI, data type, and base64 value instead of raw SyncML.
Use `dfx windows-policy csp --delete --syncml` to generate the corresponding MDM
removal payload for that CSP setting.
Use `dfx windows-policy deploy --profile <dfx.json> --file <xml>` when the CLI
should compile and install the managed policy in one dry-runnable operation.
Use `dfx windows-policy diff --file <xml>` to detect drift between desired XML
and the installed policy before deciding whether to redeploy.
Use `dfx windows-policy export --file <xml>` first when you want to bootstrap a
reviewable XML baseline from the current machine through DISM.
Use `dfx windows-policy import --file <xml>` only for DISM image/default-user
association servicing; those imported defaults apply during first logon and are
separate from managed Group Policy/CSP enforcement.
Use `dfx windows-policy merge --file <xml> --prog-id <id> --browser` to update
that XML offline before validating and installing it.
Use `dfx windows-policy normalize --file <xml>` before review or commit when XML
has been edited by hand or assembled from multiple sources.
Use `dfx windows-policy profile --file <xml>` to turn reviewed Windows policy
XML back into a dfx profile for round-trip review or source control.
Use `dfx windows-policy gpo --gpo-name <name> --policy-path <xml>` when the
deployment channel is an Active Directory domain GPO and administrators want a
reviewed GroupPolicy PowerShell artifact instead of direct local writes.
Add `--create` and `--link-target <DN>` when the artifact should create the GPO
and link it to the target site, domain, or OU in the same reviewed script.
Use `dfx windows-policy gpo-backup --gpo-name <name> --path <dir>` before
changing a domain GPO so administrators have a restorable Group Policy backup.
Use `dfx windows-policy gpo-report --gpo-name <name> --format html --file <report.html>`
to capture the domain GPO's configured settings before or after rollout.
Use `dfx windows-policy gpo-status --gpo-name <name>` to confirm the domain GPO
contains the expected `DefaultAssociationsConfiguration` policy value.
Use `dfx windows-policy gpresult --scope computer --format html --file <report.html>`
after rollout on a target machine when administrators need Resultant Set of
Policy evidence for troubleshooting or change review.
Use `dfx windows-policy refresh --target computer --force` after local or GPO
deployment when administrators want an explicit `gpupdate` step before collecting
status or `gpresult` evidence.
Use `dfx windows-policy invoke-refresh --computer <host> --random-delay 0 --force`
from an admin workstation when refresh must be scheduled remotely through the
GroupPolicy PowerShell module.
Use `dfx windows-policy reg --policy-path <xml>` when the deployment channel
expects a reviewed `.reg` artifact rather than direct `reg add` execution.
Use `dfx windows-policy lgpo --policy-path <xml>` when the deployment channel
expects LGPO text that local Group Policy tooling can apply with `LGPO.exe /t`.
Use `dfx windows-policy pol --output Registry.pol --policy-path <xml>` when the
deployment channel expects the machine `Registry.pol` binary artifact directly.
Use `dfx windows-policy script --file <xml>` when the deployment channel expects
a reviewed PowerShell script for copy, registry policy pointer, and optional
`gpupdate` actions.
Use `dfx windows-policy status` after installation to confirm the configured
policy pointer resolves to readable XML and still covers browser/callback
targets.
Use `dfx windows-policy targets --callback-scheme <scheme>` to inspect which
protocol, MIME, and extension identifiers must be present for full coverage.
Use `dfx windows-policy uninstall` when the managed default-app assignment must
be removed; `--delete-file` removes the XML file as a separate explicit action.

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
