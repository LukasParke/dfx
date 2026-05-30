# dfx

`dfx` is a cross-platform CLI for inspecting, validating, and changing default
application associations.

Default-app state is fragmented across MIME types, URL schemes, desktop entries,
macOS bundle identifiers, Windows ProgIDs, browser settings, and enterprise
policy. `dfx` gives those platform-specific pieces one automation-friendly
interface.

## Preview

Partial app names resolve to platform identifiers before any mutation runs:

![dfx quickstart preview](./docs/previews/dfx-quickstart.gif)

Profiles let you validate and dry-run a full default-app plan before applying it:

![dfx automation preview](./docs/previews/dfx-automation.gif)

The preview GIFs are generated with [Charm VHS](https://github.com/charmbracelet/vhs)
from the tapes in [`docs/vhs`](./docs/vhs). CI regenerates them as build
artifacts through [`previews.yml`](./.github/workflows/previews.yml).

## Install

```sh
go install github.com/LukasParke/dfx/cmd/dfx@latest
```

For local development:

```sh
go run ./cmd/dfx inspect
```

## Platform support

| Platform | Read | Write | Notes |
| --- | --- | --- | --- |
| Linux | Yes | Yes | Uses `xdg-mime`; browser defaults also sync through `xdg-settings` when available. |
| macOS | Yes | Dry-run plans | Reads LaunchServices cache state and emits System Settings/`duti`-style remediation guidance. |
| Windows | Yes | Dry-run plans | Reads default-app and policy state; avoids unsafe `UserChoice` registry edits. |

Linux is the active write provider. macOS and Windows intentionally avoid unsafe
native writes until a safe platform workflow is available.

## Quick start

```sh
dfx inspect
dfx get --browser
dfx get --scheme https
dfx set vivaldi --browser --dry-run
dfx doctor --browser --strict
```

`set` accepts either an exact identifier or one positional app query:

```sh
dfx set vivaldi --browser
dfx set --browser --app firefox.desktop
dfx set --mime text/html --app firefox.desktop
dfx set --scheme https://example.com/path --app firefox.desktop
```

Partial app names are resolved where possible:

- Linux: installed `.desktop` entries.
- macOS: application names and known browser aliases/prefixes to bundle IDs.
- Windows: registered default-app metadata to ProgIDs.

If a query is ambiguous, use the exact platform identifier.

## Commands

Inspect platform capability:

```sh
dfx inspect
dfx inspect --verbose
dfx inspect --json
```

Read the current handler:

```sh
dfx get --browser
dfx get --mime text/html
dfx get --scheme https
dfx get --scheme https://example.com/path
```

Diagnose browser defaults:

```sh
dfx doctor --browser
dfx doctor --browser --strict
dfx doctor --browser --fix --dry-run
dfx doctor --browser --json
```

Preflight launch routing without opening an external app by default:

```sh
dfx open-test --scheme myapp --expected com.example.App
DFX_CALLBACK_SCHEME=myapp://oauth/callback dfx open-test --callback --expected com.example.App
dfx open-test --mime text/html --expected firefox.desktop
dfx open-test --mime text/html --path ./sample.html --expected firefox.desktop --launch
```

`open-test --launch` only runs the platform opener after resolution succeeds and
any `--expected` check passes. MIME launches require `--path` to an existing
file. Scheme, browser, and callback launches ignore `--path` and record that in
launch evidence.

## Profiles

Generate and validate a profile:

```sh
dfx profile template --app firefox.desktop > dfx.json
dfx profile template --app firefox.desktop --callback-scheme myapp --callback-app myapp.desktop
dfx profile validate dfx.json
dfx profile validate --json dfx.json
```

Example profile:

```json
{
  "defaults": [
    { "kind": "browser", "app": "firefox.desktop" },
    { "kind": "scheme", "value": "myapp", "app": "myapp.desktop" }
  ]
}
```

Apply it:

```sh
dfx apply --dry-run dfx.json
dfx apply --dry-run --json dfx.json
dfx apply dfx.json
```

`profile validate` and `apply` normalize schemes, reject malformed targets,
reject duplicate or browser-overlapping defaults, and expand `$VAR`, `${VAR}`,
and `%VAR%` in profile paths. `apply` validates the full profile before applying
any entry.

## Windows policy helpers

```sh
dfx windows-policy audit --prog-id ChromeHTML --callback-scheme myapp --json
dfx windows-policy validate --file DefaultAssociations.xml --json
dfx windows-policy template --prog-id ChromeHTML --application-name Chrome --callback-scheme myapp
```

These commands validate or generate enterprise default-association XML without
editing protected `UserChoice` state. Validation covers required browser targets
(`http`, `https`, `text/html`, `application/xhtml+xml`) and optional callback
schemes.

## JSON and exit behavior

`--json` and `-json` work before the command or inside command arguments:

```sh
dfx --json inspect --verbose
dfx inspect --json --verbose
dfx --json set --scheme https --json=false
```

Boolean forms such as `--json=0`, `--json=1`, `-json=0`, and `-json=1` are
accepted. Command-local `--json=false` overrides a root-level JSON flag.

Malformed arguments return exit code `2`. Runtime/provider failures return
non-zero and preserve any available operation plan. JSON errors include an
`error` field plus a `status` object with the intended exit code. Mutation
commands include `changed` and `dry_run` metadata.

## Development

Run the full local verification gate:

```sh
GOCACHE=/tmp/dfx-go-cache go test -timeout=60s ./...
GOCACHE=/tmp/dfx-go-cache go vet ./...
```

Cross-compile package test binaries:

```sh
GOCACHE=/tmp/dfx-go-cache GOOS=darwin go test -c -o /tmp/dfx-cli-darwin.test ./internal/cli
GOCACHE=/tmp/dfx-go-cache GOOS=windows go test -c -o /tmp/dfx-cli-windows.test.exe ./internal/cli
```

Regenerate README previews:

```sh
go install github.com/charmbracelet/vhs@latest
bash scripts/generate-previews.sh
```

VHS rendering requires `ttyd`, `ffmpeg`, and a Chromium-compatible browser on
the host. The CI preview workflow installs `ttyd`, runs the tapes, and uploads
the generated GIFs as artifacts.

## Design principles

- Prefer platform-supported APIs and commands over brittle file edits.
- Make unsupported behavior explicit instead of silently doing partial work.
- Treat URL schemes, MIME handlers, browser defaults, and callback schemes as
  first-class automation targets.
- Make mutation operations inspectable and dry-runnable before changing state.
- Keep the CLI stable while platform adapters grow underneath it.

## Research wiki

- [Default Applications Wiki](./docs/wiki/README.md)
- [Remediation Guide](./docs/wiki/remediation-guide.md)
