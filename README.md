# dfx

`dfx` is a Go CLI for inspecting and enforcing default application behavior across
operating systems.

Default application state is fragmented: MIME types, URL schemes, file
extensions, desktop entries, bundle identifiers, browser handlers, and platform
policy all differ by OS. `dfx` provides one CLI surface over those platform
details so defaults can be made explicit, checked, and repaired.

## Current Scope

This repository is an early implementation scaffold with a working Linux
provider and conservative macOS/Windows provider boundaries.

- Linux: reads and writes MIME and URL scheme handlers through `xdg-mime`, with
  browser defaults also synchronized through `xdg-settings` when applicable.
- macOS: detects `duti` and reports actionable setup errors for default-app
  changes until a full LaunchServices adapter is implemented.
- Windows: reports platform policy limits instead of pretending to support
  unsafe registry hacks.

## Install

```sh
go install github.com/LukasParke/dfx/cmd/dfx@latest
```

For local development:

```sh
go run ./cmd/dfx inspect
```

## Usage

Inspect platform support:

```sh
dfx inspect
dfx inspect --verbose
dfx inspect --json
```

Run diagnostics for browser defaults:

```sh
dfx doctor --browser
dfx doctor --browser --json
dfx doctor --browser --strict
dfx doctor --browser --fix --dry-run
dfx doctor --browser --fix
```

Read a default handler:

```sh
dfx get --browser
dfx get --mime text/html
dfx get --scheme https
```

Set a default handler:

```sh
dfx set --browser --app firefox.desktop
dfx set --mime text/html --app firefox.desktop
dfx set --scheme https --app firefox.desktop
```

Apply a JSON profile:

```json
{
  "defaults": [
    { "kind": "browser", "app": "firefox.desktop" },
    { "kind": "mime", "value": "text/html", "app": "firefox.desktop" },
    { "kind": "scheme", "value": "https", "app": "firefox.desktop" }
  ]
}
```

```sh
dfx apply dfx.json
dfx apply --dry-run dfx.json
```

## Design Principles

- Prefer platform-supported APIs and commands over brittle file edits.
- Make unsupported behavior explicit instead of silently doing partial work.
- Treat URL scheme handlers and MIME handlers as first-class targets.
- Treat browser defaults as a synchronized Linux target across `http`, `https`,
  `text/html`, `application/xhtml+xml`, and `xdg-settings default-web-browser`.
- Make operations inspectable and dry-runnable before changing state.
- Keep the CLI stable while platform adapters grow underneath it.

## Research Wiki

- [Default Applications Wiki](./docs/wiki/README.md)
