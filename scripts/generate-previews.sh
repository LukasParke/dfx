#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

mkdir -p dist docs/previews
go build -o dist/dfx ./cmd/dfx

export PATH="$ROOT/dist:$PATH"
vhs docs/vhs/quickstart.tape
vhs docs/vhs/automation.tape
