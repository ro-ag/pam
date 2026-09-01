#!/usr/bin/env bash
# tools/check.sh — the single local quality gate.
#
# Run this before every PR: it is the whole gate, in the order that fails
# fastest. CI does not duplicate it (Actions cost money; quality gates run
# locally before merge — see CLAUDE.md "Working agreements").
#
#   1. cargo fmt --check          formatting, no writes
#   2. cargo clippy -D warnings   pedantic lints across every target
#   3. cargo test --workspace     Rust unit + integration tests
#   4. npm run lint               ESLint (incl. the arbitrary-value ban)
#   5. npm run build              tsc --noEmit + vite production build
#   6. npm run test               vitest (screens, ipc, design contract)
#
# Coverage stays out of the gate: `npm --prefix frontend run test:coverage`
# is report-only until the views stabilize enough to pin thresholds.

set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> cargo fmt --check"
cargo fmt --all --check

echo "==> cargo clippy (all targets, -D warnings)"
cargo clippy --workspace --all-targets -- -D warnings

echo "==> cargo test --workspace"
cargo test --workspace

echo "==> frontend lint"
npm --prefix frontend run lint

echo "==> frontend build (tsc + vite)"
npm --prefix frontend run build

echo "==> frontend test"
npm --prefix frontend run test

echo "All gates green."
