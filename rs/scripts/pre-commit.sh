#!/usr/bin/env bash
# pre-commit.sh — run all required checks before committing.
#
# Install (one-time setup):
#   ln -sf ../../rs/scripts/pre-commit.sh .git/hooks/pre-commit
#
# The git root for this project is minisign/, one level above rs/.
# The hook therefore fires on every commit to the minisign repo, so we check
# whether any staged files are under rs/ and bail early if not.
#
# Staged paths are relative to the repo root (minisign/), so the grep anchors
# on '^rs/' to match only files within this project.
#
# Can also be run directly: ./scripts/pre-commit.sh

set -euo pipefail

# Resolve the real script path before computing directories — dirname "$0" follows
# the symlink path (.git/hooks/) when invoked as a hook, not the script's location.
REAL_SCRIPT="$(readlink -f "$0")"
SCRIPT_DIR="$(cd "$(dirname "${REAL_SCRIPT}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${PROJECT_DIR}"

# Wrapper that prints each command before running it.
run() {
    echo "==> $*"
    "$@"
}

# Only trigger if Rust source or Cargo config files are staged under rs/.
# Paths are relative to the repo root (minisign/), so we anchor on '^rs/'.
STAGED=$(git -C "${PROJECT_DIR}" diff --cached --name-only)
if ! echo "${STAGED}" | grep -qE '^rs/.*\.(rs|toml)$'; then
    echo "==> No rs/ Rust/TOML files staged, skipping."
    exit 0
fi

echo "==> Running minisign-rs pre-commit checks..."

# Clippy — pedantic for all targets, then unsafe_code for lib/bins.
run gtimeout 60 cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic
run gtimeout 30 cargo clippy --lib --bins --all-features -- -F unsafe_code

# Check formatting without modifying files — fails if rustfmt would make changes.
run cargo fmt --check

# Full test suite (cross-binary and credential-store tests excluded by default).
run gtimeout 120 cargo nextest run --no-default-features

echo "==> All checks passed."
