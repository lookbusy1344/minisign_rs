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
# Can also be run from existing hook:
# if [ ! -x "rs/scripts/pre-commit.sh" ]; then
#     echo "Missing executable rs/scripts/pre-commit.sh" >&2
#     exit 1
# fi
#
# exec ./rs/scripts/pre-commit.sh

set -euo pipefail

# Resolve the real script path before computing directories — dirname "$0" follows
# the symlink path (.git/hooks/) when invoked as a hook, not the script's location.
resolve_script_path() {
    local source_path="$1"

    while [[ -L "${source_path}" ]]; do
        local source_dir
        source_dir="$(cd -P "$(dirname "${source_path}")" && pwd)"
        source_path="$(readlink "${source_path}")"

        if [[ "${source_path}" != /* ]]; then
            source_path="${source_dir}/${source_path}"
        fi
    done

    local resolved_dir
    resolved_dir="$(cd -P "$(dirname "${source_path}")" && pwd)"
    printf '%s/%s\n' "${resolved_dir}" "$(basename "${source_path}")"
}

readonly CLIPPY_PEDANTIC_TIMEOUT_SECONDS=60
readonly CLIPPY_UNSAFE_TIMEOUT_SECONDS=30
readonly FULL_TEST_SUITE_TIMEOUT_SECONDS=300

REAL_SCRIPT="$(resolve_script_path "$0")"
SCRIPT_DIR="$(cd "$(dirname "${REAL_SCRIPT}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${PROJECT_DIR}"

# Wrapper that prints each command before running it.
run() {
    echo "==> $*"
    "$@"
}

# Only trigger if Rust source, TOML, or Cargo.lock files are modified under
# rs/ — staged OR unstaged. `git diff HEAD` catches both, so a dirty working
# tree can't slip past the hook just because the user staged unrelated changes.
# Paths are relative to the repo root (minisign/), anchored on '^rs/'.
if ! git -C "${PROJECT_DIR}" diff HEAD --name-only -z | tr '\0' '\n' | grep -qE \
    '^rs/(Cargo\.lock|.*\.(rs|toml))$'; then
    echo "==> No rs/ Rust, TOML, or Cargo.lock files modified, skipping."
    exit 0
fi

echo "==> Running minisign-rs pre-commit checks..."

# Clippy — pedantic for all targets, then unsafe_code for lib/bins.
run gtimeout "${CLIPPY_PEDANTIC_TIMEOUT_SECONDS}" cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic
run gtimeout "${CLIPPY_UNSAFE_TIMEOUT_SECONDS}" cargo clippy --lib --bins --all-features -- -F unsafe_code

# Check formatting without modifying files — fails if rustfmt would make changes.
run cargo fmt --check

# Full default test suite, using the project wrapper for consistency.
run gtimeout "${FULL_TEST_SUITE_TIMEOUT_SECONDS}" ./run_all_tests.sh

echo "==> All checks passed."
