#!/usr/bin/env bash
# pre-push.sh — format, build, lint and test minisign-rs before pushing.
#
# jj repository:
#   Default: the tip only (the newest non-empty mutable revision in ::@).
#   Formats it with `jj fix`, then checks the working copy.
#   --full: formats every non-empty mutable revision in ::@ and checks each
#   in its own checkout via `jj run`.
#
# Git repository:
#   Checks HEAD in the working tree. Tracked changes under rs/ must be
#   committed first. If rustfmt reports changes, the script formats the tree
#   and fails so the result can be committed.
#
#   Install as a git hook (one-time setup):
#     ln -sf ../../rs/scripts/pre-push.sh .git/hooks/pre-push
#   Git passes the remote name and URL as arguments; the script ignores them.

set -euo pipefail

# Resolve the real script path: as a git hook, "$0" is the .git/hooks symlink.
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

readonly CRATE_DIR_NAME="rs"
readonly TEST_TIMEOUT_SECONDS=120
readonly STACK='mutable() & ::@ ~ empty()'
readonly TIP="heads(${STACK})"

# Run from the crate root. Mirrors .claude/rules/run-tests.md and CI.
readonly CHECKS="cargo fmt --check \
&& cargo build --all-targets \
&& cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic \
&& cargo clippy --lib --bins --all-features -- -F unsafe_code \
&& gtimeout ${TEST_TIMEOUT_SECONDS} cargo nextest run --no-default-features"

# Inline so formatting does not depend on unversioned .jj/repo/config.toml.
# rustfmt on stdin ignores Cargo.toml, so the edition is passed explicitly.
readonly RUSTFMT_CONFIG=(
    --config 'fix.tools.rustfmt.command=["rustfmt", "--emit", "stdout", "--edition", "2024"]'
    --config "fix.tools.rustfmt.patterns=[\"glob:'${CRATE_DIR_NAME}/**/*.rs'\"]"
    --config 'fix.tools.rustfmt.enabled=true'
)

usage() {
    echo "Usage: $0 [--full|-f]"
    echo "  --full, -f  jj only: format and check every mutable revision, not only the tip."
}

full=false
for arg in "$@"; do
    case "${arg}" in
        --full | -f) full=true ;;
        -h | --help) usage; exit 0 ;;
        -*) echo "Error: unknown argument '${arg}'" >&2; usage >&2; exit 1 ;;
        *) ;; # git hook arguments: remote name and URL
    esac
done

run_jj() {
    local root="$1"
    cd "${root}"

    local stack
    stack="$(jj log --no-graph -r "${STACK}" -T 'change_id ++ "\n"')"
    if [[ -z "${stack}" ]]; then
        echo "==> No non-empty mutable revisions in ${STACK}, nothing to check."
        exit 0
    fi

    if [[ "${full}" == true ]]; then
        echo "==> Formatting ${STACK}"
        jj "${RUSTFMT_CONFIG[@]}" fix -s "roots(${STACK})"
        echo "==> Checking each revision in ${STACK}"
        jj run --root --ignore-changes -r "${STACK}" -- bash -c "cd ${CRATE_DIR_NAME} && ${CHECKS}"
    else
        # Checks run in the working copy; when @ is empty its tree is the tip's.
        echo "==> Formatting tip ${TIP}"
        jj "${RUSTFMT_CONFIG[@]}" fix -s "${TIP}"
        echo "==> Checking jj tip $(jj log --no-graph -r "${TIP}" -T 'change_id.short() ++ " " ++ coalesce(description.first_line(), "(no description)")')"
        cd "${CRATE_DIR_NAME}"
        bash -c "${CHECKS}"
    fi
}

run_git() {
    local root="$1"
    cd "${root}"

    if [[ "${full}" == true ]]; then
        echo "Error: --full needs jj." >&2
        exit 1
    fi

    if ! git diff --quiet HEAD -- "${CRATE_DIR_NAME}"; then
        echo "Error: uncommitted changes under ${CRATE_DIR_NAME}/. Commit or stash them; the checks must see HEAD." >&2
        exit 1
    fi

    echo "==> Checking git HEAD $(git log -1 --format='%h %s')"
    cd "${CRATE_DIR_NAME}"
    if ! cargo fmt --check > /dev/null; then
        cargo fmt
        echo "Error: rustfmt changed files under ${CRATE_DIR_NAME}/. Commit the formatting and push again." >&2
        exit 1
    fi
    bash -c "${CHECKS}"
}

# Detect the repository from the script location, not the caller's directory.
cd "$(dirname "$(resolve_script_path "$0")")"

if root="$(jj --ignore-working-copy root 2> /dev/null)"; then
    run_jj "${root}"
elif root="$(git rev-parse --show-toplevel 2> /dev/null)"; then
    run_git "${root}"
else
    echo "Error: not inside a jj or git repository." >&2
    exit 1
fi

echo "==> All checks passed."
