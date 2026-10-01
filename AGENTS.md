# Minisign Repository

## Version control (read first)

Before the first VCS command, run `jj --ignore-working-copy root`. This may be a jj repo on one machine and plain Git on another.

**IMPORTANT:** if it succeeds, use `jj` for all VCS commands, including `log`, `show`, `status` and `diff`. Do not run `git` on jj repos. The `gitStatus` snapshot in the session context is not a reason to use git.

jj has no commit hooks. Run the pre-commit checks before `jj commit`, `jj describe` (when finalising a change) and `jj squash`.
If a change touches only non-code files (`*.md`), skip the cargo steps.

Before `jj git push` or moving a shared bookmark, run `scripts/pre-push.sh`. By default it formats the tip (newest non-empty mutable revision) with `jj fix`, then runs fmt check, build, clippy and nextest on it. `--full` formats every mutable revision in `::@` and checks each in its own checkout via `jj run`. `scripts/agent-pre-push-hook.sh` runs the tip check on every push command and blocks the push on failure. Claude Code (`.claude/settings.json`) and Codex (`.codex/hooks.json`) call it as a `PreToolUse` hook. The hook checks the tip of `@`, not the bookmark being pushed: `@` must sit on top of the revisions being pushed. CI runs fmt, clippy, build and tests on every pushed bookmark.

Push only on explicit request. "Push this" means: if `@` is non-empty, `jj commit` it (after the pre-commit checks). Move the bookmark to `@-` with `jj bookmark set <name> -r @-`, then `jj git push --bookmark <name>`. Use the feature bookmark already on the stack; otherwise `main`. Do not use `jj git push -c`.

## Personal information

Exclude PII from every commit, commit message and bookmark name: real names, email addresses, usernames, machine paths such as `/Users/<name>/`, hostnames, tokens and credentials. Check the diff before `jj commit`, `jj describe` (finalising) and `git commit`.

## Project Structure

This repository contains multiple implementations of minisign:

| Path | Language | Status |
|------|----------|--------|
| `rs/` | Rust | **Active — all development happens here** |
| `src/` | C | Read-only reference implementation |
| `build.zig` / `build.zig.zon` | Zig | Read-only reference implementation |

## Working Boundary

**Only modify files under `rs/`.**

`src/`, `build.zig`, `build.zig.zon`, `CMakeLists.txt`, and `share/` are the upstream C/Zig reference implementations. Treat them as read-only. They exist to verify compatibility and understand the canonical behaviour — not to be edited.
