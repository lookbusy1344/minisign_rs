# Minisign Repository

## Version control (read first)

Before the first VCS command, run `jj --ignore-working-copy root`. This may be a jj repo on one machine and plain Git on another.

**IMPORTANT:** if it succeeds, use `jj` for all VCS commands, including `log`, `show`, `status` and `diff`. Do not run `git` on jj repos. The `gitStatus` snapshot in the session context is not a reason to use git.

jj has no commit hooks. Run the pre-commit checks before `jj commit`, `jj describe` (when finalising a change) and `jj squash`.
If a change touches only non-code files (`*.md`), skip the cargo steps.

Before pushing or moving a shared bookmark, run `rs/scripts/pre-push.sh`. By default it checks the tip only. In a jj repo the tip is the newest non-empty mutable revision; the script formats it with `jj fix`, then runs fmt check, build, pedantic clippy, the `unsafe_code` clippy pass and nextest. In a plain Git repo the tip is HEAD; the script refuses uncommitted changes under `rs/`, runs `cargo fmt` and fails if it changed files, then runs the same checks. Install it as a Git hook with `ln -sf ../../rs/scripts/pre-push.sh .git/hooks/pre-push`; jj does not run Git hooks. `rs/scripts/agent-pre-push-hook.sh` runs the tip check on every push command (`jj git push`, `jj pmain`, `git push`) and blocks the push on failure. Claude Code (`.claude/settings.json`) and Codex (`.codex/hooks.json`) call it as a `PreToolUse` hook. The hook checks the tip of `@` (HEAD in Git), not the ref being pushed. Push only the bookmark or branch you are working on, with `@` on top of it. CI runs build, clippy and tests on every push to `master` and `lb_rust`.

Push only on explicit request. "Push this" means: if `@` is non-empty, `jj commit` it (after the pre-commit checks). Move the bookmark to `@-` with `jj bookmark set <name> -r @-`, then `jj git push --bookmark <name>`. Use the feature bookmark already on the stack; otherwise `lb_rust`. Do not use `jj git push -c`.

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
