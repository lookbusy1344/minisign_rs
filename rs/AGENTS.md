# Minisign Rust Project

Pure Rust rewrite of minisign (cryptographic signing tool). Security-critical. Must be 100% compatible with C version.

## Version control (read first)

Before the first VCS command, run `jj --ignore-working-copy root`. This may be a jj repo on one machine and plain Git on another.

**IMPORTANT:** if it succeeds, use `jj` for all VCS commands, including `log`, `show`, `status` and `diff`. Do not run `git` on jj repos. The `gitStatus` snapshot in the session context is not a reason to use git.

jj has no commit hooks. Run the pre-commit checks before `jj commit`, `jj describe` (when finalising a change) and `jj squash`.
If a change touches only non-code files (`*.md`), skip the cargo steps.

Before pushing or moving a shared bookmark, run `rs/scripts/pre-push.sh` (paths are relative to the repository root). It checks the tip only:

- jj: the tip is the newest non-empty mutable revision. The script formats it with `jj fix`, then runs fmt check, build, pedantic clippy, the `unsafe_code` clippy pass and nextest.
- Git: the tip is HEAD. The script refuses uncommitted changes under `rs/`, runs `cargo fmt` and fails if that changed files, then runs the same checks. Install it as a hook with `ln -sf ../../rs/scripts/pre-push.sh .git/hooks/pre-push`. jj does not run Git hooks.

`rs/scripts/agent-pre-push-hook.sh` runs the script before every `jj git push` and `git push`, and blocks the push on failure. Claude Code (`.claude/settings.json`) and Codex (`.codex/hooks.json`) call it as a `PreToolUse` hook. It checks the tip, not the ref being pushed, so push only the branch you are working on. In jj, that is the bookmark on `@-`, with an empty `@` above it.

CI runs build, clippy and tests on every push to `master` and `lb_rust`.

Push only on explicit request. "Push this" means: if `@` is non-empty, `jj commit` it (after the pre-commit checks). Move the bookmark to `@-` with `jj bookmark set <name> -r @-`, then `jj git push --bookmark <name>`. Use the feature bookmark already on the stack; otherwise `lb_rust`. Do not use `jj git push -c`.

## Workflow
- **Main branch**: `lb_rust` (not master)
- Create feature branches from `lb_rust`

## Privacy & Security
- No PII in commits — use placeholders (`your@email.com`, `YOUR_TEAM_ID`, etc.)
- Test files use synthetic/mock data only

## Non-Negotiable Rules
- **ZERO unsafe code** — `#![forbid(unsafe_code)]` in lib and main. Prefer std safe equivalents over syscalls. Test-only exception: `unsafe { env::set_var(...) }` with `#[serial]` and `// SAFETY:` comment.
- **Minimize dependencies** — check std and existing deps before adding a crate
- **ZERO clippy warnings** (pedantic mode)
- Run clippy with `--all-targets` so platform-specific test and bin code is checked too:
  - `gtimeout 300 cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic`
- Run the test suite with `./run_all_tests.sh`
- **TDD** — write tests before code
- All secrets use `Zeroize` + `ZeroizeOnDrop`
- No `.unwrap()`/`.expect()` in production paths; use `?`
- Inline format strings: `format!("{name}")` not `format!("{}", name)`

## Performance & Memory
- Prefer references (`&Path`, `&str`, `&[T]`) over owned types
- Use `as_ref()`/`as_deref()` on `Option<T>`; `Cow<T>` for conditional ownership
- Avoid cloning unless required (threading, owned returns, API constraints)

## API Design
- Private fields for security-sensitive types and types with invariants
- Getters return references, use `#[must_use]`, no `get_` prefix
- Builder pattern for structs with 3+ params or multiple booleans
