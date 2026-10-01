# Minisign Repository

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
