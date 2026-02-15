# Documentation Trimming and Reorganization Design

**Date:** 2026-02-15
**Status:** Approved
**Goal:** Trim rs/README.md and rs/CLAUDE.md to remove redundancies and improve focus while maintaining all information in better-organized locations.

## Problem Statement

The current documentation has three issues:

1. **README.md is overwhelming** (869 lines) - Users face too much information when trying to get started
2. **CLAUDE.md has redundancies** (171 lines) - Duplicates information from README and includes details that don't need to be in developer quick reference
3. **Both files lack focus** - Each tries to serve multiple audiences (end users, developers, AI assistants) in a single file

## Solution: Aggressive Split & Trim

Move detailed content to purpose-specific documentation files while keeping README and CLAUDE.md focused and scannable.

## Design

### README.md Trimming Strategy

**Target:** ~350 lines (down from 869)

**What STAYS in README.md:**
- Project badges and overview
- Project status and current version
- Key features list (condensed)
- Installation section (pre-built binaries + basic build commands)
- Quick start examples (generate key, sign, verify - essentials only)
- Basic CLI options table (condensed to most common flags)
- Configuration (MINISIGN_CONFIG_DIR)
- Links to detailed documentation
- License and contributing info

**What MOVES out of README.md:**

→ **To `docs/USAGE.md`:**
- All detailed usage examples
- Multi-file signing and verification workflows
- Password management and credential store guide (complete workflows)
- Complete CLI options reference
- Signature file format details
- Signing modes deep-dive (prehashed vs legacy)
- All extensive command examples

→ **To `docs/ARCHITECTURE.md`:**
- Module structure diagram
- Design principles
- Code organization details
- Internal architecture explanations
- Type system and abstractions

→ **To `docs/TESTING.md`:**
- Detailed test coverage statistics
- Test categories and requirements
- Running different test suites
- C minisign compatibility testing
- Development testing workflows
- Credential store testing specifics

→ **To `docs/DEVELOPMENT.md`:**
- Development guidelines
- Before committing checklist (detailed)
- Adding new features
- Security requirements for contributors
- Dependencies details (crypto and other)
- Dependency management procedures
- CI/CD pipeline information

### CLAUDE.md Trimming Strategy

**Target:** ~90 lines (down from 171)

**What STAYS in CLAUDE.md:**
- Project one-liner (what this is)
- Git workflow (main branch: lb_rust)
- Non-negotiable rules (zero unsafe, zero clippy warnings, TDD required, zeroize secrets, no unwrap/expect)
- Performance principles (avoid cloning, prefer references, builder pattern guidance)
- Pre-commit checklist (the exact commands to run)
- Security auditing reminder (cargo audit)
- Privacy/PII rules (critical for this project)

**What REMOVES from CLAUDE.md:**
- API Design & Encapsulation section (general Rust practices, not project-specific)
- Refactoring Tools section (not essential)
- Key Locations file structure (code is self-documenting)
- Detailed testing sections (moves to docs/TESTING.md)
- Crypto Dependencies list (in Cargo.toml)
- Other Key Dependencies list (in Cargo.toml)
- Dependency Management section (moves to docs/DEVELOPMENT.md)
- Documentation references list (redundant)

**Result:** CLAUDE.md becomes a tight, scannable quick-reference card.

### New Documentation Structure

**New files to create:**

#### `docs/USAGE.md` (~300-400 lines)
Complete user guide for all features:
- Complete CLI options reference table
- Detailed usage examples for all operations
- Multi-file signing and verification workflows
- Password management and credential store guide
- Signature file format specification
- Signing modes (prehashed vs legacy) deep-dive
- Configuration options
- Troubleshooting common issues

#### `docs/ARCHITECTURE.md` (~150-200 lines)
Internal design and structure:
- Module structure and organization
- Design principles (Pure Rust, security-first, test-driven)
- Key type system and abstractions
- Error handling strategy
- How components interact
- Extension points for future work

#### `docs/TESTING.md` (~200-250 lines)
Complete testing guide:
- Test coverage statistics
- Test categories (fast/slow/credential store)
- Running tests (all different commands)
- Test requirements (C minisign, etc.)
- Credential store testing specifics
- C compatibility testing
- Adding new tests
- Test organization philosophy

#### `docs/DEVELOPMENT.md` (~200-250 lines)
Developer workflow guide:
- Development workflow
- Before committing (detailed checklist with explanations)
- Adding new features
- Security requirements for contributors
- Dependencies (crypto and other)
- Dependency management procedures
- CI/CD pipeline details
- Code review expectations

**Existing docs that stay unchanged:**
- `COMPATIBILITY.md`
- `docs/benchmark-report.md`
- `docs/c-rust-parity-gaps.md`
- All other existing docs

## Implementation Approach

**Order of operations:**

1. **Create new doc files first**
   - Extract content from README.md and CLAUDE.md
   - Organize and polish content during migration
   - Add cross-references between docs
   - Ensure each file has clear purpose statement at top

2. **Trim README.md**
   - Remove sections that moved to new docs
   - Add "See docs/X.md for details" links
   - Condense remaining sections for clarity
   - Ensure it flows as cohesive getting-started guide

3. **Trim CLAUDE.md**
   - Remove redundant sections
   - Tighten remaining sections
   - Ensure it reads as quick reference card

4. **Update cross-references**
   - README links to detailed docs
   - CLAUDE.md references docs/DEVELOPMENT.md
   - Each doc file has clear navigation

## Quality Criteria

- README can be read top-to-bottom in ~5 minutes
- CLAUDE.md can be scanned in ~2 minutes
- No information is lost (everything moves, nothing deleted)
- Each doc file has single clear purpose
- Navigation between docs is clear
- First-time users can get started from README alone
- Developers can find deep details quickly

## Expected Outcomes

**File sizes:**
- README.md: 869 → ~350 lines
- CLAUDE.md: 171 → ~90 lines
- New docs: ~850-1100 lines total (4 files)

**Benefits:**
- README becomes effective onboarding document
- CLAUDE.md becomes memorable quick reference
- Detailed information lives in appropriate locations
- Each audience (users, developers, AI) has targeted docs
- Easier to maintain (changes go to right place)

## Success Metrics

- User can install and run first sign/verify in <10 minutes using only README
- Developer can understand workflow rules from CLAUDE.md in <3 minutes
- All original information remains accessible
- Documentation feels organized, not scattered
