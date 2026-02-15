# Documentation Trimming Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Reorganize rs/README.md and rs/CLAUDE.md to improve focus and readability by moving detailed content to purpose-specific documentation files.

**Architecture:** Create four new documentation files (USAGE.md, ARCHITECTURE.md, TESTING.md, DEVELOPMENT.md) to hold detailed content currently in README and CLAUDE.md. Trim both files to essential information with links to detailed docs.

**Tech Stack:** Markdown documentation, git

---

## Task 1: Create docs/USAGE.md

**Files:**
- Create: `rs/docs/USAGE.md`
- Read from: `rs/README.md` (lines 104-444)

**Step 1: Extract usage content from README**

Create `rs/docs/USAGE.md` with:
- Header and purpose statement
- Complete CLI options reference (from README lines 112-162)
- All detailed usage examples (from README lines 163-444)
- Multi-file signing/verification sections
- Password management with credential store
- Signature file format
- Signing modes (prehashed vs legacy)

**Step 2: Verify content completeness**

Check that all usage details from README are captured:
- Command-line options table
- Generate keypair examples
- Sign file examples
- Multi-file signing examples
- Verify signature examples
- Multi-file verification examples
- Recreate public key examples
- Change password examples
- Inspect key security examples
- Password management sections
- Signature file format
- Signing modes explanation

**Step 3: Add navigation header**

Add at top of file:
```markdown
# Minisign-rs Usage Guide

Complete reference for all minisign-rs operations and command-line options.

**See also:**
- [README.md](../README.md) - Quick start and installation
- [ARCHITECTURE.md](ARCHITECTURE.md) - Internal design
- [TESTING.md](TESTING.md) - Testing guide
- [DEVELOPMENT.md](DEVELOPMENT.md) - Development workflow

---
```

**Step 4: Commit**

```bash
git add rs/docs/USAGE.md
git commit -m "docs: create USAGE.md with detailed usage examples

Extract all detailed usage content from README including:
- Complete CLI options reference
- Detailed examples for all operations
- Multi-file workflows
- Password management guide
- Signature format and signing modes
"
```

---

## Task 2: Create docs/ARCHITECTURE.md

**Files:**
- Create: `rs/docs/ARCHITECTURE.md`
- Read from: `rs/README.md` (lines 578-612)

**Step 1: Extract architecture content from README**

Create `rs/docs/ARCHITECTURE.md` with:
- Header and purpose statement
- Module structure section (from README lines 582-603)
- Design principles section (from README lines 605-612)
- Dependencies information (from README lines 613-644)

**Step 2: Add internal design details**

Add sections on:
- Type system and key abstractions
- Error handling patterns
- Security model (zeroization, constant-time ops)
- How components interact

**Step 3: Add navigation header**

Add at top:
```markdown
# Minisign-rs Architecture

Internal design and code organization for minisign-rs.

**See also:**
- [README.md](../README.md) - Project overview
- [USAGE.md](USAGE.md) - Usage guide
- [TESTING.md](TESTING.md) - Testing guide
- [DEVELOPMENT.md](DEVELOPMENT.md) - Development workflow

---
```

**Step 4: Commit**

```bash
git add rs/docs/ARCHITECTURE.md
git commit -m "docs: create ARCHITECTURE.md with internal design details

Extract architecture content from README including:
- Module structure and organization
- Design principles
- Dependencies
- Type system and abstractions
"
```

---

## Task 3: Create docs/TESTING.md

**Files:**
- Create: `rs/docs/TESTING.md`
- Read from: `rs/README.md` (lines 533-577)
- Read from: `rs/CLAUDE.md` (lines 98-143)

**Step 1: Extract testing content from README and CLAUDE.md**

Create `rs/docs/TESTING.md` with:
- Header and purpose statement
- Test coverage statistics (from README lines 33-46)
- Test requirements (from README lines 535-544)
- Running tests without keychain popups (from README lines 546-563)
- Testing credential store (from README lines 565-577)
- Credential store feature details (from CLAUDE.md lines 100-111)
- Test categories (from CLAUDE.md lines 112-128)
- Test runner script (from CLAUDE.md lines 129-136)
- Test requirements (from CLAUDE.md lines 137-143)

**Step 2: Organize into clear sections**

Structure as:
1. Overview and test statistics
2. Test categories (fast, slow, credential store)
3. Running tests (all variations)
4. Test requirements
5. C minisign compatibility testing
6. Adding new tests
7. Test organization philosophy

**Step 3: Add navigation header**

Add at top:
```markdown
# Minisign-rs Testing Guide

Complete guide to running and writing tests for minisign-rs.

**See also:**
- [README.md](../README.md) - Quick start
- [USAGE.md](USAGE.md) - Usage guide
- [ARCHITECTURE.md](ARCHITECTURE.md) - Internal design
- [DEVELOPMENT.md](DEVELOPMENT.md) - Development workflow

---
```

**Step 4: Commit**

```bash
git add rs/docs/TESTING.md
git commit -m "docs: create TESTING.md with comprehensive testing guide

Extract testing content from README and CLAUDE.md including:
- Test coverage statistics
- Test categories and requirements
- Running different test suites
- Credential store testing
- C minisign compatibility testing
"
```

---

## Task 4: Create docs/DEVELOPMENT.md

**Files:**
- Create: `rs/docs/DEVELOPMENT.md`
- Read from: `rs/README.md` (lines 772-808, 810-835)
- Read from: `rs/CLAUDE.md` (lines 56-73, 158-165)

**Step 1: Extract development content from README and CLAUDE.md**

Create `rs/docs/DEVELOPMENT.md` with:
- Header and purpose statement
- Development guidelines (from README lines 772-808)
- Pre-commit checklist (from CLAUDE.md lines 56-64)
- Security auditing (from CLAUDE.md lines 66-73)
- Dependency management (from CLAUDE.md lines 158-165)
- CI/CD information (from README lines 810-835)

**Step 2: Expand with developer workflow details**

Add sections on:
- Setting up development environment
- Running clippy and fmt
- Before committing detailed workflow
- Adding new features process
- Security requirements for code
- Code review expectations

**Step 3: Add navigation header**

Add at top:
```markdown
# Minisign-rs Development Guide

Developer workflow and guidelines for contributing to minisign-rs.

**See also:**
- [README.md](../README.md) - Project overview
- [USAGE.md](USAGE.md) - Usage guide
- [ARCHITECTURE.md](ARCHITECTURE.md) - Internal design
- [TESTING.md](TESTING.md) - Testing guide

---
```

**Step 4: Commit**

```bash
git add rs/docs/DEVELOPMENT.md
git commit -m "docs: create DEVELOPMENT.md with developer workflow

Extract development content from README and CLAUDE.md including:
- Development guidelines
- Pre-commit checklist
- Security auditing
- Dependency management
- CI/CD pipeline details
"
```

---

## Task 5: Trim README.md

**Files:**
- Modify: `rs/README.md`

**Step 1: Remove detailed usage sections**

Remove lines 104-444 (detailed usage examples) and replace with:
```markdown
## Usage

For complete usage documentation including all CLI options, detailed examples, and workflows, see [docs/USAGE.md](docs/USAGE.md).

### Quick Start

#### Generate a keypair
```bash
minisign_rs -G
```

#### Sign a file
```bash
minisign_rs -S -m file.txt
```

#### Verify a signature
```bash
minisign_rs -V -m file.txt -p minisign.pub
```
```

**Step 2: Remove architecture sections**

Remove lines 578-644 (architecture, dependencies) and replace with:
```markdown
## Architecture

For internal design details, module structure, and dependencies, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
```

**Step 3: Condense test coverage section**

Replace lines 33-46 with:
```markdown
### Test Coverage

- **478 total tests** (467 fast + 11 slow) covering all operations
- Comprehensive unit and integration tests
- C minisign compatibility tests
- Property-based fuzzing tests

See [docs/TESTING.md](docs/TESTING.md) for complete testing guide.
```

**Step 4: Update installation section**

Keep installation section but condense build instructions to basics:
```markdown
### Building from Source

```bash
# Build the project
cargo build --release

# Run tests
cargo test --no-default-features
```

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for development workflow.
```

**Step 5: Remove development guidelines section**

Remove lines 772-808 and replace with link to DEVELOPMENT.md

**Step 6: Remove CI/CD section**

Remove lines 810-835 and move reference to DEVELOPMENT.md

**Step 7: Verify README flows**

Read through entire README to ensure:
- Clear getting-started path
- All sections flow logically
- Links to detailed docs are clear
- Can be read in ~5 minutes

**Step 8: Commit**

```bash
git add rs/README.md
git commit -m "docs(readme): trim to essential getting-started content

Move detailed content to purpose-specific docs:
- Usage details → docs/USAGE.md
- Architecture → docs/ARCHITECTURE.md
- Testing details → docs/TESTING.md
- Development workflow → docs/DEVELOPMENT.md

README now focuses on: overview, quick installation, basic usage, links
Size: 869 → ~350 lines
"
```

---

## Task 6: Trim CLAUDE.md

**Files:**
- Modify: `rs/CLAUDE.md`

**Step 1: Remove API design section**

Remove lines 43-54 (API Design & Encapsulation - general Rust practices)

**Step 2: Remove refactoring tools section**

Remove lines 75-80 (Refactoring Tools - not essential)

**Step 3: Remove key locations section**

Remove lines 82-96 (Key Locations - code is self-documenting)

**Step 4: Remove detailed testing sections**

Remove lines 98-143 and replace with:
```markdown
## Testing

**Run before committing:**
```bash
cargo test --no-default-features           # Fast tests
cargo test --no-default-features -- --ignored  # Slow tests
```

See [docs/TESTING.md](docs/TESTING.md) for complete testing guide.
```

**Step 5: Remove dependency lists**

Remove lines 144-156 (dependency lists - in Cargo.toml)

**Step 6: Remove dependency management section**

Remove lines 158-165 and add reference:
```markdown
## Dependencies

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for dependency management.
```

**Step 7: Remove documentation references**

Remove lines 166-171 (redundant list)

**Step 8: Verify CLAUDE.md is scannable**

Ensure file:
- Fits on ~2 screens
- Quick reference format
- Essential rules only
- Can be scanned in ~2 minutes

**Step 9: Commit**

```bash
git add rs/CLAUDE.md
git commit -m "docs(claude): trim to essential quick reference

Remove redundant and non-essential content:
- API design guidelines (general Rust practices)
- Refactoring tools (not essential)
- Key locations (code is self-documenting)
- Detailed testing sections (moved to docs/TESTING.md)
- Dependency lists (in Cargo.toml)
- Documentation references (redundant)

CLAUDE.md now focuses on: non-negotiables, pre-commit checklist, workflow
Size: 171 → ~90 lines
"
```

---

## Task 7: Update cross-references

**Files:**
- Modify: `rs/README.md`
- Modify: `rs/CLAUDE.md`
- Modify: `rs/docs/USAGE.md`
- Modify: `rs/docs/ARCHITECTURE.md`
- Modify: `rs/docs/TESTING.md`
- Modify: `rs/docs/DEVELOPMENT.md`

**Step 1: Add "See also" sections to each doc**

Ensure each file has clear navigation to other docs at the top.

**Step 2: Add detailed doc references in README**

In README, add a "Documentation" section:
```markdown
## Documentation

- [docs/USAGE.md](docs/USAGE.md) - Complete usage guide and CLI reference
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - Internal design and structure
- [docs/TESTING.md](docs/TESTING.md) - Testing guide
- [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) - Development workflow
- [COMPATIBILITY.md](COMPATIBILITY.md) - C/Rust compatibility proof
- [docs/benchmark-report.md](docs/benchmark-report.md) - Performance comparison
```

**Step 3: Verify all links work**

Check that all cross-references point to correct files.

**Step 4: Commit**

```bash
git add rs/README.md rs/CLAUDE.md rs/docs/*.md
git commit -m "docs: add cross-references between documentation files

Add navigation links between all docs for easy discovery.
Each file now has clear 'See also' section pointing to related docs.
"
```

---

## Task 8: Final verification

**Step 1: Read README top to bottom**

Verify:
- Can be read in ~5 minutes
- Clear getting-started path
- Links to detailed docs are obvious
- No broken sections or flow issues

**Step 2: Read CLAUDE.md top to bottom**

Verify:
- Can be scanned in ~2 minutes
- Essential rules are clear
- Pre-commit checklist is complete
- References to detailed docs are clear

**Step 3: Spot-check new docs**

Verify each new doc:
- Has clear purpose statement
- Content is well-organized
- Navigation links work
- Information from old docs is preserved

**Step 4: Check file sizes**

Verify target sizes achieved:
```bash
wc -l rs/README.md rs/CLAUDE.md rs/docs/USAGE.md rs/docs/ARCHITECTURE.md rs/docs/TESTING.md rs/docs/DEVELOPMENT.md
```

Expected:
- README.md: ~350 lines (was 869)
- CLAUDE.md: ~90 lines (was 171)
- USAGE.md: ~300-400 lines
- ARCHITECTURE.md: ~150-200 lines
- TESTING.md: ~200-250 lines
- DEVELOPMENT.md: ~200-250 lines

**Step 5: Final commit if any adjustments needed**

If minor adjustments were made during verification:
```bash
git add -A
git commit -m "docs: final adjustments after verification"
```

---

## Success Criteria

✅ README.md is ~350 lines (down from 869)
✅ CLAUDE.md is ~90 lines (down from 171)
✅ Four new doc files created and well-organized
✅ No information lost (everything moved, nothing deleted)
✅ All cross-references work
✅ README can be read in ~5 minutes
✅ CLAUDE.md can be scanned in ~2 minutes
✅ Each doc has single clear purpose
✅ Navigation between docs is intuitive
