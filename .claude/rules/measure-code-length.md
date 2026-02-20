# Measuring Code Length

Use `tokei` with JSON output piped through `jq`. Commands run from `rs/` (the Rust crate root). Never use `wc -l`, `find`, or estimates.

## Commands

**Production code** (`src/`):
```bash
tokei src/ --output json | jq '.Rust | {code, comments, total: (.code + .comments + .blanks)}'
```

**Test code** (`tests/`):
```bash
tokei tests/ --output json | jq '.Rust | {code, comments, total: (.code + .comments + .blanks)}'
```

## Metrics

| Field | Meaning | Use as |
|-------|---------|--------|
| `code` | Non-blank, non-comment lines | Headline figure |
| `comments` | Comment lines | Supporting detail |
| `total` | code + comments + blanks | "Total with comments" |

## When to Update README

Update `README.md` whenever `code` or `total` change materially. The README tracks these figures as project metrics.
