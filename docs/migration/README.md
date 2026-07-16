# QODEC repository migration

## Why the repository was split

QODEC (the `qodec/` crate and its Interop Benchmark v2 harness under
`qodec/evals/interop/`) was developed inside `PhysShell/007`, alongside an
unrelated private agent harness (`o7`, the repository's root Rust crate) and
a stack of `DO NOT MERGE` scope PRs (N2-A through N2-D1b) documenting its own
research history. That arrangement meant:

- every QODEC-only change re-triggered `o7`-unrelated CI in a repository whose
  primary purpose is the `o7` harness;
- QODEC's own CI (`qodec-v2*.yml`, the `qodec-n2*.yml` scope workflows) ran
  against a shared `main` history it had no reason to be coupled to;
- QODEC could not be handed to anyone, or depended on by another project, as
  a standalone artifact without also handing over `o7`.

This migration extracts QODEC's own history and current tree into
`PhysShell/qodec`, a standalone public repository, and stops the embedded
QODEC CI from running on unrelated `007` work (tracked as a separate,
follow-on cleanup PR in `007` once the standalone repository and its own CI
are verified).

## Source identity

The authoritative migration source is **not a merge commit** — the source PRs
(`PhysShell/007#54`, `#55`, `#56`) are all intentionally unmerged and marked
`DO NOT MERGE`, by design of the scope-PR research process this repository
uses. That is expected, not a blocker. The migration source is the exact,
verified tip of the stacked branch chain ending at PR #56:

| PR | Branch | Head SHA | Base |
|---|---|---|---|
| [`#54`](https://github.com/PhysShell/007/pull/54) | `claude/qodec-benchmark-v2-source-freeze-n2c` | `acb57379e2d0b9ed6fe79fd45e7540d7d00d7490` | `main` @ `7d4dc3aabf760c4df272cf13a7e17ea437c81490` |
| [`#55`](https://github.com/PhysShell/007/pull/55) | `claude/n2d0-durable-evidence-rescue` | `4e40b6f393cbdaf1bfcc36b8c422f7e17ae41dee` | PR #54 branch @ `acb57379e2d0b9ed6fe79fd45e7540d7d00d7490` |
| [`#56`](https://github.com/PhysShell/007/pull/56) | `claude/qodec-benchmark-v2-n2d-identity-lock` | `662adf6ea6ba7438f1a31e9faf95554b4b14eedf` | PR #55 branch @ `4e40b6f393cbdaf1bfcc36b8c422f7e17ae41dee` |

Every value above was resolved directly from the GitHub API immediately
before migration (never copied from a prompt or guessed), and the ancestry
(`#54` head is an ancestor of `#55` head; `#55` head is an ancestor of `#56`
head) was independently verified with `git merge-base --is-ancestor` against
a full clone of `PhysShell/007` before any filtering began.

`PhysShell/007#58` (`o7 invoke`) has no relationship to this migration and
was not consulted, cloned from, or imported in any form.

## The `git-filter-repo` procedure

1. A full clone of `PhysShell/007` was fetched, and the three branches above
   fetched and tip-verified against the GitHub API values.
2. `HEAD` was detached at the PR #56 head SHA (`662adf6e...`), a new local
   `migration-source` branch created there, renamed to `main`, and `origin`
   removed — freezing the exact commit graph to be filtered, with no network
   dependency on `007` for the rest of the procedure.
3. [`git-filter-repo`](https://github.com/newren/git-filter-repo) rewrote
   that history down to only the paths listed below, then renamed the
   `qodec/` subtree to the repository root:

   ```
   git filter-repo --force \
     --refs refs/heads/main \
     --path qodec/ \
     --path-glob '.github/workflows/qodec*.yml' \
     --path-glob '.github/workflows/qodec*.yaml' \
     --path flake.nix \
     --path flake.lock \
     --path rust-toolchain.toml \
     --path .gitignore \
     --path .editorconfig \
     --path-glob 'LICENSE*' \
     --path-glob 'NOTICE*' \
     --path-rename qodec/:
   ```

4. Stray refs left over from the pre-filter clone (a leftover `007` release
   tag, `ORIG_HEAD`, `FETCH_HEAD`) were deleted and reflogs expired, so only
   the filtered `main` branch remained reachable before the first push.

`git-filter-repo` naturally drops any commit that touches none of the listed
paths, and rewrites every commit SHA on the commits it keeps — no commit,
tree, or blob in this repository's history is byte-identical to its `007`
counterpart, only content-identical where the paths were unchanged. This is
why base-commit-SHA-dependent internal consistency checks inherited from
`007` (see "Known non-functional inherited checks" below) cannot resolve
their reference commit in this repository, and gracefully skip rather than
fail.

## Included paths

- `qodec/` (the entire subtree — Rust crate source, `Cargo.toml`/`Cargo.lock`,
  and the full `evals/interop/` benchmark harness) → repository root
- `.github/workflows/qodec*.yml` / `*.yaml` (8 workflow files)
- `flake.nix`, `flake.lock`
- `rust-toolchain.toml`
- `.gitignore`

No `.editorconfig`, `LICENSE*`, or `NOTICE*` existed in `007`'s tree at the
migration source commit, so those glob patterns matched nothing — not an
error.

## Deliberately excluded components

- **`o7` application source** — the repository-root `Cargo.toml`/`Cargo.lock`
  (package `o7`), `src/*.rs`, `tests/*.rs`, `examples/`, `fuzz/`, `judge/`.
  None of it is reachable from any commit in this repository's history.
- **Codex CLI integration** — the `codex-cli` flake input
  (`github:PhysShell/codex-cli-nix`) and its package reference in the old
  `flake.nix`'s default dev shell. Removed from `flake.nix` during the
  standalone-adaptation commit (see below); never present in any filtered
  commit's tree.
- **`Demand Radar` / unrelated `007` experiments** — `docs/`, `TODO.md`,
  `deny.toml`, `.gitattributes`, and any other root-level `007` file not in
  the included-paths list above.

A full-history pickaxe search (`git log main -G'<pattern>'`, scoped to the
filtered `main` branch only — not `--all`, which would also match dangling
pre-filter objects) for `o7 invoke`, `src/invoke.rs`, `call_claude`,
`call_codex`, `codex-cli`, and `Demand Radar` confirmed: zero matches for the
first four, and matches for `codex-cli` only in `flake.nix`/`flake.lock`
(exactly the input this migration removes).

## The root path rename

Every file under `qodec/` in `007` now lives at the equivalent path with the
`qodec/` prefix dropped (`qodec/src/main.rs` → `src/main.rs`,
`qodec/evals/interop/v2/README.md` → `evals/interop/v2/README.md`, etc.).
Executable and configuration code that constructed a `qodec/`-relative path
string was updated to match (path prefixes in `corpus_tool.py`, JSON Schema
`$id` fields, `REPO_ROOT`-relative test constants, the `.gitignore` entry
that keeps `evals/interop/v2/private/` out of git, `flake.nix`'s Nix-store
staging paths, and so on). `Path(__file__).resolve().parents[N]`-style
ascent, which doesn't spell out `qodec/` as a literal string, needed no
change — the relative nesting inside the old `qodec/` subtree was preserved
by the rename, only what sits above it changed.

**Frozen historical evidence was deliberately left untouched** even where it
records the old `qodec/...` layout: self-hash-locked JSON records
(`stage1-pilot-evidence.json`, `stage1-and-stage2-acceptance-revocation.json`,
`repo-spotless-rejection-record.json`, `execution-plan-errata.json`, its
`errata_sha256`), frozen acceptance contracts (`n2d0-contract.json`,
`n2d1-contract.json`), and the historical-record-reproducing builder scripts
that regenerate them (`tools/build_stage1_pilot_evidence.py`,
`tools/build_evidence_revocation.py`,
`tools/build_repo_spotless_rejection_record.py`) all still say `qodec/...`,
because that is what was literally true when those records were captured in
`007` and rewriting them would silently corrupt their own self-hashes and
misrepresent history. Where a test needed to actually *locate* a real,
currently-present file using one of those frozen path strings, the fix was
applied at the point of use in the test (stripping the known historical
`qodec/` prefix before joining with the new `REPO_ROOT`) rather than by
editing the frozen record.

**Known non-functional inherited checks.** A handful of "frozen-base" guards
(`evals/interop/v2/n2/source-freeze/tools/frozen_base_check.py`,
`evals/interop/v2/n2/miner/tools/generate_ci_artifacts.py`, and the test
files that exercise them) compare the working tree against a specific `007`
commit SHA that predates this migration. Since `git-filter-repo` rewrites
every commit SHA, that reference commit does not exist in this repository's
history; the test files already carried a
`@unittest.skipUnless(git cat-file -e <sha>, ...)` guard for exactly this
situation, so they skip cleanly rather than fail or silently vacuous-pass.
The same fix was applied to two similar checks in
`tests/test_execution_plan_errata.py` that compared against `007`'s N2-D0
closure commit. These guards describe historical, monorepo-specific
development discipline from completed N2 scopes and are not part of this
repository's ongoing CI surface.

## Commit-map files

`docs/migration/007-commit-map.tsv` (SHA-256
`c37535363dc00576279a7843e87b4ae5fb27e69d41aef80070349da19ac426b6`) is
`git-filter-repo`'s own `commit-map` output, copied verbatim: every original
`007` commit SHA the filter processed, mapped to its rewritten SHA in this
repository (or omitted if the commit was dropped for touching none of the
included paths).

`docs/migration/007-ref-map.tsv` (SHA-256
`278778792f21644565deba5675bc79ba6a29b533c22ffc48641aa90e5448858d`) is the
corresponding `ref-map` output.

Neither file's contents were edited after generation.

## Evidence-retention rules

- Pre-migration GitHub releases, Actions run artifacts, PR discussion, and
  issue history remain **only** in `PhysShell/007` — none of it is
  transferred, mirrored, or re-uploaded here.
- Every hash, SHA, run ID, and URL recorded in this repository's frozen
  evidence JSON refers to `PhysShell/007` and is **intentionally not
  rewritten** to point at this repository.
- New development, new CI runs, and new evidence from this point forward
  belong to `PhysShell/qodec`.

## How to verify provenance

```
python3 tools/verify_migration_provenance.py
```

independently recomputes `MIGRATION_PROVENANCE.json`'s self-hash and fails
closed on any mismatch. To verify the history-filtering claims independently:

```
git clone https://github.com/PhysShell/007.git
cd 007
git log --oneline <SOURCE_HEAD_SHA>   # confirms the source commit is real
git merge-base --is-ancestor <PR54_HEAD> <PR55_HEAD> && echo ok
git merge-base --is-ancestor <PR55_HEAD> <SOURCE_HEAD_SHA> && echo ok
```

using the SHAs recorded in `MIGRATION_PROVENANCE.json`.
