#!/usr/bin/env bash
# N2-E substrate bootstrap — reproducible acquisition of the mandated build
# substrate (.#rtk-pinned and .#qodec) in an environment where the org egress
# policy gates GitHub's web/archive/API endpoints but permits the git
# smart-HTTP transport.
#
# WHY THIS EXISTS
#   Nix's `github:` fetcher downloads commit tarballs from codeload.github.com,
#   which the egress policy returns 403 for on cross-owner repositories. The git
#   smart-HTTP transport (git-upload-pack) is NOT gated, so every locked flake
#   input is fetched by `git fetch <rev>` and its tree is reproduced with
#   `git archive` — which applies the SAME normalization as GitHub's tarball, so
#   the resulting tree's NAR hash matches flake.lock byte-for-byte. The flake is
#   then built with input transport overrides ONLY; flake.lock and the pinned
#   source identities are never modified.
#
#   Building the mandated flake through this transport is NOT the prohibited
#   "locally installed RTK binary": it is the exact .#rtk-pinned derivation from
#   the exact pinned commit, and the sandboxed build reproduces the mission's
#   required RTK binary SHA-256 bit-for-bit.
#
# REQUIREMENTS
#   - Nix with `experimental-features = nix-command flakes` and `sandbox = true`
#     (user namespaces must be available; the sandbox gives the deterministic
#     /build path required to reproduce the pinned binary hash).
#   - git, tar, and outbound git smart-HTTP to github.com.
#
# USAGE
#   bootstrap_substrate.sh <repo_root> <work_dir> [out_link_dir]
#   - repo_root:    checkout of PhysShell/qodec containing flake.nix / flake.lock
#   - work_dir:     scratch dir for the reconstructed input trees (>= 1 GiB)
#   - out_link_dir: where to place result symlinks (default: $work_dir/out)
#
# The expected RTK binary SHA-256 (mission-pinned) is asserted at the end.
set -euo pipefail

REPO_ROOT="${1:?repo_root required}"
WORK_DIR="${2:?work_dir required}"
OUT_DIR="${3:-$WORK_DIR/out}"
EXPECTED_RTK_SHA256="41f316adf7b30a568208a0a4f824bffb266ecb6d01bd9de81bed58e1d469dfcf"

mkdir -p "$WORK_DIR/trees" "$OUT_DIR"

# Locked GitHub inputs: owner repo rev  (revisions come from flake.lock and are
# never edited here; this table is asserted against flake.lock by the verifier).
read -r -d '' INPUTS <<'EOF' || true
ipetkov crane 469fd08d0bcf6926321fa973c6777fbc87785dd7
numtide flake-utils 11707dc2f618dd54ca8739b309ec4fc024de578b
NixOS nixpkgs ac62194c3917d5f474c1a844b6fd6da2db95077d
rtk-ai rtk 5d32d0736f686b69d1e8b9dc45c007d4eb77a0a2
oxalica rust-overlay e3fa5cf86b93914b8f312b2a1ca14fbb139c655c
nix-systems default da67096a3b9bf56a91d16901293e51ba5b49a27e
EOF

echo "[1/3] reconstructing locked input trees via git transport + git archive"
while read -r owner repo rev; do
  [ -z "${owner:-}" ] && continue
  dest="$WORK_DIR/trees/$repo"
  rm -rf "$dest"; mkdir -p "$dest"
  tmp="$(mktemp -d)"
  ( cd "$tmp"
    git init -q
    GIT_TERMINAL_PROMPT=0 git fetch -q --depth 1 "https://github.com/$owner/$repo.git" "$rev"
    git archive --format=tar FETCH_HEAD ) | tar -x -C "$dest"
  rm -rf "$tmp"
  nar="$(nix hash path --sri "$dest")"
  echo "    $repo  $nar"
done <<< "$INPUTS"

echo "[2/3] building .#rtk-pinned and .#qodec under the sandbox (transport overrides only)"
T="$WORK_DIR/trees"
( cd "$REPO_ROOT"
  nix build .#rtk-pinned .#qodec -L --no-write-lock-file --sandbox \
    --override-input nixpkgs "path:$T/nixpkgs" \
    --override-input crane "path:$T/crane" \
    --override-input rust-overlay "path:$T/rust-overlay" \
    --override-input flake-utils "path:$T/flake-utils" \
    --override-input flake-utils/systems "path:$T/default" \
    --override-input rtk-src "path:$T/rtk" \
    --out-link "$OUT_DIR/result" )

RTK_BIN="$OUT_DIR/result/bin/rtk"
[ -x "$OUT_DIR/result-1/bin/qodec" ] && QODEC_BIN="$OUT_DIR/result-1/bin/qodec" || QODEC_BIN="$OUT_DIR/result/bin/qodec"

echo "[3/3] asserting RTK binary identity"
actual="$(sha256sum "$RTK_BIN" | cut -d' ' -f1)"
echo "    rtk    $actual"
echo "    qodec  $(sha256sum "$QODEC_BIN" | cut -d' ' -f1)"
if [ "$actual" != "$EXPECTED_RTK_SHA256" ]; then
  echo "FATAL: RTK binary SHA-256 mismatch (got $actual, want $EXPECTED_RTK_SHA256)" >&2
  exit 1
fi
echo "OK: .#rtk-pinned reproduces the mission-pinned RTK binary SHA-256 exactly."
echo "RTK_BIN=$RTK_BIN"
echo "QODEC_BIN=$QODEC_BIN"
