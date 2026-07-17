#!/usr/bin/env bash
# Outer network-namespace + resource-limit wrapper around one Sandboy-confined
# command, for the N2-A miner canary.
#
# Layering (outermost to innermost):
#   ulimit (this shell)     -- CPU time / process count caps, inherited across
#                              exec+fork regardless of privilege. NOT address
#                              space (RLIMIT_AS): CoreCLR reserves virtual
#                              memory far beyond what it commits/uses at
#                              startup, and a `ulimit -v` cap makes it fail
#                              immediately with HRESULT 0x8007000E
#                              (E_OUTOFMEMORY) — confirmed against the real
#                              canary build, not a hypothetical. This is a
#                              genuine interop constraint, not something to
#                              force through; wall-clock (`timeout`) and CPU
#                              time/process-count limits below don't have
#                              this problem.
#   sudo --preserve-env=... -- root, needed only to create the network
#                              namespace; explicitly allowlists the SAME small
#                              set of env names Sandboy's own policy allows
#                              (defense in depth, not reliance on sudo alone)
#   unshare --net           -- fresh network namespace: no interface but the
#                              loopback we bring up ourselves, i.e. no route
#                              to anywhere off-host
#   runuser -p -u <caller>  -- drop back to the unprivileged runner user,
#                              preserving the already-minimal environment
#   timeout                 -- wall-clock cap
#   sandboy run              -- Landlock + seccomp + its OWN env_clear()+
#                              env_allow confinement (final, authoritative)
#   <argv...>                -- the untrusted command
#
# Usage:
#   run_confined_build.sh <sandboy-bin> <policy.toml> <cwd> -- <argv...>
#
# The caller (capture_build.py) is responsible for exporting exactly the env
# names the Sandboy policy's env_allow lists, pointed at dedicated (non-host)
# values, before invoking this script.
set -euo pipefail

SANDBOY_BIN=$1; POLICY=$2; CWD=$3; shift 3
[ "${1:-}" = "--" ] || { echo "run_confined_build.sh: expected -- before argv" >&2; exit 2; }
shift

CALLER_USER=$(id -un)
# `sudo` strips almost every environment variable unless named here --
# real N2-D1b evidence (CI run #7) showed RUSTUP_TOOLCHAIN and VIRTUAL_ENV
# (both correctly set by the caller and correctly listed in the Sandboy
# policy's own env_allow) produce byte-identical failures to before those
# fixes existed, because this list -- written only for N2-A's dotnet-only
# canary -- silently dropped them at the `sudo` layer, before Sandboy's own
# confinement ever saw them. This is now the union of every env_allow name
# across all 5 N2-D1b ecosystems (generic_sandbox_policy.py's
# ECOSYSTEM_POLICY_HINTS), not just dotnet's -- a strict superset of the
# original dotnet-only list, so N2-A's own (frozen, already-accepted) usage
# is unaffected.
#
# N2D1B_TIMEOUT_SINK_TARGET is a synthetic, wrapper-only key (never itself
# forwarded to the confined child, and never a Sandboy env_allow entry --
# see generic_sandbox_policy.py's TIMEOUT_SINK_AUTHORIZED_CASES): when set,
# it names the single exact IP address this job's veth-pair timeout-sink
# route (below) should target. Authorized strictly per exact case_id
# (currently repo-requests only), never a whole ecosystem.
PRESERVE_ENV="PATH,HOME,TMPDIR,DOTNET_ROOT,DOTNET_CLI_TELEMETRY_OPTOUT,DOTNET_NOLOGO,DOTNET_SKIP_FIRST_TIME_EXPERIENCE,DOTNET_MULTILEVEL_LOOKUP,DOTNET_GENERATE_ASPNET_CERTIFICATE,NUGET_PACKAGES,CARGO_HOME,RUSTUP_HOME,CARGO_NET_OFFLINE,RUSTUP_TOOLCHAIN,RUST_TEST_THREADS,PYTHONDONTWRITEBYTECODE,PIP_NO_INDEX,VIRTUAL_ENV,JAVA_HOME,MAVEN_OPTS,GRADLE_USER_HOME,GRADLE_OPTS,N2D1B_TIMEOUT_SINK_TARGET"

ulimit -t 600                    # 600s CPU time
ulimit -u 512                    # max processes/threads for this user

# D1b remediation round 2 (2026-07-17), repo-requests-only: when the caller
# sets N2D1B_TIMEOUT_SINK_TARGET, add a route to that single exact target IP
# that makes connect() genuinely block (never returning a synchronous
# errno) until the CALLER's own socket-timeout mechanism fires. Deliberately
# NOT a `blackhole`/`unreachable`/`prohibit` route type: those return a
# synchronous errno at connect()-time (the kernel's route-lookup path
# short-circuits before any L2 transmission), which is exactly the wrong
# semantics for a test suite that expects a genuine socket.timeout (real CI
# run 29547420247 confirmed the FAILURE mode this guards against: an
# immediate "OSError: [Errno 101] Network is unreachable" instead of a
# timeout, because the isolated netns simply had no route to the target at
# all). Instead: a veth pair with BOTH ends brought up but NEITHER assigned
# an IP address, and a directly-connected, gateway-less /32 route to the
# target via the local end. Sending traffic there requires ARP resolution
# for an address neither veth peer owns -- nothing ever answers, so the
# kernel keeps retrying ARP indefinitely while connect() blocks, and the
# caller's own `socket.settimeout()` (non-blocking socket + select()/
# poll()) is what actually raises `socket.timeout`, well before any
# kernel-level ARP-failure timeout. Empirically validated via a local live
# probe (loopback still works; the sink target produces a genuine, bounded
# socket.timeout at several different requested timeouts; every other
# RFC1918/external target stays immediately blocked, never connecting and
# never hanging) before this conditional was added -- see
# timeout_sink_probe.py for the same three checks re-run live on every
# authorized job. A route to exactly one /32 address, not a general "allow
# this subnet" rule: it does not create a real listener (no ECONNREFUSED)
# and does not permit arbitrary RFC1918 connectivity.
exec sudo --preserve-env="$PRESERVE_ENV" unshare --net bash -c '
  ip link set lo up
  if [ -n "${N2D1B_TIMEOUT_SINK_TARGET:-}" ]; then
    ip link add n2d1bsink0 type veth peer name n2d1bsink1
    ip link set n2d1bsink0 up
    ip link set n2d1bsink1 up
    ip route add "${N2D1B_TIMEOUT_SINK_TARGET}/32" dev n2d1bsink0
  fi
  cd "$1" || exit 1
  shift
  caller_user=$1; shift
  sandboy_bin=$1; shift
  policy=$1; shift
  exec runuser -p -u "$caller_user" -- timeout 900 "$sandboy_bin" run --policy "$policy" -- "$@"
' _ "$CWD" "$CALLER_USER" "$SANDBOY_BIN" "$POLICY" "$@"
