"""Unit tests for run_pilot_case.py's build_toolchain_fn_and_env -- targeted
at the real, byte-level-inspection-confirmed bugs found in CI run #7:

  - Python: venv_root was computed with Path(python_bin).resolve(), which
    follows the venv's own bin/python symlink to the real base interpreter
    (e.g. /usr/bin/python3.x) and silently derives the WRONG root (e.g.
    "/usr" instead of the venv directory) -- VIRTUAL_ENV then pointed
    nowhere useful and the sandbox never actually exposed the real venv,
    reproducing the identical PermissionError as before the fix existed.
  - Maven: no fix at all previously existed for ~/.m2/repository -- trusted
    setup populates the REAL, unconfined ~/.m2, but the confined process's
    HOME is an isolated fresh directory with no relationship to it.
  - Gradle: no fix at all previously existed for the daemon's own client<->
    daemon TCP loopback bind, which Sandboy's (correctly) fully-closed
    tcp_bind policy rejects.
"""
import argparse
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import run_pilot_case as rpc  # noqa: E402


def _args(**overrides):
    base = {
        "java_home_11": "/usr/lib/jvm/java-11-openjdk-amd64",
        "java_home_21": "/usr/lib/jvm/java-21-openjdk-amd64",
        "venv_python": "",
        "python_base_interpreter": "",
        "setup_python_action_commit": "",
        "case_id": "repo-hyperfine",
        "source_artifact_dir": "/fake/source-artifact/repo-requests",
    }
    base.update(overrides)
    return argparse.Namespace(**base)


class TestPythonVenvRootComputation(unittest.TestCase):
    def test_symlinked_venv_python_does_not_collapse_to_base_interpreter_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            fake_base_python = tmp_path / "usr-bin" / "python3.11"
            fake_base_python.parent.mkdir(parents=True)
            fake_base_python.write_text("#!/bin/sh\n")
            fake_base_python.chmod(0o755)

            venv_root = tmp_path / "venv-repo-pyflakes"
            (venv_root / "bin").mkdir(parents=True)
            venv_python = venv_root / "bin" / "python"
            venv_python.symlink_to(fake_base_python)

            _toolchain_fn, env_values = rpc.build_toolchain_fn_and_env(
                "python", _args(venv_python=str(venv_python))
            )
            self.assertEqual(env_values["VIRTUAL_ENV"], str(venv_root))
            # The bug this guards against: .resolve() following the symlink
            # would have produced the base interpreter's grandparent instead.
            self.assertNotEqual(env_values["VIRTUAL_ENV"], str(fake_base_python.parent.parent))
            self.assertNotIn("PYTHON_BASE_INTERPRETER_ROOT", env_values)

    def test_pinned_base_interpreter_root_is_the_grandparent_of_the_base_interpreter_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            base_interpreter = tmp_path / "hostedtoolcache" / "Python" / "3.12.3" / "x64" / "bin" / "python3"
            base_interpreter.parent.mkdir(parents=True)
            base_interpreter.write_text("#!/bin/sh\n")

            venv_root = tmp_path / "venv-repo-pyflakes"
            (venv_root / "bin").mkdir(parents=True)
            venv_python = venv_root / "bin" / "python"
            venv_python.symlink_to(base_interpreter)

            _toolchain_fn, env_values = rpc.build_toolchain_fn_and_env(
                "python",
                _args(venv_python=str(venv_python), python_base_interpreter=str(base_interpreter)),
            )
            self.assertEqual(
                env_values["PYTHON_BASE_INTERPRETER_ROOT"],
                str(tmp_path / "hostedtoolcache" / "Python" / "3.12.3" / "x64"),
            )


class TestRequestsEditableInstallSourceDirExposure(unittest.TestCase):
    """Real CI evidence (Stage 2, third full run): repo-requests' own frozen
    requirements-dev.txt reads "-e .[socks]" (editable) -- pip's
    editable-install metadata records the absolute path of the trusted-setup
    extraction directory `pip install` actually ran against, which the
    confined capture's own separately re-extracted work_dir/source never
    automatically sees. Failed with "ModuleNotFoundError: No module named
    'requests'" until this exact directory was exposed."""

    def test_repo_requests_gets_the_editable_install_source_dir(self):
        _toolchain_fn, env_values = rpc.build_toolchain_fn_and_env(
            "python", _args(case_id="repo-requests", source_artifact_dir="/fake/source-artifact/repo-requests")
        )
        self.assertEqual(
            env_values["PYTHON_EDITABLE_INSTALL_SOURCE_DIR"],
            str(Path("/fake/source-artifact/repo-requests") / "source"),
        )

    def test_repo_pyflakes_does_not_get_it(self):
        # Same ecosystem, different case_id -- repo-pyflakes' own
        # `pip install .` is a regular (non-editable) install, self-contained
        # in the venv's site-packages; never silently broadened.
        _toolchain_fn, env_values = rpc.build_toolchain_fn_and_env(
            "python", _args(case_id="repo-pyflakes")
        )
        self.assertNotIn("PYTHON_EDITABLE_INSTALL_SOURCE_DIR", env_values)


class TestMavenLocalRepoExposure(unittest.TestCase):
    def test_maven_opts_points_at_real_m2_repository_and_policy_key_matches(self):
        _toolchain_fn, env_values = rpc.build_toolchain_fn_and_env("jvm-maven", _args())
        real_m2_repo = str(Path.home() / ".m2" / "repository")
        self.assertIn(f"-Dmaven.repo.local={real_m2_repo}", env_values["MAVEN_OPTS"])
        self.assertEqual(env_values["MAVEN_LOCAL_REPO_PATH"], real_m2_repo)

    def test_maven_opts_points_at_real_sbt_cache_and_policy_key_matches(self):
        # A real capture (CI run #11) showed scala-maven-plugin's embedded
        # zinc compiler cache its compiler-bridge under $HOME/.sbt -- a
        # cache root entirely separate from ~/.m2, hitting the exact same
        # never-exposed-to-confined-HOME gap.
        _toolchain_fn, env_values = rpc.build_toolchain_fn_and_env("jvm-maven", _args())
        real_sbt_cache = str(Path.home() / ".sbt")
        self.assertIn(f"-Dsbt.global.base={real_sbt_cache}", env_values["MAVEN_OPTS"])
        self.assertEqual(env_values["SBT_GLOBAL_BASE_PATH"], real_sbt_cache)


class TestGradleDaemonDisabled(unittest.TestCase):
    def test_gradle_properties_under_gradle_user_home_disables_the_daemon(self):
        # First attempt (CI run #7/#8) was GRADLE_OPTS=-Dorg.gradle.daemon=
        # false -- real evidence showed Gradle instead forked a fresh
        # "single-use" daemon (still a daemon, still the same TCP bind)
        # because the injected JVM arg didn't match any idle default
        # daemon. org.gradle.daemon=false only reliably disables the daemon
        # from a gradle.properties file under GRADLE_USER_HOME.
        with tempfile.TemporaryDirectory() as tmp:
            fake_home = Path(tmp)
            with mock.patch.object(rpc.Path, "home", return_value=fake_home):
                _toolchain_fn, env_values = rpc.build_toolchain_fn_and_env("jvm-gradle", _args())
            gradle_user_home = fake_home / ".gradle"
            self.assertEqual(env_values["GRADLE_USER_HOME"], str(gradle_user_home))
            self.assertNotIn("GRADLE_OPTS", env_values)
            props = (gradle_user_home / "gradle.properties").read_text()
            self.assertIn("org.gradle.daemon=false", props)
            self.assertNotIn("org.gradle.parallel", props)


class TestGradleDeterministicSchedulingProfile(unittest.TestCase):
    """D1b authorization (2026-07-16, repo-moshi only): a real pair (both
    genuine BUILD SUCCESSFUL, all identity fields matching) still failed
    canonical-byte equality because Gradle's own parallel task scheduler
    interleaves per-task console lines nondeterministically -- force fully
    serial scheduling and a plain console, scoped to repo-moshi ONLY."""

    def test_repo_moshi_gets_the_deterministic_scheduling_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake_home = Path(tmp)
            with mock.patch.object(rpc.Path, "home", return_value=fake_home):
                toolchain_fn, env_values = rpc.build_toolchain_fn_and_env(
                    "jvm-gradle", _args(case_id="repo-moshi")
                )
            gradle_user_home = fake_home / ".gradle"
            props = (gradle_user_home / "gradle.properties").read_text()
            self.assertIn("org.gradle.daemon=false", props)
            self.assertIn("org.gradle.parallel=false", props)
            self.assertIn("org.gradle.workers.max=1", props)
            self.assertIn("org.gradle.console=plain", props)
            self.assertIn("org.gradle.console.interactive=false", props)
            # Synthetic profile fields surface through the toolchain-identity
            # closure (mirroring how python's provenance fields flow into the
            # receipt), never invented independently of what was actually
            # written to gradle.properties.
            with mock.patch.object(
                rpc.et, "capture_gradle_toolchain_identity",
                return_value={"resolved_version": "9.5.1", "runtime_identifier": "21"},
            ):
                raw = toolchain_fn(Path("/fake/source"))
            self.assertEqual(raw["gradle_scheduling_profile_sha256"], __import__("hashlib").sha256(props.encode()).hexdigest())
            self.assertEqual(raw["gradle_scheduling_profile_properties"], props)
            self.assertEqual(raw["gradle_scheduling_profile_gradle_user_home"], str(gradle_user_home))

    def test_another_gradle_case_does_not_get_the_scheduling_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake_home = Path(tmp)
            with mock.patch.object(rpc.Path, "home", return_value=fake_home):
                toolchain_fn, env_values = rpc.build_toolchain_fn_and_env(
                    "jvm-gradle", _args(case_id="repo-some-other-gradle-case")
                )
            gradle_user_home = fake_home / ".gradle"
            props = (gradle_user_home / "gradle.properties").read_text()
            self.assertNotIn("org.gradle.parallel", props)
            with mock.patch.object(
                rpc.et, "capture_gradle_toolchain_identity",
                return_value={"resolved_version": "9.5.1", "runtime_identifier": "21"},
            ):
                raw = toolchain_fn(Path("/fake/source"))
            self.assertNotIn("gradle_scheduling_profile_sha256", raw)

    def test_frozen_argv_with_conflicting_flag_fails_closed(self):
        original = rpc.CASES["repo-moshi"]["frozen_argv"]
        rpc.CASES["repo-moshi"]["frozen_argv"] = ["./gradlew", "test", "--max-workers=4"]
        try:
            with tempfile.TemporaryDirectory() as tmp:
                fake_home = Path(tmp)
                with mock.patch.object(rpc.Path, "home", return_value=fake_home):
                    with self.assertRaises(SystemExit):
                        rpc.build_toolchain_fn_and_env("jvm-gradle", _args(case_id="repo-moshi"))
        finally:
            rpc.CASES["repo-moshi"]["frozen_argv"] = original

    def test_conflicting_ambient_gradle_opts_fails_closed(self):
        import os

        with tempfile.TemporaryDirectory() as tmp:
            fake_home = Path(tmp)
            with mock.patch.object(rpc.Path, "home", return_value=fake_home), \
                    mock.patch.dict(os.environ, {"GRADLE_OPTS": "-Dorg.gradle.workers.max=4"}):
                with self.assertRaises(SystemExit):
                    rpc.build_toolchain_fn_and_env("jvm-gradle", _args(case_id="repo-moshi"))


class TestHelmValuesSubprojectBuildDirsWritable(unittest.TestCase):
    """Real CI evidence (Stage 2, first full 9-case run): even though the
    frozen argv scopes execution to :helm-values-shared:test alone, Gradle's
    default eager configuration phase evaluates every subproject listed in
    settings.gradle.kts -- the build genuinely failed with "Cannot create
    directory '.../helm-values-intellij-plugin/build/tmp/generateManifest'"
    because that sibling module's own plugin creates its build dir during
    configuration, before any task selection narrows the build."""

    def test_every_subproject_build_dir_is_writable(self):
        dirs = rpc.CASES["repo-helm-values"]["project_writable_dirs_relative"]
        for subproject in ("helm-values-gradle-plugin", "helm-values-intellij-plugin",
                           "helm-values-shared", "helm-values-test"):
            self.assertIn(f"{subproject}/build", dirs)

    def test_root_build_and_gradle_dirs_still_writable(self):
        dirs = rpc.CASES["repo-helm-values"]["project_writable_dirs_relative"]
        self.assertIn("build", dirs)
        self.assertIn(".gradle", dirs)
        self.assertIn(".kotlin", dirs)


class TestRustlingsTestExercisesWritable(unittest.TestCase):
    """Real CI evidence (Stage 2, first full 9-case run): rustlings' own
    integration tests invoke the compiled binary with
    current_dir("tests/test_exercises"), which writes its own
    .rustlings-state.txt there -- 3 tests failed with "Permission denied
    (os error 13)" until this directory was writable."""

    def test_tests_test_exercises_is_writable(self):
        dirs = rpc.CASES["repo-rustlings"]["project_writable_dirs_relative"]
        self.assertIn("tests/test_exercises", dirs)

    def test_target_dir_still_writable(self):
        dirs = rpc.CASES["repo-rustlings"]["project_writable_dirs_relative"]
        self.assertIn("target", dirs)

    def test_dockerfile_parser_rs_does_not_get_the_rustlings_specific_dir(self):
        # Different case, own crate layout -- never silently broadened.
        dirs = rpc.CASES["repo-dockerfile-parser-rs"]["project_writable_dirs_relative"]
        self.assertNotIn("tests/test_exercises", dirs)


class TestDeterministicCargoTestScheduling(unittest.TestCase):
    """D1b authorization (2026-07-16, repo-rustlings + repo-dockerfile-parser-
    rs only): real CI evidence showed cargo test's default multi-threaded
    test harness interleave individual test-result lines nondeterministically
    between capture-a and capture-b. RUST_TEST_THREADS=1 is Rust's own
    documented environment-variable equivalent of --test-threads=1, taking
    effect with no change to the frozen ["cargo", "test"] argv itself --
    same class of fix as repo-moshi's deterministic Gradle scheduling
    profile (external configuration, never a frozen-argv edit)."""

    def test_repo_rustlings_gets_rust_test_threads_1(self):
        _toolchain_fn, env_values = rpc.build_toolchain_fn_and_env("rust", _args(case_id="repo-rustlings"))
        self.assertEqual(env_values["RUST_TEST_THREADS"], "1")

    def test_repo_dockerfile_parser_rs_gets_rust_test_threads_1(self):
        _toolchain_fn, env_values = rpc.build_toolchain_fn_and_env(
            "rust", _args(case_id="repo-dockerfile-parser-rs")
        )
        self.assertEqual(env_values["RUST_TEST_THREADS"], "1")

    def test_repo_hyperfine_does_not_get_rust_test_threads(self):
        # Same ecosystem, different case_id, not a cargo-test invocation --
        # never silently broadened to the whole rust ecosystem.
        _toolchain_fn, env_values = rpc.build_toolchain_fn_and_env("rust", _args(case_id="repo-hyperfine"))
        self.assertNotIn("RUST_TEST_THREADS", env_values)


class TestPythonArgv0OverrideSelection(unittest.TestCase):
    """Real CI evidence (Stage 2, first full 9-case run): repo-requests'
    frozen argv is a bare console-script invocation (["pytest"]), not a
    "python <module>" invocation like repo-pyflakes' -- each needs its own
    argv[0] substitution target. See resolve_python_argv0_override's own
    docstring for the full failure-mode analysis."""

    def test_python_module_style_substitutes_the_interpreter_itself(self):
        override = rpc.resolve_python_argv0_override(
            ecosystem="python",
            venv_python="/tmp/venv-repo-pyflakes/bin/python",
            frozen_argv=["python", "-m", "pyflakes", "src/"],
        )
        self.assertEqual(override, "/tmp/venv-repo-pyflakes/bin/python")

    def test_bare_console_script_style_substitutes_the_sibling_script_not_the_interpreter(self):
        override = rpc.resolve_python_argv0_override(
            ecosystem="python",
            venv_python="/tmp/venv-repo-requests/bin/python",
            frozen_argv=["pytest"],
        )
        self.assertEqual(override, "/tmp/venv-repo-requests/bin/pytest")
        # The bug this guards against: overriding with the bare interpreter
        # path here would silently drop "pytest" as an argument entirely.
        self.assertNotEqual(override, "/tmp/venv-repo-requests/bin/python")

    def test_no_venv_python_means_no_override(self):
        override = rpc.resolve_python_argv0_override(
            ecosystem="python", venv_python="", frozen_argv=["pytest"]
        )
        self.assertIsNone(override)

    def test_non_python_ecosystem_means_no_override_even_with_venv_python_set(self):
        override = rpc.resolve_python_argv0_override(
            ecosystem="rust", venv_python="/tmp/venv-x/bin/python", frozen_argv=["cargo", "test"]
        )
        self.assertIsNone(override)


class TestRepoRequestsToolchainIdentityIsExactMatchClassifiable(unittest.TestCase):
    """D1b remediation (2026-07-17): the prior "3.x" requested_version_or_
    range never exact/compatible-matched toolchain_identity.classify()'s own
    wildcard-range grammar against a real three-component resolved version
    ("3.12.3") -- every real repo-requests run classified as
    toolchain_executed.classification="unexpected-resolution". Fixed by
    pinning the exact same actions/setup-python identity repo-pyflakes
    already uses (python-version 3.12.3), so requested_version_or_range now
    literally equals the pinned, always-resolved version."""

    def test_requested_version_or_range_is_the_exact_pinned_version(self):
        self.assertEqual(rpc.CASES["repo-requests"]["requested_version_or_range"], "3.12.3")

    def test_resolver_mechanism_documents_the_pinned_setup_python_identity(self):
        mechanism = rpc.CASES["repo-requests"]["resolver_mechanism"]
        self.assertIn("a26af69be951a213d495a4c3e4e4022e16d87065", mechanism)
        self.assertIn("3.12.3", mechanism)

    def test_classify_against_the_real_pinned_resolution_is_exact_match(self):
        import toolchain_identity as ti  # noqa: E402 -- available via generic_capture's sys.path setup

        classification = ti.classify(
            requested_version_or_range=rpc.CASES["repo-requests"]["requested_version_or_range"],
            resolved_version="3.12.3",
            runtime_identifier="cpython-3.12.3-cpython-312-cpython-312-x86_64-linux-gnu-linux-x86_64",
            resolved_executable_path="/opt/hostedtoolcache/Python/3.12.3/x64/bin/python3",
            executed_binary_absolute_path="/home/runner/work/_temp/venv-repo-requests/bin/python",
            executed_binary_sha256="a" * 64,
        )
        self.assertEqual(classification, "exact-match")

    def test_the_prior_wildcard_range_would_have_been_unexpected_resolution(self):
        # Documents the actual bug: "3.x" against a real three-component
        # resolved version never matches classify()'s own range grammar.
        import toolchain_identity as ti  # noqa: E402

        classification = ti.classify(
            requested_version_or_range="3.x",
            resolved_version="3.12.3",
            runtime_identifier="cpython-3.12.3-cpython-312-cpython-312-x86_64-linux-gnu-linux-x86_64",
            resolved_executable_path="/usr/bin/python3",
            executed_binary_absolute_path="/home/runner/work/_temp/venv-repo-requests/bin/python",
            executed_binary_sha256="a" * 64,
        )
        self.assertEqual(classification, "unexpected-resolution")


if __name__ == "__main__":
    unittest.main()
