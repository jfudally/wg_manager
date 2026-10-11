"""Shape tests for the portable CLI binaries built with pypackager.

pypackager (github.com/jfudally/pypackager) wraps ``pex --scie eager``:
each binary embeds a CPython 3.13 interpreter plus the locked runtime
deps, so ``wg-manager`` runs on a host with no Python installed.

``make cli-binary`` is the one entrypoint humans, CI and the release
workflow share. CI builds every target on PRs without publishing (like
``image-build.yml``); the release workflow builds the same targets and
attaches them to the GitHub release. These tests pin that shape — the
build itself is what the workflows run.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
SPEC_PATH = REPO_ROOT / "packaging" / "wg-manager-cli.toml"
CI_PATH = REPO_ROOT / ".github" / "workflows" / "ci.yml"
RELEASE_PATH = REPO_ROOT / ".github" / "workflows" / "release.yml"

# Every target is built natively on a runner of its own OS/arch: pex's
# abbreviated cross-platforms can't evaluate the ``python_full_version``
# markers in the uv.lock export.
TARGETS = {"linux-x86_64", "linux-aarch64", "macos-aarch64"}


def _makefile() -> str:
    return (REPO_ROOT / "Makefile").read_text()


def _recipe(target: str) -> str:
    """Recipe lines of ``target`` in the Makefile."""
    lines = _makefile().splitlines()
    start = lines.index(f"{target}:") + 1
    body: list[str] = []
    for line in lines[start:]:
        if not line.startswith("\t"):
            break
        body.append(line)
    return "\n".join(body)


def _matrix_targets(job: dict) -> set[str]:
    return {leg["target"] for leg in job["strategy"]["matrix"]["include"]}


def _runs(job: dict) -> list[str]:
    return [s.get("run", "") for s in job["steps"]]


@pytest.fixture(scope="module")
def spec() -> dict:
    return tomllib.loads(SPEC_PATH.read_text())


@pytest.fixture(scope="module")
def job() -> dict:
    """The CI workflow's build-only ``cli-binary`` job."""
    return yaml.safe_load(CI_PATH.read_text())["jobs"]["cli-binary"]


@pytest.fixture(scope="module")
def workflow() -> dict:
    return yaml.safe_load(RELEASE_PATH.read_text())


class TestBuildSpec:
    def test_builds_the_wg_manager_console_script(self, spec: dict) -> None:
        assert spec["app"]["project"] == "."
        assert spec["app"]["console_script"] == "wg-manager"
        assert spec["app"]["name"] == "wg-manager"

    def test_embeds_the_interpreter(self, spec: dict) -> None:
        assert spec["build"]["scie"] == "eager"

    def test_embeds_the_python_ci_tests_against(self, spec: dict) -> None:
        # Same minor as the Dockerfile and the CI backend job.
        assert spec["build"]["python_version"] == "3.13"

    def test_resolves_against_a_real_313_interpreter(self, spec: dict) -> None:
        """pypackager runs pex on its own 3.14 interpreter. Without
        ``--python``, pex picks cp314 wheels that the embedded 3.13
        can't load, and the binary fails on first run."""
        args = spec["build"]["extra_pex_args"]
        assert args[args.index("--python") + 1] == "python3.13"

    def test_resolves_the_locked_versions(self, spec: dict) -> None:
        """``--project`` alone resolves pyproject's ranges; the export
        of uv.lock pins every dep to what the tests ran against."""
        args = spec["build"]["extra_pex_args"]
        assert args[args.index("-r") + 1] == "build/cli-requirements.txt"

    def test_does_not_cross_resolve(self, spec: dict) -> None:
        assert spec["build"]["auto_platform"] is False

    def test_lists_every_target(self, spec: dict) -> None:
        listed = {f"{t['os']}-{t['arch']}" for t in spec["targets"]}
        assert listed == TARGETS

    def test_writes_a_manifest(self, spec: dict) -> None:
        assert spec["build"]["manifest"]


class TestMakefile:
    def test_cli_binary_is_phony_and_in_help(self) -> None:
        body = _makefile()
        phony = " ".join(
            line for line in body.splitlines() if line.startswith(".PHONY:")
        ).split()
        assert "cli-binary" in phony
        assert re.search(r'@echo\s+"\s*cli-binary\b', body)

    def test_pypackager_is_pinned_to_a_commit(self) -> None:
        """A tag can be moved; a commit can't."""
        assert re.search(
            r"^PYPACKAGER := .*git\+https://github\.com/jfudally/pypackager@[0-9a-f]{40} ",
            _makefile(),
            re.M,
        )

    def test_exports_the_lockfile_before_building(self) -> None:
        recipe = _recipe("cli-binary")
        export = recipe.index("uv export")
        build = recipe.index("$(PYPACKAGER) build")
        assert export < build
        assert "--frozen" in recipe and "--no-dev" in recipe
        assert "-o build/cli-requirements.txt" in recipe

    def test_builds_one_target_from_the_spec(self) -> None:
        recipe = _recipe("cli-binary")
        assert "-f packaging/wg-manager-cli.toml" in recipe
        assert "--target $(CLI_TARGET)" in recipe

    def test_smoke_runs_the_built_binary(self) -> None:
        assert "dist/wg-manager-$(CLI_TARGET) --help" in _recipe("cli-binary")

    def test_pex_cache_is_ignored_and_cleaned(self) -> None:
        assert ".pex-cache/" in (REPO_ROOT / ".gitignore").read_text().splitlines()
        assert ".pex-cache" in _recipe("clean")


class TestCI:
    def test_builds_every_target(self, job: dict) -> None:
        assert _matrix_targets(job) == TARGETS

    def test_each_target_builds_on_its_own_runner(self, job: dict) -> None:
        assert job["runs-on"] == "${{ matrix.runner }}"
        runners = [leg["runner"] for leg in job["strategy"]["matrix"]["include"]]
        assert len(set(runners)) == len(runners)

    def test_reports_every_target(self, job: dict) -> None:
        assert job["strategy"]["fail-fast"] is False

    def test_installs_python_313_for_pex(self, job: dict) -> None:
        (step,) = [s for s in job["steps"] if "actions/setup-python" in s.get("uses", "")]
        assert step["with"]["python-version"] == "3.13"

    def test_runs_make_cli_binary(self, job: dict) -> None:
        assert any(r.startswith("make cli-binary") for r in _runs(job))


class TestRelease:
    def test_builds_every_target(self, workflow: dict) -> None:
        job = workflow["jobs"]["build-cli"]
        assert _matrix_targets(job) == TARGETS
        assert any(r.startswith("make cli-binary") for r in _runs(job))

    def test_does_not_restore_a_cache(self, workflow: dict) -> None:
        """A release builds from scratch: a cache written by a branch
        run must not feed a published artifact."""
        job = workflow["jobs"]["build-cli"]
        assert not any("actions/cache" in s.get("uses", "") for s in job["steps"])

    def test_images_wait_for_the_binaries(self, workflow: dict) -> None:
        """A CLI build failure must stop the release before anything is
        pushed to GHCR, or the release is half-shipped."""
        for name in ("build-and-push-api", "build-and-push-web"):
            assert "build-cli" in workflow["jobs"][name]["needs"]

    def test_release_attaches_binaries_and_checksums(self, workflow: dict) -> None:
        job = workflow["jobs"]["release"]
        assert "build-cli" in job["needs"]
        (create,) = [r for r in _runs(job) if "gh release create" in r]
        assert "./cli/wg-manager-*" in create
        assert "./cli/SHA256SUMS" in create
        assert any("sha256sum wg-manager-*" in r for r in _runs(job))

    def test_footer_lists_the_binaries(self) -> None:
        assert "### CLI binaries" in RELEASE_PATH.read_text()


def _build_step(job: dict) -> dict:
    (step,) = [s for s in job["steps"] if s.get("run", "").startswith("make cli-binary")]
    return step


class TestGithubApiAuth:
    """pex's scie builder (science) looks up the latest
    python-build-standalone release on api.github.com. Anonymous calls
    share the runner IP's 60/hour quota, and a 403 failed the first CI
    run. science reads a bearer token from this variable."""

    TOKEN_VAR = "SCIENCE_AUTH_API_GITHUB_COM_BEARER"

    def test_ci_build_authenticates(self, job: dict) -> None:
        assert _build_step(job)["env"][self.TOKEN_VAR] == "${{ secrets.GITHUB_TOKEN }}"

    def test_release_build_authenticates(self, workflow: dict) -> None:
        step = _build_step(workflow["jobs"]["build-cli"])
        assert step["env"][self.TOKEN_VAR] == "${{ secrets.GITHUB_TOKEN }}"

    def test_release_build_token_is_read_only(self, workflow: dict) -> None:
        """The workflow grants contents/packages write; the build runs
        third-party code (pypackager, pex, wheel builds) and needs none."""
        assert workflow["jobs"]["build-cli"]["permissions"] == {"contents": "read"}
