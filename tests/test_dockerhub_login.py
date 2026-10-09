"""CI jobs that pull from Docker Hub log in first, when credentials exist.

Docker Hub rate-limits anonymous pulls per IP, and GitHub's hosted
runners share IPs, so a busy hour fails builds that pull ``python``,
``node`` or ``prom/prometheus`` with ``429 Too Many Requests``. That
blocked the v0.11.4 release PR on 2026-10-09. An authenticated pull
gets its own, much higher, quota.

The login is optional: ``DOCKERHUB_USERNAME`` (repo variable) and
``DOCKERHUB_TOKEN`` (secret) unset, e.g. on forks or Dependabot PRs,
means the step is skipped and the job pulls anonymously as before.
Secrets can't appear in a step's ``if:``, so each job exposes only a
``'true'``/``'false'`` flag, never the token, as ``HAS_DOCKERHUB_LOGIN``.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"

# (workflow file, job id, `uses:` / `run:` substring of the first step that pulls)
PULLING_JOBS = [
    ("ci.yml", "alerts", "make alerts-check"),
    ("image-build.yml", "api-image", "docker/build-push-action"),
    ("image-build.yml", "web-image", "docker/build-push-action"),
    ("release.yml", "build-and-push-api", "docker/build-push-action"),
    ("release.yml", "build-and-push-web", "docker/build-push-action"),
]

FLAG = "${{ vars.DOCKERHUB_USERNAME != '' && secrets.DOCKERHUB_TOKEN != '' }}"


def _job(workflow: str, job: str) -> dict:
    doc = yaml.safe_load((WORKFLOWS / workflow).read_text())
    return doc["jobs"][job]


def _dockerhub_login_index(steps: list[dict]) -> int:
    """Index of the docker/login-action step with no `registry` (Docker Hub)."""
    hits = [
        i
        for i, s in enumerate(steps)
        if str(s.get("uses", "")).startswith("docker/login-action@")
        and "registry" not in (s.get("with") or {})
    ]
    assert len(hits) == 1, f"expected one Docker Hub login step, got {hits}"
    return hits[0]


@pytest.mark.parametrize(("workflow", "job", "pull_marker"), PULLING_JOBS)
def test_logs_in_to_docker_hub_before_pulling(
    workflow: str, job: str, pull_marker: str
) -> None:
    steps = _job(workflow, job)["steps"]
    login = _dockerhub_login_index(steps)
    pulls = [
        i
        for i, s in enumerate(steps)
        if pull_marker in str(s.get("uses", "")) + str(s.get("run", ""))
    ]
    assert pulls, f"no step matching {pull_marker!r} in {workflow}:{job}"
    assert login < pulls[0], f"{workflow}:{job} logs in after it pulls"


@pytest.mark.parametrize(("workflow", "job", "pull_marker"), PULLING_JOBS)
def test_login_uses_the_token_and_is_optional(
    workflow: str, job: str, pull_marker: str
) -> None:
    job_def = _job(workflow, job)
    step = job_def["steps"][_dockerhub_login_index(job_def["steps"])]
    assert step["with"]["username"] == "${{ vars.DOCKERHUB_USERNAME }}"
    assert step["with"]["password"] == "${{ secrets.DOCKERHUB_TOKEN }}"
    assert step["if"] == "env.HAS_DOCKERHUB_LOGIN == 'true'"
    # Only the boolean reaches the job's environment, never the token.
    assert job_def["env"]["HAS_DOCKERHUB_LOGIN"] == FLAG
    others = {k: v for k, v in job_def["env"].items() if k != "HAS_DOCKERHUB_LOGIN"}
    assert not any("DOCKERHUB_TOKEN" in str(v) for v in others.values()), others
