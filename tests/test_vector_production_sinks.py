"""Config-shape tests for Phase 2e audit-log cycle 3.

Cycle 3 closes the Vault-audit work-stream by documenting the
production off-host shipping options. Each shipping option lands as a
self-contained vector config under ``docker/vector/production/`` so
an operator can ``vector validate`` the file standalone before
swapping it into a deployment. These tests pin the per-file
contract — file source pointing at the audit log written by cycle 1's
file audit device, exactly one production sink of the expected type,
no sink writing back into the audit volume — so the docs and the
configs cannot drift.

The configs are dev-mode operator examples, not part of the dev
compose stack (the dev stack uses the cycle 2 ``vault-audit.toml``
console sink). Production deployments either replace or *join* the
console sink with one of these production options; the choice
depends on the operator's existing log fabric.

The test bucket is intentionally pure parse-and-assert: no AWS
account, Loki endpoint, or syslog daemon is required to run them,
which keeps the fast ``make test`` invocation hermetic. Live
end-to-end shipping is the operator's responsibility against their
own infrastructure; the cookbook walks the smoke flow per sink.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_DIR = REPO_ROOT / "docker" / "vector" / "production"

#: Per-config contract. Maps the filename under ``docker/vector/production/``
#: to the expected vector sink ``type`` field. Centralised here so a new
#: sink option lands by adding one row to this table plus the config
#: file itself — the parametrised tests pick the new row up
#: automatically.
EXPECTED_SINK_TYPE: dict[str, str] = {
    "loki.toml": "loki",
    "cloudwatch.toml": "aws_cloudwatch_logs",
    "s3-object-lock.toml": "aws_s3",
    "syslog.toml": "socket",
}


@pytest.fixture(scope="module", params=sorted(EXPECTED_SINK_TYPE))
def production_config(request: pytest.FixtureRequest) -> tuple[str, dict]:
    """Yield ``(filename, parsed_toml)`` for every production config.

    Module-scoped + parametrised: each config file is parsed once and
    every contract assertion runs against it, so adding a new sink
    option is a one-line extension to ``EXPECTED_SINK_TYPE``.
    """
    filename: str = request.param
    path = PRODUCTION_DIR / filename
    return filename, tomllib.loads(path.read_text())


class TestProductionConfigShape:
    """Contract every production config must satisfy.

    A production sink that drifts from this contract is an audit-gap
    waiting to happen — wrong source path means the config tails the
    wrong file (or nothing at all), wrong sink type means the docs
    diverge from the artefact, and a write-back path means the
    sidecar can corrupt the trail it's shipping. Pinning these four
    invariants per file keeps the production drift surface bounded.
    """

    def test_file_exists(self, production_config: tuple[str, dict]) -> None:
        """Config file is on disk under ``docker/vector/production/``."""
        filename, parsed = production_config
        # If tomllib.loads succeeded the file exists; the assertion
        # below documents the contract for a future reader scanning
        # this class in isolation.
        assert parsed, f"{filename} parsed empty"

    def test_has_file_source_at_audit_log(
        self, production_config: tuple[str, dict]
    ) -> None:
        """A ``file``-type source includes ``/vault/logs/audit.log``."""
        filename, parsed = production_config
        sources = parsed.get("sources", {})
        assert "vault_audit" in sources, (
            f"{filename}: expected a [sources.vault_audit] section, "
            f"found {list(sources)!r}"
        )
        src = sources["vault_audit"]
        assert src["type"] == "file", (
            f"{filename}: vault_audit source must be type=file, "
            f"got {src['type']!r}"
        )
        assert "/vault/logs/audit.log" in src["include"], (
            f"{filename}: file source must tail /vault/logs/audit.log, "
            f"includes={src['include']!r}"
        )

    def test_has_exactly_one_production_sink_of_expected_type(
        self, production_config: tuple[str, dict]
    ) -> None:
        """Exactly one sink of the expected type per file.

        Multiple sinks of the same type duplicate every record on the
        wire; zero sinks of the expected type means the file is
        misnamed. Each production file is one canonical option.
        """
        filename, parsed = production_config
        expected_type = EXPECTED_SINK_TYPE[filename]
        sinks = parsed.get("sinks", {})
        matching = [
            (name, defn)
            for name, defn in sinks.items()
            if defn.get("type") == expected_type
        ]
        assert len(matching) == 1, (
            f"{filename}: expected exactly one sink of type "
            f"{expected_type!r}, found {len(matching)}: "
            f"{[name for name, _ in matching]!r}"
        )

    def test_production_sink_inputs_reach_audit_source(
        self, production_config: tuple[str, dict]
    ) -> None:
        """Production sink's inputs trace back to the file source.

        Inputs may reference the file source directly or route through
        one or more transforms (Loki configs typically parse JSON for
        label extraction, S3 / syslog typically don't). Walk the
        transform graph back to vault_audit either way.
        """
        filename, parsed = production_config
        expected_type = EXPECTED_SINK_TYPE[filename]
        sink = next(
            defn
            for defn in parsed["sinks"].values()
            if defn.get("type") == expected_type
        )
        transforms = parsed.get("transforms", {})
        inputs = list(sink["inputs"])
        seen: set[str] = set()
        while inputs:
            name = inputs.pop()
            if name in seen:
                continue
            seen.add(name)
            if name == "vault_audit":
                return
            if name in transforms:
                inputs.extend(transforms[name].get("inputs", []))
        pytest.fail(
            f"{filename}: sink inputs {sink['inputs']!r} don't trace "
            f"back to the vault_audit file source (transforms walked: "
            f"{sorted(seen)!r})"
        )

    def test_no_sink_writes_into_audit_volume(
        self, production_config: tuple[str, dict]
    ) -> None:
        """No sink path lands inside ``/vault/logs/``.

        Belt-and-braces guard on top of the kernel-level ``:ro``
        mount: a config-level write into the audit volume would be
        rejected at runtime, but the test pins the operator-facing
        intent so a future reader reviewing the production examples
        can't be misled into thinking vector round-trips into the
        audit dir.
        """
        filename, parsed = production_config
        for name, sink in parsed.get("sinks", {}).items():
            for field in ("path", "key_prefix", "filename"):
                value = sink.get(field, "")
                if isinstance(value, str):
                    assert "/vault/logs" not in value, (
                        f"{filename}: sink {name!r} {field}={value!r} "
                        "writes into the audit volume; the volume is "
                        "read-only and a production sink must ship "
                        "off-host"
                    )


class TestProductionDirectory:
    """Cross-file invariants for the production examples directory."""

    def test_every_expected_file_present(self) -> None:
        """``docker/vector/production/`` contains every documented file.

        The cookbook §6 cycle 3 section walks the operator through one
        sink at a time and links each subsection to the matching file
        under this directory. A missing file would land an operator on
        a 404 mid-runbook — worst possible UX for a security
        configuration step.
        """
        for filename in EXPECTED_SINK_TYPE:
            assert (PRODUCTION_DIR / filename).is_file(), (
                f"missing production sink config: "
                f"docker/vector/production/{filename}"
            )

    def test_no_unexpected_toml_files(self) -> None:
        """The directory contains only the four documented configs.

        Guards against silent drift: a new sink option that lands as
        a TOML file but doesn't get added to ``EXPECTED_SINK_TYPE``
        wouldn't be covered by the per-file contract tests. The
        contract is "every TOML under production/ has a row in the
        table"; this test pins the other direction.
        """
        if not PRODUCTION_DIR.is_dir():
            return  # the per-file test will fail first if directory is missing
        actual = {p.name for p in PRODUCTION_DIR.glob("*.toml")}
        expected = set(EXPECTED_SINK_TYPE)
        assert actual == expected, (
            f"production/ contents drift: extra={actual - expected!r}, "
            f"missing={expected - actual!r}"
        )
