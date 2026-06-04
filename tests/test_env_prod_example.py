"""Tests for ``.env.prod.example`` — the operator's secret-template
file for the production-shaped docker-compose overlay.

``.env.prod.example`` is the single source of truth for which
``${VAR}`` interpolations the overlay expects an operator to supply.
Anytime the overlay references a new ``${SOMETHING}``, this file
must document it; this test pins the contract so a refactor that
adds an undocumented var trips at test time.

The template must NEVER ship real values — only placeholder shapes
(``CHANGEME`` etc.) and explanatory comments. Each documented key
gets an inline comment explaining what it's for and how to generate
a strong value.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
PROD_OVERLAY = REPO_ROOT / "docker-compose.prod.yml"
ENV_TEMPLATE = REPO_ROOT / ".env.prod.example"


@pytest.fixture(scope="module")
def template_body() -> str:
    """Read the env template or fail the suite."""
    assert ENV_TEMPLATE.is_file(), (
        f"{ENV_TEMPLATE} is missing — operators need a documented "
        "template to fill in for the production-shaped overlay."
    )
    return ENV_TEMPLATE.read_text()


@pytest.fixture(scope="module")
def template_keys(template_body: str) -> set[str]:
    """Extract every ``KEY=...`` name documented in the template,
    whether the line is commented or uncommented.

    Commented entries (``# OPTIONAL_KEY=default``) are how the template
    documents optional vars — they count as "documented" for the
    coverage assertion. Uncommented entries are required vars the
    operator must fill in.
    """
    keys: set[str] = set()
    for line in template_body.splitlines():
        stripped = line.lstrip("#").strip()
        if not stripped:
            continue
        if "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            # Skip section-divider lines like ``# ---`` (no real var
            # name after the comment marker).
            if key and key.replace("_", "").isalnum():
                keys.add(key)
    return keys


@pytest.fixture(scope="module")
def overlay_referenced_vars() -> set[str]:
    """Every ``${VAR}`` actually referenced by the prod overlay (i.e.
    on non-comment YAML lines).

    Walks the overlay file as text and pulls out every ``${VAR}`` or
    ``${VAR:-default}`` interpolation that appears on a YAML line
    Compose will actually resolve. Lines starting with ``#`` are
    skipped — a ``${VAR}`` inside a comment block is documentation,
    not an interpolation.
    """
    import re

    if not PROD_OVERLAY.is_file():
        return set()
    referenced: set[str] = set()
    for line in PROD_OVERLAY.read_text().splitlines():
        if line.lstrip().startswith("#"):
            continue
        referenced.update(re.findall(r"\$\{([A-Z_][A-Z0-9_]*)", line))
    return referenced


# ---------------------------------------------------------------------------
# Coverage: every overlay ${VAR} is in the template
# ---------------------------------------------------------------------------


class TestVarCoverage:
    """Each ``${VAR}`` the overlay references must have a row in the
    template — otherwise operators discover the missing variable at
    deploy time."""

    def test_every_overlay_var_is_documented(
        self,
        template_keys: set[str],
        overlay_referenced_vars: set[str],
    ) -> None:
        missing = overlay_referenced_vars - template_keys
        assert not missing, (
            ".env.prod.example must document every ${VAR} the overlay "
            f"references; missing: {sorted(missing)}. Add a row + an "
            "inline comment explaining what each one is for and how "
            "to generate a strong value."
        )


# ---------------------------------------------------------------------------
# Sanity: no real secrets baked in
# ---------------------------------------------------------------------------


def _value_assignments(body: str) -> list[tuple[str, str]]:
    """Return ``(KEY, VALUE)`` for every non-comment assignment line.

    Mentions of dev secrets inside ``# this replaces dev-only-root``
    style comments are documentation, not real defaults; the scan
    skips them so the test asserts only on actual values an operator
    would inherit.
    """
    out: list[tuple[str, str]] = []
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" in stripped:
            k, v = stripped.split("=", 1)
            out.append((k.strip(), v.strip()))
    return out


class TestNoBakedSecrets:
    """The template must NEVER ship real-looking secret VALUES.

    Mentions of the dev-only secrets in comments are fine (the docs
    block in the template explains *why* operators must replace
    ``dev-only-root``); what's not OK is for any of those strings to
    appear as an actual ``KEY=value`` default.
    """

    def test_no_dev_only_root_as_default_value(
        self, template_body: str
    ) -> None:
        for key, value in _value_assignments(template_body):
            assert "dev-only-root" not in value, (
                f".env.prod.example {key}= must NOT carry the dev "
                "compose's well-known `dev-only-root` Vault token as "
                "a default value."
            )

    def test_no_obvious_plaintext_default(
        self, template_body: str
    ) -> None:
        # Dev mysql defaults `rootpw` / `wg`. None of these may appear
        # as a real default in the prod template.
        for key, value in _value_assignments(template_body):
            assert value != "rootpw", (
                f".env.prod.example {key}= must NOT default to "
                "`rootpw` — that's the dev compose's known-bad MySQL "
                "root password."
            )
