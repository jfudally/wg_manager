"""Tests for ``scripts/extract_changelog.py`` (Phase 2f cycle 2).

The release workflow tags an image with ``v<X.Y.Z>`` and creates a
GitHub release whose body is the matching ``## [vX.Y.Z]`` section of
``CHANGELOG.md``. The extractor is the small helper that walks the
file and returns the right slice. Pinning its behaviour here keeps
the release flow honest — a future refactor that breaks the regex
trips the test before it ships a release with wrong / empty notes.

The extractor is also runnable as a CLI so an operator can preview
locally with ``python scripts/extract_changelog.py v0.1.0``.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "extract_changelog.py"


def _load_extract():
    """Import ``scripts/extract_changelog.py`` as a module by path.

    The script lives outside ``src/`` (it's an operator helper, not
    library code) so we can't ``from wg_manager.scripts import …``.
    Load it by file path the way the conftest fixtures elsewhere do.
    """
    spec = importlib.util.spec_from_file_location("extract_changelog", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def changelog_sample() -> str:
    """A minimal Keep-a-Changelog-shaped fixture covering the cases the
    extractor must handle: an ``Unreleased`` section above versioned
    ones, multiple versioned sections, ``###`` subheadings inside a
    section."""
    return """# Changelog

All notable changes to wg-manager.

## [Unreleased]

### Added

- Some unreleased work.

## [v0.2.0] - 2026-07-01

### Added

- Cycle X feature.

### Fixed

- Latent bug.

## [v0.1.0] - 2026-06-15

### Added

- First release.
"""


class TestScriptExists:
    def test_script_file_exists(self) -> None:
        assert SCRIPT_PATH.is_file(), (
            f"{SCRIPT_PATH} is missing — Phase 2f cycle 2 ships the "
            "extractor"
        )


class TestExtractsMatchingSection:
    def test_extracts_v0_2_0(self, changelog_sample: str) -> None:
        ext = _load_extract()
        body = ext.extract_section(changelog_sample, "v0.2.0")
        assert "Cycle X feature." in body
        assert "Latent bug." in body
        # The heading itself must not be in the output.
        assert "## [v0.2.0]" not in body
        # The next section's content must not leak in.
        assert "First release." not in body

    def test_extracts_oldest_section(self, changelog_sample: str) -> None:
        """Tail-of-file section: no `## ` follows, so the regex needs
        an end-of-string anchor."""
        ext = _load_extract()
        body = ext.extract_section(changelog_sample, "v0.1.0")
        assert "First release." in body
        assert "## [v0.1.0]" not in body
        assert "Cycle X feature." not in body


class TestVersionPrefixHandling:
    def test_accepts_v_prefixed(self, changelog_sample: str) -> None:
        """``v0.1.0`` and ``0.1.0`` both work — operators type either."""
        ext = _load_extract()
        body = ext.extract_section(changelog_sample, "v0.1.0")
        assert "First release." in body

    def test_accepts_bare(self, changelog_sample: str) -> None:
        ext = _load_extract()
        body = ext.extract_section(changelog_sample, "0.1.0")
        assert "First release." in body


class TestMissingVersionFails:
    def test_unknown_version_raises_or_returns_none(
        self, changelog_sample: str
    ) -> None:
        """A version not in the file is the most common failure mode —
        the extractor must surface it loudly, not return ``None`` for
        the workflow to pass into ``gh release create`` and produce an
        empty body."""
        ext = _load_extract()
        with pytest.raises(LookupError):
            ext.extract_section(changelog_sample, "v9.9.9")


class TestCliEntrypoint:
    """The CLI form is what the workflow shells out to. Pin that
    ``python scripts/extract_changelog.py vX.Y.Z`` exits 0 on a known
    version and prints the body."""

    def test_cli_prints_extracted_body(self, tmp_path: Path) -> None:
        # Run against the real repo CHANGELOG so we don't depend on a
        # fixture file existing on disk. The repo's CHANGELOG always
        # has ``## [Unreleased]`` so use that.
        # Build a minimal fixture to feed the script via cwd switch.
        cwd = tmp_path
        (cwd / "CHANGELOG.md").write_text(
            "## [Unreleased]\n\n- pending\n\n## [v0.1.0] - 2026-06-15\n\n- first\n"
        )
        result = subprocess.run(  # noqa: S603
            [sys.executable, str(SCRIPT_PATH), "v0.1.0"],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert "first" in result.stdout
        assert "pending" not in result.stdout

    def test_cli_exits_nonzero_on_unknown_version(self, tmp_path: Path) -> None:
        (tmp_path / "CHANGELOG.md").write_text(
            "## [Unreleased]\n\n## [v0.1.0]\n\n- first\n"
        )
        result = subprocess.run(  # noqa: S603
            [sys.executable, str(SCRIPT_PATH), "v9.9.9"],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode != 0
        assert "v9.9.9" in (result.stderr + result.stdout)
