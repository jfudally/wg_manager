"""Guard: the Alembic migration chain has exactly one head.

Two branches that each add "the next" migration (both ``0020_*`` on top
of ``0019``) merge without a textual conflict but leave two heads, and
then ``alembic upgrade head``, which ``make prod-up`` runs via
bootstrap-app, refuses to run. This happened reviving the enrollment
token-admin branch onto a ``main`` that had gained its own 0020.

The test fails with the competing heads named, so the fix (renumber one
and re-point its ``down_revision``) is obvious.
"""

from __future__ import annotations

from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory

REPO_ROOT = Path(__file__).resolve().parents[1]


def _script() -> ScriptDirectory:
    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    return ScriptDirectory.from_config(cfg)


def test_single_head() -> None:
    heads = _script().get_heads()
    assert len(heads) == 1, (
        f"Alembic has {len(heads)} heads: {sorted(heads)}. Renumber the newer "
        "migration and point its down_revision at the other head."
    )


def test_file_prefix_matches_revision() -> None:
    # Files are named NNNN_<revision-suffix>.py and the revision id repeats
    # the file stem, so a renumber must change both.
    for script in _script().walk_revisions():
        stem = Path(script.path).stem
        assert stem == script.revision, (script.path, script.revision)
