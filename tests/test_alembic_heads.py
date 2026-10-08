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


# Alembic's ``alembic_version.version_num`` is ``VARCHAR(32)``. On MySQL a
# longer id fails *after* the migration's DDL has auto-committed, so the
# schema changes but the version doesn't, and every retry then fails on
# the half-applied change. SQLite ignores VARCHAR lengths, so only this
# test catches it in CI. ``0022_enrollment_token_source_binding`` (36)
# broke ``make prod-up`` on v0.9.0 and v0.10.0 this way.
_VERSION_NUM_MAX = 32


def test_revision_ids_fit_alembic_version_column() -> None:
    too_long = sorted(
        (len(s.revision), s.revision)
        for s in _script().walk_revisions()
        if len(s.revision) > _VERSION_NUM_MAX
    )
    assert too_long == [], (
        f"Revision ids longer than {_VERSION_NUM_MAX} characters don't fit "
        f"alembic_version.version_num on MySQL: {too_long}. Shorten the id "
        "and the file name together."
    )
