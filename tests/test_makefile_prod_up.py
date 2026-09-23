"""Tests for the ``make prod-up`` target's idempotent bootstrap guard.

``vault-init.json`` is authored on first ``make prod-up`` by the host
(so Docker doesn't silently mkdir it at the bind-mount target) but
rewritten by ``bootstrap-substrate`` on every subsequent run — at
which point the file is owned by the container's ``wgmanager`` user
(UID 1001), not the host operator. If the Makefile unconditionally
``touch``es + ``chmod``s the file, every re-run of ``prod-up`` after
the first blows up with ``touch: cannot touch 'vault-init.json':
Permission denied`` and the operator has to ``sudo chown`` before
they can try again.

Pinning the guard's shape here so a future refactor that drops the
``if [ ! -e ]`` conditional trips the test rather than the operator.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MAKEFILE_PATH = REPO_ROOT / "Makefile"


def _block_for_target(target: str) -> str:
    """Return the recipe lines between ``<target>:`` and the next
    top-level target line (i.e. the next non-indented, non-blank line
    that looks like ``name:``). Blank lines and comment lines inside
    the recipe are preserved."""
    body = MAKEFILE_PATH.read_text()
    in_block = False
    block_lines: list[str] = []
    for line in body.splitlines():
        if line.startswith(f"{target}:"):
            in_block = True
            continue
        if in_block:
            # A new target starts at column 0 with `name:` — stop there.
            if line and not line[0].isspace() and re.match(r"[A-Za-z0-9_.-]+:", line):
                break
            block_lines.append(line)
    return "\n".join(block_lines)


class TestProdUpVaultInitGuard:
    """The ``vault-init.json`` bootstrap step must be idempotent."""

    def test_target_declared(self) -> None:
        body = MAKEFILE_PATH.read_text()
        assert "prod-up:" in body, "Makefile must declare the prod-up target"

    def test_touch_is_guarded_on_file_absence(self) -> None:
        """The touch must live inside an ``if [ ! -e vault-init.json ]``
        (or equivalent absence check) so re-runs skip it when the file
        is already container-owned."""
        block = _block_for_target("prod-up")
        # Locate the touch line and the guard that dominates it.
        assert "touch vault-init.json" in block, (
            f"prod-up must still touch vault-init.json on first run — "
            f"got:\n{block}"
        )
        # The guard: some form of "if file does not exist" ahead of touch.
        # Accepts `[ ! -e vault-init.json ]`, `[ ! -f vault-init.json ]`,
        # or the `test` equivalents.
        guard_patterns = [
            r"\[\s*!\s+-e\s+vault-init\.json\s*\]",
            r"\[\s*!\s+-f\s+vault-init\.json\s*\]",
            r"test\s+!\s+-e\s+vault-init\.json",
            r"test\s+!\s+-f\s+vault-init\.json",
        ]
        assert any(re.search(p, block) for p in guard_patterns), (
            "prod-up must guard the vault-init.json touch behind an "
            "'if [ ! -e vault-init.json ]' (or -f, or `test !`) check "
            "so re-runs don't fail with EPERM when bootstrap-substrate "
            f"has re-authored the file as UID 1001 — got:\n{block}"
        )

    def test_chmod_is_inside_the_same_guard(self) -> None:
        """chmod 0600 must also be gated by the absence check — otherwise
        the second-run failure just shifts from touch to chmod."""
        block = _block_for_target("prod-up")
        assert "chmod 0600 vault-init.json" in block or "chmod 600 vault-init.json" in block, (
            f"prod-up must still chmod vault-init.json to 0600 on first "
            f"run — got:\n{block}"
        )
        # A crude but reliable check: the chmod line must appear
        # *after* the guard's opening `if` and *before* its closing
        # `fi`. We flatten to a single string and require the chmod
        # to sit between the two.
        guard_open = re.search(
            r"if\s+\[\s*!\s+-[ef]\s+vault-init\.json\s*\]\s*;\s*then",
            block,
        )
        guard_close = block.find("fi", guard_open.end() if guard_open else 0)
        assert guard_open is not None and guard_close != -1, (
            "expected a well-formed `if [ ! -e vault-init.json ]; then "
            f"... fi` around the touch/chmod — got:\n{block}"
        )
        chmod_pos = block.find("chmod", guard_open.end())
        assert 0 < chmod_pos < guard_close, (
            "chmod 0600 vault-init.json must live inside the same "
            "absence guard as the touch, so re-runs skip both — got:\n"
            f"{block}"
        )

    def test_compose_up_still_runs(self) -> None:
        """The guard change must not accidentally drop the compose call."""
        block = _block_for_target("prod-up")
        assert "up -d --build --wait" in block, (
            f"prod-up must still invoke `up -d --build --wait` — got:\n{block}"
        )
