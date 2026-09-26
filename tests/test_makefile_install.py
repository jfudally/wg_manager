"""Tests for ``make install`` on a fresh clone (no ``.venv`` yet).

``make install`` used to run ``uv pip install -e ".[dev]"``, which needs
an existing virtualenv, so on a fresh clone it failed with ``No virtual
environment found``. The pip fallback was broken the same way: it ran
``.venv/bin/python -m ensurepip``, and that interpreter doesn't exist
yet either.

These tests run the real recipe with ``make`` in a temporary directory
holding a copy of the Makefile and no ``.venv``. Stub ``uv`` /
``python3`` executables on ``PATH`` record how they're called, so
nothing is installed and no network is needed.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.skipif(shutil.which("make") is None, reason="needs make")


def _stub(path: Path, body: str) -> None:
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


@pytest.fixture()
def fresh_clone(tmp_path: Path) -> Path:
    """A directory with the Makefile and no ``.venv``, like a new clone."""
    shutil.copy(REPO_ROOT / "Makefile", tmp_path / "Makefile")
    return tmp_path


def _make_install(cwd: Path, bindir: Path) -> subprocess.CompletedProcess[str]:
    # Only the stubs plus the system dirs make and sh live in, so a real
    # uv (usually in ~/.local/bin or ~/.cargo/bin) can't leak in.
    path = os.pathsep.join([str(bindir), "/usr/bin", "/bin"])
    return subprocess.run(
        ["make", "install"],
        cwd=cwd,
        env={"PATH": path, "HOME": str(cwd)},
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_with_uv_syncs_the_locked_dev_environment(fresh_clone: Path) -> None:
    """Same command as CI: creates .venv and installs the uv.lock pins."""
    bindir = fresh_clone / "bin"
    bindir.mkdir()
    log = fresh_clone / "uv.log"
    _stub(bindir / "uv", f'echo "$@" >> {log}\n')

    result = _make_install(fresh_clone, bindir)

    assert result.returncode == 0, result.stdout + result.stderr
    assert log.read_text().splitlines() == ["sync --extra dev --frozen"]


def test_without_uv_creates_the_venv_before_using_it(fresh_clone: Path) -> None:
    if any((Path(d) / "uv").exists() for d in ("/usr/bin", "/bin")):
        pytest.skip("a system-wide uv would shadow the fallback path")
    bindir = fresh_clone / "bin"
    bindir.mkdir()
    log = fresh_clone / "py.log"
    # The stub python3 records its args and, for `-m venv DIR`, creates
    # DIR/bin/python as another recording stub, like the real thing.
    venv_python = (
        '#!/bin/sh\\necho "venv-python $@" >> ' + str(log) + "\\n"
    )
    _stub(
        bindir / "python3",
        f'echo "python3 $@" >> {log}\n'
        'if [ "$1" = "-m" ] && [ "$2" = "venv" ]; then\n'
        '  mkdir -p "$3/bin"\n'
        f'  printf \'{venv_python}\' > "$3/bin/python"\n'
        '  chmod +x "$3/bin/python"\n'
        "fi\n",
    )

    result = _make_install(fresh_clone, bindir)

    assert result.returncode == 0, result.stdout + result.stderr
    calls = log.read_text().splitlines()
    assert calls[0] == "python3 -m venv .venv"
    assert calls[-1] == 'venv-python -m pip install -e .[dev]'


def test_without_uv_reuses_an_existing_venv(fresh_clone: Path) -> None:
    if any((Path(d) / "uv").exists() for d in ("/usr/bin", "/bin")):
        pytest.skip("a system-wide uv would shadow the fallback path")
    bindir = fresh_clone / "bin"
    bindir.mkdir()
    log = fresh_clone / "py.log"
    _stub(bindir / "python3", f'echo "python3 $@" >> {log}\n')
    (fresh_clone / ".venv" / "bin").mkdir(parents=True)
    _stub(fresh_clone / ".venv" / "bin" / "python", f'echo "venv-python $@" >> {log}\n')

    result = _make_install(fresh_clone, bindir)

    assert result.returncode == 0, result.stdout + result.stderr
    assert log.read_text().splitlines() == ["venv-python -m pip install -e .[dev]"]
