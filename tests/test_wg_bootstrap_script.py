"""Shape tests for ``scripts/wg_bootstrap.sh`` — the VPN-first node bootstrap.

This script replaces the deleted ``wg_node`` Cinc cookbook. The old flow
brought a node onto the VPN *by converging a cookbook*, which forced the
Cinc server to be reachable before the node had any VPN connectivity (i.e.
public-facing). The new flow flips the order: the script first joins the
node to the VPN by calling the wg_manager API directly, then bootstraps
Cinc **over the now-up VPN**, so the Cinc server can stay VPN-only.

These are shape-only tests in the style of
``tests/test_prod_bootstrap_scripts.py``: they assert the script is
present, executable, and wires together the expected sub-commands so a
future edit that drops (say) the ``wg-quick down`` reprovision-safety
teardown or the ``knife bootstrap`` call breaks at test time rather than
silently shipping a half-working bootstrap. Live execution lives in the
operator's manual end-to-end smoke against a real node.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "wg_bootstrap.sh"


@pytest.fixture(scope="module")
def body() -> str:
    assert SCRIPT.is_file(), (
        f"{SCRIPT} is missing — the VPN-first node bootstrap has nothing "
        "to exec. It replaces the removed cookbooks/wg_node cookbook."
    )
    return SCRIPT.read_text()


def _is_executable(path: Path) -> bool:
    """Owner-executable bit is set."""
    return bool(os.stat(path).st_mode & stat.S_IXUSR)


class TestScriptPresence:
    def test_script_present_and_executable(self) -> None:
        assert SCRIPT.is_file(), f"{SCRIPT} is missing"
        assert _is_executable(SCRIPT), (
            f"{SCRIPT} is not owner-executable — operators invoke it directly."
        )

    def test_fails_loud(self, body: str) -> None:
        # Fail-loud per the project's standards: an unset var or a failed
        # pipeline stage must abort rather than press on with bad state.
        assert "set -euo pipefail" in body


class TestSubcommands:
    """The script is multipurpose: vpn, cinc, and all."""

    @pytest.mark.parametrize("sub", ["vpn", "cinc", "all"])
    def test_usage_lists_subcommand(self, body: str, sub: str) -> None:
        # The usage/help text must advertise every subcommand so an
        # operator can discover them without reading the source.
        assert sub in body, f"subcommand {sub!r} not referenced in the script"


class TestVpnPhase:
    """The vpn phase joins the node to the WireGuard VPN via the API."""

    def test_calls_manual_client_endpoint(self, body: str) -> None:
        # Reuses the existing control-plane contract: POST /<ver>/clients/manual
        # returns the full wg0.conf (private key inline, once).
        assert "clients/manual" in body

    def test_writes_wg_config(self, body: str) -> None:
        assert "wg0.conf" in body

    def test_brings_tunnel_up_with_wg_quick(self, body: str) -> None:
        assert "wg-quick" in body

    def test_tears_down_running_interface_before_rewrite(self, body: str) -> None:
        # Reprovision-safety: a running wg0 must be torn down before a new
        # client config is written, or a stale interface lingers. See the
        # project memory on reprovision wg checks.
        assert "wg-quick down" in body

    def test_config_not_delivered_via_bash_dash_s_stdin_collision(
        self, body: str
    ) -> None:
        # Regression (2026-06-19): the wg0.conf was delivered by piping
        # ``$wg_config`` into ``ssh ... 'bash -s' <<'REMOTE'``. A heredoc and a
        # pipe both claim the command's stdin; the heredoc wins, so ``bash -s``
        # consumed the REMOTE *script* as its stdin and the remote ``cat >
        # wg0.conf`` then read the *trailing script lines* instead of
        # ``$wg_config``. The node's wg0.conf ended up containing shell
        # commands (``chmod 600 ...``), wg-quick failed with "Line
        # unrecognized", and the tunnel never came up.
        #
        # The remote script body must NOT be fed to ``bash -s`` on stdin while
        # ``$wg_config`` is also piped in — those two channels collide. Deliver
        # the script body as a ``bash -c`` argument so stdin is free for the
        # config.
        assert "bash -s" not in body, (
            "remote script fed to 'bash -s' on stdin collides with the "
            "wg_config piped on the same stdin — use 'bash -c <body>' so the "
            "config can be read from stdin by the remote cat"
        )

    def test_config_piped_to_remote_for_cat(self, body: str) -> None:
        # The rendered config (carrying the node's private key inline) must
        # reach the node's ``cat > wg0.conf`` on stdin — keep it off argv and
        # off any intermediate file.
        assert 'printf' in body and '"$wg_config"' in body
        assert 'cat > "/etc/wireguard/${iface}.conf"' in body


class TestCincPhase:
    """The cinc phase bootstraps the node into Cinc over the VPN."""

    def test_runs_knife_bootstrap(self, body: str) -> None:
        assert "knife bootstrap" in body
