"""Behaviour tests for ``scripts/enroll_node.sh`` (Phase 3f userdata script).

The script is meant to run unattended from cloud-init on a fresh host.
These tests actually run it, under a temporary filesystem root
(``WGM_ROOT``) and with ``curl`` / ``wg`` / ``systemctl`` and friends
replaced by recording stubs on ``PATH``. That checks what it writes,
with which permissions, and what it sends, not just that certain
strings appear in the source.

Security properties checked here:

* the token never appears on a command line (it goes to curl via a
  header file, so it isn't visible in ``ps``),
* the WireGuard private key is generated locally, kept at 0600, and
  never sent,
* the sshd drop-in matches the one the worker installs
  (:data:`wg_manager.host_ssh._SSHD_DROPIN_TEMPLATE`), so an enrolled
  host and an SSH-bootstrapped host end up configured identically.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import textwrap
from pathlib import Path

import pytest

from wg_manager.host_ssh import (
    _SSHD_DROPIN_TEMPLATE,
    HOST_CA_PUB_PATH,
    HOST_CERT_PATH,
    SSHD_DROPIN_PATH,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "enroll_node.sh"

TOKEN = "wgmenr_TESTTOKENvalue-123"
FAKE_PRIV = "cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5MTI="
FAKE_PUB = "cHVibGlja2V5cHVibGlja2V5cHVibGlja2V5cHViMTI="
HOST_PUB = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeHostKeyFakeHostKeyFakeHostKey0 root@web-01"

RESPONSE = {
    "client_id": 7,
    "name": "web-web-01",
    "address": "10.9.0.2/32",
    "wg_config": (
        "[Interface]\nAddress = 10.9.0.2/32\n"
        "PostUp = wg set %i private-key /etc/wireguard/privatekey\n\n"
        "[Peer]\nPublicKey = HUB=\nEndpoint = hub:51820\n"
        "AllowedIPs = 10.9.0.0/24\nPersistentKeepalive = 25\n"
    ),
    "ssh_username": "wgmgr",
    "user_ca_public_key": "ssh-ed25519 AAAAUSERCA ca",
    "host_certificate": "ssh-ed25519-cert-v01@openssh.com AAAAHOSTCERT",
    "host_cert_principals": ["10.9.0.2"],
    "task_id": "t1",
}

# Stub bodies. Each records its argv to $FAKE_LOG/<name>.log (one line
# per call) so tests can assert what the script invoked.
_RECORD = 'printf "%s\\n" "$*" >> "$FAKE_LOG/$(basename "$0").log"'

_STUBS = {
    "curl": textwrap.dedent(f"""\
        #!/usr/bin/env bash
        {_RECORD}
        out=""; code_fmt=""
        while [[ $# -gt 0 ]]; do
          case "$1" in
            -H) [[ "$2" == @* ]] && cat "${{2#@}}" >> "$FAKE_LOG/curl.headers"; shift 2 ;;
            --data-binary) [[ "$2" == @* ]] && cp "${{2#@}}" "$FAKE_LOG/curl.body"; shift 2 ;;
            -o) out="$2"; shift 2 ;;
            -w) code_fmt="$2"; shift 2 ;;
            *) shift ;;
          esac
        done
        n=$(cat "$FAKE_LOG/curl.count" 2>/dev/null || echo 0)
        n=$((n+1))
        echo "$n" > "$FAKE_LOG/curl.count"
        read -r -a codes <<< "$FAKE_HTTP_CODES"
        idx=$(( n <= ${{#codes[@]}} ? n-1 : ${{#codes[@]}}-1 ))
        code="${{codes[$idx]}}"
        if [[ "$code" == 201 ]]; then
          cp "$FAKE_RESPONSE" "$out"
        else
          echo '{{"detail":"nope"}}' > "$out"
        fi
        [[ -n "$code_fmt" ]] && printf '%s' "$code"
        exit 0
        """),
    "wg": textwrap.dedent(f"""\
        #!/usr/bin/env bash
        {_RECORD}
        case "$1" in
          genkey) echo "{FAKE_PRIV}" ;;
          pubkey) cat >/dev/null; echo "{FAKE_PUB}" ;;
        esac
        """),
    "id": textwrap.dedent(f"""\
        #!/usr/bin/env bash
        {_RECORD}
        [[ -z "${{FAKE_NO_USER:-}}" ]]
        """),
    "hostname": "#!/usr/bin/env bash\necho Web-01\n",
    "ssh-keygen": textwrap.dedent(f"""\
        #!/usr/bin/env bash
        {_RECORD}
        mkdir -p "$WGM_ROOT/etc/ssh"
        echo "{HOST_PUB}" > "$WGM_ROOT/etc/ssh/ssh_host_ed25519_key.pub"
        """),
}
for _name in ("wg-quick", "systemctl", "useradd", "visudo", "sshd", "service"):
    _STUBS[_name] = f"#!/usr/bin/env bash\n{_RECORD}\n"


@pytest.fixture()
def env(tmp_path: Path) -> dict[str, str]:
    """Fake root + stub PATH + the env a userdata script would set."""
    root = tmp_path / "root"
    (root / "etc" / "ssh").mkdir(parents=True)
    (root / "etc" / "ssh" / "ssh_host_ed25519_key.pub").write_text(HOST_PUB + "\n")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name, body in _STUBS.items():
        p = bindir / name
        p.write_text(body)
        p.chmod(0o755)
    log = tmp_path / "log"
    log.mkdir()
    resp = tmp_path / "response.json"
    resp.write_text(json.dumps(RESPONSE))
    return {
        "PATH": f"{bindir}:{os.environ['PATH']}",
        "HOME": str(tmp_path),
        "WGM_ROOT": str(root),
        "WGM_SKIP_PACKAGES": "1",
        "WGM_RETRY_DELAY": "0",
        "WGM_ENROLL_URL": "https://enroll.example.com:8443/",
        "WGM_ENROLL_TOKEN": TOKEN,
        "WGM_CA_BUNDLE_PEM": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        "FAKE_LOG": str(log),
        "FAKE_RESPONSE": str(resp),
        "FAKE_HTTP_CODES": "201",
    }


def _run(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(SCRIPT)], env=env, capture_output=True, text=True, timeout=30
    )


def _root(env: dict[str, str]) -> Path:
    return Path(env["WGM_ROOT"])


def _log(env: dict[str, str], name: str) -> str:
    p = Path(env["FAKE_LOG"]) / name
    return p.read_text() if p.exists() else ""


def _mode(p: Path) -> int:
    return stat.S_IMODE(p.stat().st_mode)


def _under(env: dict[str, str], abs_path: str) -> Path:
    return _root(env) / abs_path.lstrip("/")


class TestScriptFile:
    def test_present_and_executable(self) -> None:
        assert SCRIPT.is_file()
        assert os.stat(SCRIPT).st_mode & stat.S_IXUSR

    def test_fails_loud(self) -> None:
        assert "set -euo pipefail" in SCRIPT.read_text()


class TestHappyPath:
    def test_enrolls_and_writes_everything(self, env: dict[str, str]) -> None:
        r = _run(env)
        assert r.returncode == 0, r.stderr

        # Request: local keys, lowercased short hostname.
        body = json.loads(_log(env, "curl.body"))
        assert body == {
            "hostname": "web-01",
            "wg_public_key": FAKE_PUB,
            "ssh_host_public_key": HOST_PUB,
        }
        argv = _log(env, "curl.log")
        assert "https://enroll.example.com:8443/v1/enroll" in argv
        assert "--cacert" in argv

        wg = _under(env, "/etc/wireguard")
        assert (wg / "privatekey").read_text().strip() == FAKE_PRIV
        assert _mode(wg / "privatekey") == 0o600
        assert (wg / "wg0.conf").read_text() == RESPONSE["wg_config"]
        assert _mode(wg / "wg0.conf") == 0o600

        assert _under(env, HOST_CA_PUB_PATH).read_text() == RESPONSE["user_ca_public_key"] + "\n"
        assert _under(env, HOST_CERT_PATH).read_text() == RESPONSE["host_certificate"] + "\n"
        assert _under(env, SSHD_DROPIN_PATH).read_text() == _SSHD_DROPIN_TEMPLATE.format(
            ca_pub=HOST_CA_PUB_PATH, host_cert=HOST_CERT_PATH
        )

        sudoers = _under(env, "/etc/sudoers.d/wg-manager")
        assert sudoers.read_text() == "wgmgr ALL=(ALL) NOPASSWD:ALL\n"
        assert _mode(sudoers) == 0o440

        assert "enable wg-quick@wg0" in _log(env, "systemctl.log")
        assert "restart wg-quick@wg0" in _log(env, "systemctl.log")
        assert "reload" in _log(env, "systemctl.log")

    def test_token_never_on_argv(self, env: dict[str, str]) -> None:
        assert _run(env).returncode == 0
        for name in ("curl.log", "wg.log", "systemctl.log"):
            assert TOKEN not in _log(env, name), name
        assert f"Authorization: Bearer {TOKEN}" in _log(env, "curl.headers")

    def test_private_key_never_sent(self, env: dict[str, str]) -> None:
        assert _run(env).returncode == 0
        assert FAKE_PRIV not in _log(env, "curl.body")
        assert FAKE_PRIV not in _log(env, "curl.log")

    def test_token_file_variant(self, env: dict[str, str], tmp_path: Path) -> None:
        tf = tmp_path / "token"
        tf.write_text(TOKEN + "\n")
        env.pop("WGM_ENROLL_TOKEN")
        env["WGM_ENROLL_TOKEN_FILE"] = str(tf)
        assert _run(env).returncode == 0
        assert f"Authorization: Bearer {TOKEN}" in _log(env, "curl.headers")
        assert not tf.exists(), "token file should be removed after use"


class TestIdempotencyAndSetup:
    def test_existing_private_key_is_reused(self, env: dict[str, str]) -> None:
        wg = _under(env, "/etc/wireguard")
        wg.mkdir(parents=True)
        (wg / "privatekey").write_text("EXISTINGKEY=\n")
        assert _run(env).returncode == 0
        assert "genkey" not in _log(env, "wg.log")
        assert (wg / "privatekey").read_text() == "EXISTINGKEY=\n"

    def test_generates_host_key_when_missing(self, env: dict[str, str]) -> None:
        (_root(env) / "etc/ssh/ssh_host_ed25519_key.pub").unlink()
        assert _run(env).returncode == 0
        assert "-A" in _log(env, "ssh-keygen.log")

    def test_creates_management_user_when_missing(self, env: dict[str, str]) -> None:
        env["FAKE_NO_USER"] = "1"
        assert _run(env).returncode == 0
        assert "wgmgr" in _log(env, "useradd.log")

    def test_existing_user_not_recreated(self, env: dict[str, str]) -> None:
        assert _run(env).returncode == 0
        assert _log(env, "useradd.log") == ""


class TestFailures:
    def test_retries_transient_5xx(self, env: dict[str, str]) -> None:
        env["FAKE_HTTP_CODES"] = "503 502 201"
        r = _run(env)
        assert r.returncode == 0, r.stderr
        assert _log(env, "curl.count").strip() == "3"

    def test_retries_rate_limited_429(self, env: dict[str, str]) -> None:
        """A NAT'd fleet enrolling at once can trip the per-IP request cap.
        That's transient, so it must back off and retry, not abort."""
        env["FAKE_HTTP_CODES"] = "429 429 201"
        r = _run(env)
        assert r.returncode == 0, r.stderr
        assert _log(env, "curl.count").strip() == "3"

    def test_4xx_is_fatal_without_retry(self, env: dict[str, str]) -> None:
        env["FAKE_HTTP_CODES"] = "401"
        r = _run(env)
        assert r.returncode != 0
        assert _log(env, "curl.count").strip() == "1"
        assert not _under(env, "/etc/wireguard/wg0.conf").exists()
        assert "401" in r.stderr

    def test_gives_up_after_max_attempts(self, env: dict[str, str]) -> None:
        env["FAKE_HTTP_CODES"] = "503"
        env["WGM_MAX_ATTEMPTS"] = "3"
        r = _run(env)
        assert r.returncode != 0
        assert _log(env, "curl.count").strip() == "3"

    @pytest.mark.parametrize(
        "missing", ["WGM_ENROLL_URL", "WGM_ENROLL_TOKEN", "WGM_CA_BUNDLE_PEM"]
    )
    def test_required_settings(self, env: dict[str, str], missing: str) -> None:
        env.pop(missing)
        r = _run(env)
        assert r.returncode == 2
        assert missing.replace("_PEM", "") in r.stderr
        assert _log(env, "curl.log") == ""

    def test_refuses_plain_http(self, env: dict[str, str]) -> None:
        env["WGM_ENROLL_URL"] = "http://enroll.example.com:8001"
        r = _run(env)
        assert r.returncode == 2
        assert "https" in r.stderr
