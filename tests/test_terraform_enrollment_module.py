"""Regression guards for deploy/terraform (Phase 3f polish).

The Terraform module was verified end to end against a running API with
the real provider (apply, re-plan, replace, destroy, and a swept token
row); see ``docs/operator-guide.md``, "Terraform". Those runs need Docker,
registry access and a live API, so they aren't part of the suite.
``make terraform-check`` runs ``terraform fmt``/``validate``.

These tests pin, as text, the specific behaviours those runs showed are
easy to get wrong, so a later edit can't silently undo them:

* restapi stays on 2.x: 3.0.0 breaks plan *and* destroy once the sweeper
  deletes a long-dead token (404 on read).
* Input changes replace the token via ``replace_triggered_by``: the
  provider's ``force_new`` is suppressed by ``ignore_all_server_changes``
  and planned an input change as "no changes".
* Destroy revokes (``POST .../{id}/revoke``) rather than a DELETE the API
  doesn't have.
* The provider block sets ``create_returns_object``, without which
  create fails ("object does not have an id set").
* The token output is sensitive, and the example instance ignores
  ``user_data`` changes, so a re-minted token never replaces a host.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "deploy" / "terraform" / "wg-manager-enrollment-token"
EXAMPLE = ROOT / "deploy" / "terraform" / "examples" / "aws-instance"


def _hcl(path: Path) -> str:
    """File body with ``#`` comments removed, so prose can't satisfy a check."""
    return "\n".join(line.split("#", 1)[0] for line in path.read_text().splitlines())


@pytest.fixture(scope="module")
def module_main() -> str:
    return _hcl(MODULE / "main.tf")


@pytest.mark.parametrize("path", [MODULE / "versions.tf", EXAMPLE / "main.tf"])
def test_restapi_is_pinned_to_2x(path: Path) -> None:
    body = _hcl(path)
    block = re.search(r'restapi\s*=\s*\{[^}]*\}', body, re.S)
    assert block, path
    assert re.search(r'version\s*=\s*"~>\s*2\.0"', block.group(0)), block.group(0)


def test_destroy_revokes(module_main: str) -> None:
    assert re.search(r'destroy_path\s*=\s*"/enrollment-tokens/\{id\}/revoke"', module_main)
    assert re.search(r'destroy_method\s*=\s*"POST"', module_main)


def test_input_changes_replace_the_token(module_main: str) -> None:
    assert re.search(
        r"replace_triggered_by\s*=\s*\[\s*terraform_data\.inputs\s*\]", module_main
    )
    inputs = re.search(r'resource\s+"terraform_data"\s+"inputs"\s*\{[^}]*\}', module_main, re.S)
    assert inputs and re.search(r"input\s*=\s*local\.payload", inputs.group(0))
    # The request body and the trigger must be the same values.
    assert re.search(r"data\s*=\s*jsonencode\(local\.payload\)", module_main)


def test_server_side_changes_are_not_drift(module_main: str) -> None:
    assert re.search(r"ignore_all_server_changes\s*=\s*true", module_main)


def test_example_provider_reads_id_from_create_response() -> None:
    provider = re.search(r'provider\s+"restapi"\s*\{[^}]*\}', _hcl(EXAMPLE / "main.tf"), re.S)
    assert provider
    assert re.search(r"create_returns_object\s*=\s*true", provider.group(0))
    for arg in ("cert_file", "key_file", "root_ca_file"):
        assert re.search(rf"\b{arg}\s*=", provider.group(0)), arg


def test_token_output_is_sensitive() -> None:
    outputs = _hcl(MODULE / "outputs.tf")
    token = re.search(r'output\s+"token"\s*\{[^}]*\}', outputs, re.S)
    assert token and re.search(r"sensitive\s*=\s*true", token.group(0))


def test_example_instance_ignores_userdata_changes() -> None:
    body = _hcl(EXAMPLE / "main.tf")
    assert re.search(r"ignore_changes\s*=\s*\[\s*user_data\s*\]", body)


def test_userdata_template_feeds_enroll_node_sh() -> None:
    tpl = (EXAMPLE / "userdata.sh.tftpl").read_text()
    for var in ("WGM_ENROLL_URL", "WGM_ENROLL_TOKEN", "WGM_CA_BUNDLE_PEM"):
        assert f"export {var}=" in tpl, var
    assert "enroll_node.sh" in tpl


def test_makefile_has_terraform_check() -> None:
    makefile = (ROOT / "Makefile").read_text()
    assert re.search(r"^terraform-check:", makefile, re.M)
    assert "scripts/terraform_check.sh" in makefile
