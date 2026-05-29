"""Tests for :mod:`wg_manager.pki` — Phase 2d PKI layer.

Both :class:`LocalDevPKI` (in-process root + intermediate, used by the
test suite and developers without a Vault container) and
:class:`VaultPKI` (hvac → Vault PKI secrets engine, the production
backend) implement the same :class:`PKIBackend` protocol. The
parameterised matrix in :class:`TestPKIBackends` proves they share
observable behaviour — leaf cert issuance with correct CN/SANs,
key-usage extensions, chain validation back to the bundle root, CRL
shape — so callers in :mod:`wg_manager.main` (CP2 uvicorn TLS) and
the operator-facing CLI (CP3) never need to know which backend is
active.

Vault-backed cases are auto-skipped when no Vault is reachable at
``$VAULT_ADDR`` (default ``http://127.0.0.1:8200``); the plain
``pytest -q`` run stays hermetic. ``make vault-up && pytest -q
tests/test_pki.py`` exercises the full matrix. Phase 2d CP1
acceptance requires both modes green, mirroring the Phase 2b / 2c
pattern documented in :doc:`docs/vault-cookbook`.

Log-scrub guardrail mirrors the Phase 2b / 2c guardrails: private-key
bodies must never appear in captured ``logging`` output, because they
would let a log-read attacker recover an unexpired operator credential.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone

import hvac
import pytest
import requests
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from hvac.exceptions import InvalidRequest as HvacInvalidRequest

from wg_manager.config import Settings
from wg_manager.pki import (
    Cert,
    LocalDevPKI,
    PKIBackend,
    PKIError,
    VaultPKI,
    make_pki_backend,
)


# ---------------------------------------------------------------------------
# Vault availability probe (mirrors tests/test_ssh_ca.py)
# ---------------------------------------------------------------------------

_VAULT_ADDR = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
_VAULT_TOKEN = os.environ.get("VAULT_TOKEN", "dev-only-root")


def _vault_reachable() -> bool:
    """Return ``True`` if a Vault listener answers at ``$VAULT_ADDR``."""
    try:
        resp = requests.get(f"{_VAULT_ADDR}/v1/sys/health", timeout=0.5)
        return resp.status_code < 500
    except requests.RequestException:
        return False


_VAULT_AVAILABLE = _vault_reachable()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def local_pki() -> LocalDevPKI:
    """A LocalDevPKI seeded with a freshly-generated root + intermediate.

    Each test gets its own in-process hierarchy so a test that revokes /
    rotates can't contaminate the next test's expected CRL shape.
    """
    return LocalDevPKI.generate()


@pytest.fixture
def vault_pki(request: pytest.FixtureRequest) -> VaultPKI:
    """A VaultPKI bound to per-test mounts in the dev container.

    Each test bootstraps its own root + intermediate at per-test mount
    paths so revocation / rotation in one test doesn't leak into the
    next. Vault dev mode wipes everything on restart anyway.
    """
    if not _VAULT_AVAILABLE:
        pytest.skip(f"Vault not reachable at {_VAULT_ADDR}")
    client = hvac.Client(url=_VAULT_ADDR, token=_VAULT_TOKEN)

    suffix = (
        request.node.name.replace("[", "-")
        .replace("]", "")
        .replace("/", "-")
        .lower()
    )
    # Vault mount paths are 1-byte-per-char; keep both under the limit.
    root = f"pki-test-root-{suffix}"[:64]
    intermediate = f"pki-test-int-{suffix}"[:64]

    return VaultPKI.bootstrap(
        client=client,
        root_mount=root,
        intermediate_mount=intermediate,
        server_role="wg-manager-server",
        client_role="wg-manager-client",
        allowed_domains="wg.local,example.com",
        max_ttl="24h",
    )


@pytest.fixture(params=["local", "vault"])
def pki(request: pytest.FixtureRequest) -> PKIBackend:
    """Parameterised fixture yielding each backend in turn."""
    return request.getfixturevalue(f"{request.param}_pki")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_cert(pem: str) -> x509.Certificate:
    """Parse a PEM cert body. Raises if it isn't a single cert."""
    return x509.load_pem_x509_certificate(pem.encode())


def _load_chain(pem: str) -> list[x509.Certificate]:
    """Parse a PEM bundle into an ordered list of certs."""
    return x509.load_pem_x509_certificates(pem.encode())


def _sans(cert: x509.Certificate) -> set[str]:
    """Return the SAN strings (DNS + IP) on ``cert`` as a flat set."""
    try:
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except x509.ExtensionNotFound:
        return set()
    out: set[str] = set()
    for entry in san:
        if isinstance(entry, x509.DNSName):
            out.add(entry.value)
        elif isinstance(entry, x509.IPAddress):
            out.add(str(entry.value))
    return out


def _eku_oids(cert: x509.Certificate) -> set[x509.ObjectIdentifier]:
    """Return the Extended Key Usage OIDs on ``cert`` as a set."""
    try:
        eku = cert.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
    except x509.ExtensionNotFound:
        return set()
    return set(eku)


# ---------------------------------------------------------------------------
# Shared contract — both backends must satisfy these
# ---------------------------------------------------------------------------


class TestPKIBackends:
    """Behaviours every backend must satisfy."""

    def test_ca_bundle_parses_as_a_chain(self, pki: PKIBackend) -> None:
        """``ca_bundle_pem`` must be a non-empty PEM bundle terminating in
        a self-signed root (so it can be dropped straight into
        ``ssl_ca_certs`` / ``--ssl-ca-certs``)."""
        chain = _load_chain(pki.ca_bundle_pem)
        assert chain, "ca_bundle_pem is empty"
        root = chain[-1]
        # A root is self-signed: issuer == subject.
        assert root.issuer == root.subject

    def test_issue_server_cert_returns_cert_value(self, pki: PKIBackend) -> None:
        cert = pki.issue_server_cert(
            common_name="api.wg.local",
            sans=["api.wg.local"],
            ttl_seconds=300,
        )
        assert isinstance(cert, Cert)
        assert cert.cert_pem.startswith("-----BEGIN CERTIFICATE-----")
        assert "PRIVATE KEY" in cert.private_pem
        assert cert.common_name == "api.wg.local"

    def test_server_cert_carries_serverauth_eku(self, pki: PKIBackend) -> None:
        cert = pki.issue_server_cert(
            common_name="api.wg.local", sans=["api.wg.local"], ttl_seconds=300
        )
        parsed = _load_cert(cert.cert_pem)
        ekus = _eku_oids(parsed)
        assert ExtendedKeyUsageOID.SERVER_AUTH in ekus, (
            f"server cert must carry serverAuth EKU, got {ekus!r}"
        )

    def test_client_cert_carries_clientauth_eku(self, pki: PKIBackend) -> None:
        cert = pki.issue_client_cert(
            common_name="ops@wg.local",
            sans=["ops@wg.local"],
            ttl_seconds=300,
        )
        parsed = _load_cert(cert.cert_pem)
        ekus = _eku_oids(parsed)
        assert ExtendedKeyUsageOID.CLIENT_AUTH in ekus, (
            f"client cert must carry clientAuth EKU, got {ekus!r}"
        )

    def test_server_cert_sans_match_request(self, pki: PKIBackend) -> None:
        cert = pki.issue_server_cert(
            common_name="api.wg.local",
            sans=["api.wg.local", "wg.local", "127.0.0.1"],
            ttl_seconds=300,
        )
        parsed = _load_cert(cert.cert_pem)
        got = _sans(parsed)
        assert {"api.wg.local", "wg.local", "127.0.0.1"} <= got, (
            f"server SANs missing: requested ⊆? actual; got {got!r}"
        )

    def test_server_cert_ttl_honoured(self, pki: PKIBackend) -> None:
        """The cert expires within ``ttl_seconds`` of now and is valid now.

        Vault's signing path can add a small skew on either bound; the
        security invariant we care about is "the cert doesn't outlive the
        requested TTL by more than the configured skew".
        """
        before = datetime.now(timezone.utc)
        cert = pki.issue_server_cert(
            common_name="api.wg.local", sans=["api.wg.local"], ttl_seconds=300
        )
        slack = timedelta(seconds=60)
        assert cert.not_after <= before + timedelta(seconds=300) + slack, (
            f"cert outlives requested ttl: not_after={cert.not_after}, "
            f"now={before}"
        )
        assert cert.not_before <= before + slack, (
            f"cert is not valid yet: not_before={cert.not_before}, now={before}"
        )

    def test_private_key_pairs_with_cert_pubkey(self, pki: PKIBackend) -> None:
        """The returned ``private_pem`` must match the cert's public key —
        otherwise the operator can't actually use the cert to terminate TLS."""
        cert = pki.issue_server_cert(
            common_name="api.wg.local", sans=["api.wg.local"], ttl_seconds=300
        )
        parsed = _load_cert(cert.cert_pem)
        priv = load_pem_private_key(cert.private_pem.encode(), password=None)
        # Compare raw SubjectPublicKeyInfo bytes — handles RSA, EC, Ed25519
        # uniformly without needing to branch on the algorithm.
        from_cert = parsed.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        from_priv = priv.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        assert from_cert == from_priv, (
            "private key does not match certificate public key"
        )

    def test_chain_pem_contains_issuing_intermediate(
        self, pki: PKIBackend
    ) -> None:
        """``Cert.chain_pem`` must contain enough CAs to chain back to the
        bundle root. At minimum the issuing intermediate must be present so
        ``ssl_context.load_verify_locations`` succeeds for a mTLS client
        receiving only the leaf + chain over the wire.
        """
        cert = pki.issue_server_cert(
            common_name="api.wg.local", sans=["api.wg.local"], ttl_seconds=300
        )
        chain = _load_chain(cert.chain_pem)
        assert chain, "chain_pem is empty — clients won't be able to verify"
        leaf = _load_cert(cert.cert_pem)
        # The issuing intermediate must verify the leaf's signature.
        issuer = chain[0]
        # cryptography 40+ exposes verify_directly_issued_by which checks
        # both name binding and signature in one call.
        try:
            leaf.verify_directly_issued_by(issuer)
        except (InvalidSignature, ValueError) as exc:
            raise AssertionError(
                f"chain_pem[0] does not directly issue the leaf cert: {exc}"
            ) from exc

    def test_chain_validates_back_to_bundle_root(
        self, pki: PKIBackend
    ) -> None:
        """Walk the chain (leaf → chain_pem → ca_bundle_pem) and confirm
        every link is properly signed by its parent up to a self-signed
        root that lives in the backend's advertised bundle."""
        cert = pki.issue_server_cert(
            common_name="api.wg.local", sans=["api.wg.local"], ttl_seconds=300
        )
        # All issuing material the backend wants us to know about. The
        # leaf walks up through chain_pem (per-cert) plus the bundle (the
        # trust anchors). We dedupe by subject DER so a backend that
        # repeats the root across both surfaces still passes.
        roots = {
            c.subject.public_bytes(): c for c in _load_chain(pki.ca_bundle_pem)
        }
        issuers = {
            c.subject.public_bytes(): c for c in _load_chain(cert.chain_pem)
        }
        issuers.update(roots)
        node = _load_cert(cert.cert_pem)
        # Bounded walk — three levels is the deepest hierarchy we plan to
        # ship (root → intermediate → leaf), give one of slack.
        for _ in range(4):
            if node.issuer == node.subject:
                # Reached a self-signed root; check it's a bundle root.
                assert node.subject.public_bytes() in roots, (
                    "leaf walked to a self-signed cert that isn't in "
                    "ca_bundle_pem — clients trusting the bundle won't "
                    "trust this leaf"
                )
                return
            parent = issuers.get(node.issuer.public_bytes())
            assert parent is not None, (
                f"missing issuer for {node.subject.rfc4514_string()!r}: "
                f"need a cert with subject {node.issuer.rfc4514_string()!r}"
            )
            node.verify_directly_issued_by(parent)
            node = parent
        raise AssertionError("chain too deep to be sensible (>4 levels)")

    def test_two_issues_produce_distinct_certs(self, pki: PKIBackend) -> None:
        a = pki.issue_server_cert(
            common_name="api.wg.local", sans=["api.wg.local"], ttl_seconds=300
        )
        b = pki.issue_server_cert(
            common_name="api.wg.local", sans=["api.wg.local"], ttl_seconds=300
        )
        # Fresh keypair + fresh serial per issue.
        assert a.private_pem != b.private_pem
        assert a.cert_pem != b.cert_pem
        assert a.serial != b.serial

    def test_revoke_records_serial_in_crl(self, pki: PKIBackend) -> None:
        """After ``revoke_cert(serial=N)`` the CRL must list ``N``."""
        cert = pki.issue_client_cert(
            common_name="ops@wg.local",
            sans=["ops@wg.local"],
            ttl_seconds=300,
        )
        pki.revoke_cert(serial=cert.serial)
        crl = x509.load_pem_x509_crl(pki.crl_pem().encode())
        revoked_serials = {entry.serial_number for entry in crl}
        assert cert.serial in revoked_serials, (
            f"serial {cert.serial} missing from CRL after revoke; "
            f"CRL serials: {sorted(revoked_serials)!r}"
        )

    def test_log_scrub_no_private_key_in_logs(
        self,
        pki: PKIBackend,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A successful issue must not leak the private PEM into logs.

        Mirrors the Phase 2b / 2c guardrail. If this fails the
        implementation is logging the secret it just produced — a
        log-read attacker could recover an unexpired operator cert.
        """
        caplog.set_level(logging.DEBUG, logger="wg_manager.pki")
        cert = pki.issue_server_cert(
            common_name="api.wg.local", sans=["api.wg.local"], ttl_seconds=300
        )
        joined = "\n".join(r.getMessage() for r in caplog.records)
        assert "BEGIN PRIVATE KEY" not in joined
        assert "BEGIN RSA PRIVATE KEY" not in joined
        assert "BEGIN EC PRIVATE KEY" not in joined
        # Sanity — make sure the issue really happened (no false positive).
        assert cert.cert_pem


# ---------------------------------------------------------------------------
# LocalDevPKI-specific
# ---------------------------------------------------------------------------


class TestLocalDevPKI:
    """Behaviours specific to the in-process dev backend."""

    def test_generate_returns_distinct_hierarchies(self) -> None:
        """Two ``generate()`` calls must produce different root subjects so
        a developer who forgets to pin the PEM doesn't accidentally treat
        two CAs as one."""
        a = LocalDevPKI.generate()
        b = LocalDevPKI.generate()
        assert a.ca_bundle_pem != b.ca_bundle_pem

    def test_from_pem_round_trips(self) -> None:
        """An operator-supplied root/intermediate pair must reload to the
        same advertised bundle."""
        ca = LocalDevPKI.generate()
        reloaded = LocalDevPKI.from_pem(
            root_pem=ca.root_pem,
            root_key_pem=ca.root_key_pem,
            intermediate_pem=ca.intermediate_pem,
            intermediate_key_pem=ca.intermediate_key_pem,
        )
        assert reloaded.ca_bundle_pem == ca.ca_bundle_pem


# ---------------------------------------------------------------------------
# VaultPKI-specific
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _VAULT_AVAILABLE, reason="Vault not reachable")
class TestVaultPKI:
    """Behaviours that depend on the real Vault PKI secrets engine."""

    def test_unallowed_domain_rejected(self, vault_pki: VaultPKI) -> None:
        """Vault enforces ``allowed_domains`` — asking outside the set
        should raise :class:`PKIError`, not return a usable cert."""
        with pytest.raises(PKIError):
            vault_pki.issue_server_cert(
                common_name="not-on-the-list.bogus",
                sans=["not-on-the-list.bogus"],
                ttl_seconds=300,
            )

    def test_ttl_above_max_rejected(self, vault_pki: VaultPKI) -> None:
        """The bootstrap pinned ``max_ttl=24h``; ask for a year and Vault
        either truncates or refuses. Either is fine — the security
        invariant is "leaf cert never outlives the role cap"."""
        cert = vault_pki.issue_server_cert(
            common_name="api.wg.local",
            sans=["api.wg.local"],
            ttl_seconds=60 * 60 * 24 * 365,
        )
        # 24h + skew slack — must not be issued for a year.
        cap = datetime.now(timezone.utc) + timedelta(hours=24, minutes=5)
        assert cert.not_after <= cap, (
            f"Vault honoured a TTL above max_ttl: not_after={cert.not_after}"
        )

    def test_bootstrap_idempotent(self) -> None:
        """Two back-to-back bootstraps against the same mounts must
        succeed — operators run ``make pki-bootstrap`` repeatedly."""
        client = hvac.Client(url=_VAULT_ADDR, token=_VAULT_TOKEN)
        root = "pki-test-idem-root"
        intermediate = "pki-test-idem-int"
        first = VaultPKI.bootstrap(
            client=client,
            root_mount=root,
            intermediate_mount=intermediate,
            server_role="wg-manager-server",
            client_role="wg-manager-client",
            allowed_domains="wg.local",
            max_ttl="24h",
        )
        second = VaultPKI.bootstrap(
            client=client,
            root_mount=root,
            intermediate_mount=intermediate,
            server_role="wg-manager-server",
            client_role="wg-manager-client",
            allowed_domains="wg.local",
            max_ttl="24h",
        )
        # Same intermediate, same advertised bundle. (Vault keeps the
        # mount; the second call is a no-op.)
        assert first.ca_bundle_pem == second.ca_bundle_pem


# ---------------------------------------------------------------------------
# Factory selection
# ---------------------------------------------------------------------------


class TestMakePKIBackend:
    """``make_pki_backend()`` reads settings and returns the right backend."""

    def test_local_backend_selected_by_settings(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PKI_BACKEND", "local")
        # No pinned PEM → auto-generate (dev/test only).
        for k in (
            "PKI_LOCAL_DEV_ROOT_PEM",
            "PKI_LOCAL_DEV_ROOT_KEY_PEM",
            "PKI_LOCAL_DEV_INT_PEM",
            "PKI_LOCAL_DEV_INT_KEY_PEM",
        ):
            monkeypatch.delenv(k, raising=False)
        backend = make_pki_backend(Settings())
        assert isinstance(backend, LocalDevPKI)
        cert = backend.issue_server_cert(
            common_name="api.wg.local",
            sans=["api.wg.local"],
            ttl_seconds=300,
        )
        assert cert.cert_pem.startswith("-----BEGIN CERTIFICATE-----")

    def test_local_backend_honours_supplied_pem(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When an operator supplies a CA bundle, ``make_pki_backend`` must
        load that exact hierarchy — proves operators can pin a stable dev
        CA across restarts when they want one (the same shape Phase 2c's
        ``SSH_CA_LOCAL_DEV_PEM`` allows)."""
        ca = LocalDevPKI.generate()
        monkeypatch.setenv("PKI_BACKEND", "local")
        monkeypatch.setenv("PKI_LOCAL_DEV_ROOT_PEM", ca.root_pem)
        monkeypatch.setenv("PKI_LOCAL_DEV_ROOT_KEY_PEM", ca.root_key_pem)
        monkeypatch.setenv("PKI_LOCAL_DEV_INT_PEM", ca.intermediate_pem)
        monkeypatch.setenv(
            "PKI_LOCAL_DEV_INT_KEY_PEM", ca.intermediate_key_pem
        )
        backend = make_pki_backend(Settings())
        assert isinstance(backend, LocalDevPKI)
        assert backend.ca_bundle_pem == ca.ca_bundle_pem

    def test_local_backend_stable_across_calls(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Two calls to ``make_pki_backend`` with the local backend and no
        pinned PEM must return backends advertising the *same* bundle.

        Regression-style: mirrors the Phase 2c CP4.2.1 fix that memoised
        ``LocalDevSSHCA`` per-process. Without it, the API and worker each
        hold a different root and mTLS verification breaks on the second
        hop.
        """
        monkeypatch.setenv("PKI_BACKEND", "local")
        for k in (
            "PKI_LOCAL_DEV_ROOT_PEM",
            "PKI_LOCAL_DEV_ROOT_KEY_PEM",
            "PKI_LOCAL_DEV_INT_PEM",
            "PKI_LOCAL_DEV_INT_KEY_PEM",
        ):
            monkeypatch.delenv(k, raising=False)
        first = make_pki_backend(Settings())
        second = make_pki_backend(Settings())
        assert first.ca_bundle_pem == second.ca_bundle_pem, (
            "local PKI regenerated the root between calls — clients "
            "trusting one root cannot verify certs issued by the other"
        )

    def test_unknown_backend_value_is_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PKI_BACKEND", "magical-realism")
        with pytest.raises(ValueError, match="magical-realism"):
            make_pki_backend(Settings())

    def test_vault_backend_selected_by_settings(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``make_pki_backend`` constructs a :class:`VaultPKI` against an
        already-bootstrapped pair of mounts. Bootstrap inline so this
        test doesn't quietly depend on ``make pki-bootstrap`` having been
        run out of band."""
        if not _VAULT_AVAILABLE:
            pytest.skip(f"Vault not reachable at {_VAULT_ADDR}")
        root = "pki-factory-root"
        intermediate = "pki-factory-int"
        client = hvac.Client(url=_VAULT_ADDR, token=_VAULT_TOKEN)
        VaultPKI.bootstrap(
            client=client,
            root_mount=root,
            intermediate_mount=intermediate,
            server_role="wg-manager-server",
            client_role="wg-manager-client",
            allowed_domains="wg.local",
            max_ttl="24h",
        )
        monkeypatch.setenv("PKI_BACKEND", "vault")
        monkeypatch.setenv("VAULT_ADDR", _VAULT_ADDR)
        monkeypatch.setenv("VAULT_TOKEN", _VAULT_TOKEN)
        monkeypatch.setenv("PKI_VAULT_ROOT_MOUNT", root)
        monkeypatch.setenv("PKI_VAULT_INT_MOUNT", intermediate)
        monkeypatch.setenv("PKI_VAULT_SERVER_ROLE", "wg-manager-server")
        monkeypatch.setenv("PKI_VAULT_CLIENT_ROLE", "wg-manager-client")
        backend = make_pki_backend(Settings())
        assert isinstance(backend, VaultPKI)


# ---------------------------------------------------------------------------
# Settings exposes operator-tunable defaults for the Vault PKI roles
# ---------------------------------------------------------------------------


class TestVaultPKISettings:
    """The ``make pki-bootstrap`` script reads these to configure roles."""

    def test_settings_exposes_pki_fields(self) -> None:
        """Every ``PKI_*`` setting the bootstrap script wants to thread
        through must exist on :class:`Settings` with the documented
        default."""
        s = Settings()
        assert s.pki_backend == "local"
        # Server / client role names default to the bootstrap labels.
        assert s.pki_vault_server_role
        assert s.pki_vault_client_role
        # Mount paths default to ``pki`` / ``pki_int`` — the convention
        # the Vault cookbook uses.
        assert s.pki_vault_root_mount
        assert s.pki_vault_int_mount
        # Allowed domains may be empty (operator hasn't configured) but
        # must be a string field so the setting parses.
        assert isinstance(s.pki_vault_allowed_domains, str)


# ---------------------------------------------------------------------------
# Cert value object basics
# ---------------------------------------------------------------------------


class TestCertValueObject:
    """``Cert`` is the operator-facing return type; pin its shape."""

    def test_cert_is_frozen(self) -> None:
        """``Cert`` instances must be immutable so callers can't quietly
        mutate the private-key field after handing it off to TLS code."""
        ca = LocalDevPKI.generate()
        cert = ca.issue_server_cert(
            common_name="api.wg.local",
            sans=["api.wg.local"],
            ttl_seconds=300,
        )
        with pytest.raises((AttributeError, Exception)):
            cert.private_pem = "stolen"  # type: ignore[misc]

    def test_cert_fields_present(self) -> None:
        ca = LocalDevPKI.generate()
        cert = ca.issue_server_cert(
            common_name="api.wg.local",
            sans=["api.wg.local"],
            ttl_seconds=300,
        )
        assert cert.serial > 0
        assert cert.common_name == "api.wg.local"
        assert "api.wg.local" in cert.sans
        assert cert.not_before.tzinfo is not None, "not_before must be tz-aware"
        assert cert.not_after.tzinfo is not None, "not_after must be tz-aware"
