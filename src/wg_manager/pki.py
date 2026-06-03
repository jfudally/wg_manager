"""Phase 2d X.509 PKI layer.

This module is the wg-manager-facing seam over an X.509 certificate
authority. CP1 lands the module + two backends + bootstrap glue; CP2
onward wires it into the API listener (mTLS), the dashboard
(operator-cert "Who am I?" splash), and the MySQL boundary.

Two backends implement :class:`PKIBackend`:

* :class:`LocalDevPKI` — an in-process root + intermediate built on
  ``cryptography``. The hierarchy lives in this process's memory and
  is regenerated on every restart unless the operator pins the four
  PEMs via ``PKI_LOCAL_DEV_*`` (see :class:`wg_manager.config.Settings`).
  Used by the test suite and by developers who don't want a Vault
  container in the loop. **Not** safe for production: the CA private
  keys are reachable from anything that can import the process. The
  ``make_pki_backend`` factory memoises the un-pinned dev hierarchy
  per-process (see :data:`_LOCAL_PKI_CACHE`) so the API and the
  Celery worker — both of which call the factory at import time —
  share one root. Multi-*process* dev requires the pinned PEMs;
  production is :class:`VaultPKI`.
* :class:`VaultPKI` — wraps the Vault PKI secrets engine with a
  two-tier root → intermediate hierarchy. The CA private keys never
  leave Vault; we hold an authenticated :class:`hvac.Client` and the
  mount + role names that :meth:`VaultPKI.bootstrap` (or
  ``make pki-bootstrap``) previously configured.

Mirrors the shape of :mod:`wg_manager.crypto` and
:mod:`wg_manager.ssh_ca`: a ``Protocol`` contract, a dev backend with
a ``generate``/``from_pem`` factory pair, a Vault backend with an
idempotent ``bootstrap`` classmethod, and a :func:`make_pki_backend`
selector keyed off :class:`Settings`. The CP1 surface is intentionally
thin — Phase 2d CP3 grows operator-facing helpers (PKCS#12 export,
audit-friendly subject parsing) on top of this contract.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol, runtime_checkable

import hvac
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from hvac.exceptions import InvalidPath, InvalidRequest, VaultError

from wg_manager.config import Settings

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class PKIError(RuntimeError):
    """Raised when the PKI refuses to issue / revoke or returns garbage.

    Wraps the underlying Vault / cryptography exception so callers (the
    CP2 TLS-bootstrap helper, the CP3 ``certs`` CLI, the renewal job)
    catch a single project-named error type rather than re-raising
    :class:`hvac.exceptions.InvalidRequest` or
    :class:`cryptography.exceptions.InvalidSignature`.
    """


# ---------------------------------------------------------------------------
# Value object
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Cert:
    """An issued X.509 leaf certificate plus its private key + chain.

    Frozen so callers can't quietly mutate the private-key field after
    handing it off to TLS code. The (private_pem, cert_pem, chain_pem)
    triple is the minimum payload a TLS server needs to terminate;
    chain_pem is also the file an mTLS client presents as the issuing
    chain so the peer can build a path back to the trust anchor.

    :ivar cert_pem: PEM body of the leaf cert.
    :ivar private_pem: PEM body of the matching private key
        (PKCS#8 unencrypted for :class:`LocalDevPKI`; Vault's default
        for :class:`VaultPKI`). Drop this on the floor as soon as it
        is committed to disk / handed to TLS — it is sensitive.
    :ivar chain_pem: PEM concatenation of the issuing chain (the
        intermediate). Sent over the wire so the peer can build a
        path back to the trust anchor advertised in
        :attr:`PKIBackend.ca_bundle_pem`.
    :ivar serial: Issuer-assigned serial as an integer. Used for
        revocation lookups and audit log lines.
    :ivar common_name: The CN baked into the subject. Kept here so
        callers don't need to re-parse the cert for the most common
        operator-facing field.
    :ivar sans: SAN list (DNS names + IP addresses, stringified)
        embedded in the cert.
    :ivar not_before: Validity window start (UTC, tz-aware).
    :ivar not_after: Validity window end (UTC, tz-aware). Renewal
        jobs that want to act ahead of expiry sleep until
        ``not_after - jitter``.
    """

    cert_pem: str
    private_pem: str
    chain_pem: str
    serial: int
    common_name: str
    sans: tuple[str, ...] = field(default_factory=tuple)
    not_before: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    not_after: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class PKIBackend(Protocol):
    """Minimum surface every PKI backend must implement.

    Methods take keyword-only args to make call-sites self-documenting
    and to leave room for future extension fields without breaking
    positional callers.
    """

    name: str

    @property
    def ca_bundle_pem(self) -> str:
        """Return the trust-anchor bundle in PEM form.

        The bundle terminates in one or more self-signed roots so a
        TLS client trusting this file can build a full path for any
        leaf the backend has issued. Drop this straight into
        ``--ssl-ca-certs`` (uvicorn) or the ``ssl_ca`` connection-arg
        on the MySQL client.
        """
        ...

    def issue_server_cert(
        self, *, common_name: str, sans: list[str], ttl_seconds: int
    ) -> Cert:
        """Issue a leaf cert with the ``serverAuth`` EKU."""
        ...

    def issue_client_cert(
        self, *, common_name: str, sans: list[str], ttl_seconds: int
    ) -> Cert:
        """Issue a leaf cert with the ``clientAuth`` EKU."""
        ...

    def revoke_cert(self, *, serial: int) -> None:
        """Mark ``serial`` as revoked.

        After this call, :meth:`crl_pem` must list ``serial``. The
        implementation is allowed to fail loudly if ``serial`` was
        never issued by this backend.
        """
        ...

    def crl_pem(self) -> str:
        """Return the current CRL in PEM form."""
        ...


# ---------------------------------------------------------------------------
# Local-dev backend
# ---------------------------------------------------------------------------


_ONE_YEAR = timedelta(days=365)
_TEN_YEARS = timedelta(days=365 * 10)
_DEV_ROOT_CN = "wg-manager dev root"
_DEV_INT_CN = "wg-manager dev intermediate"


def _new_ec_key() -> EllipticCurvePrivateKey:
    """Generate a fresh P-256 keypair. Compact PEMs, fast TLS handshake."""
    return ec.generate_private_key(ec.SECP256R1())


def _key_pem(key: EllipticCurvePrivateKey) -> str:
    """Serialise ``key`` to PKCS#8 PEM (unencrypted)."""
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def _cert_pem(cert: x509.Certificate) -> str:
    """Serialise ``cert`` to PEM."""
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _name(common_name: str) -> x509.Name:
    """Build a one-attribute :class:`x509.Name` from a CN string."""
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _san_extension(sans: list[str]) -> x509.SubjectAlternativeName:
    """Parse ``sans`` into DNS + IPAddress entries.

    A string that looks like an IP (succeeds ``ipaddress.ip_address``)
    becomes an :class:`x509.IPAddress`; everything else becomes an
    :class:`x509.DNSName`. Email-style CNs (``ops@wg.local``) are
    forwarded as DNSName — the test fixture uses them as opaque
    identifiers, not as RFC822 names.
    """
    import ipaddress

    entries: list[x509.GeneralName] = []
    for raw in sans:
        try:
            entries.append(x509.IPAddress(ipaddress.ip_address(raw)))
        except ValueError:
            entries.append(x509.DNSName(raw))
    return x509.SubjectAlternativeName(entries)


class LocalDevPKI:
    """In-process root + intermediate hierarchy. Dev / test backend only.

    Use :meth:`generate` for a fresh hierarchy (the test fixture path)
    or :meth:`from_pem` when an operator pins the four PEMs via
    ``PKI_LOCAL_DEV_*`` for cross-restart stability.
    """

    name = "local"

    def __init__(
        self,
        *,
        root_cert: x509.Certificate,
        root_key: EllipticCurvePrivateKey,
        intermediate_cert: x509.Certificate,
        intermediate_key: EllipticCurvePrivateKey,
    ) -> None:
        """Bind to an already-built root + intermediate pair.

        Prefer :meth:`generate` / :meth:`from_pem`; this constructor is
        public mostly so tests can inject a known hierarchy.
        """
        self._root_cert = root_cert
        self._root_key = root_key
        self._intermediate_cert = intermediate_cert
        self._intermediate_key = intermediate_key
        # Revoked serials are kept in a set so :meth:`crl_pem` produces a
        # stable CRL for the lifetime of the backend instance. The dev
        # backend's CRL doesn't persist across restarts — production is
        # Vault, which keeps the CRL on its own storage.
        self._revoked: set[int] = set()

    # ------------------------------------------------------------------
    # Factories
    # ------------------------------------------------------------------

    @classmethod
    def generate(cls) -> "LocalDevPKI":
        """Build a fresh root + intermediate, both signed in-process."""
        root_key = _new_ec_key()
        now = datetime.now(timezone.utc)
        root_cert = (
            x509.CertificateBuilder()
            .subject_name(_name(_DEV_ROOT_CN))
            .issuer_name(_name(_DEV_ROOT_CN))
            .public_key(root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + _TEN_YEARS)
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=1), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(root_key, hashes.SHA256())
        )

        intermediate_key = _new_ec_key()
        intermediate_cert = (
            x509.CertificateBuilder()
            .subject_name(_name(_DEV_INT_CN))
            .issuer_name(root_cert.subject)
            .public_key(intermediate_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + _ONE_YEAR)
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(root_key, hashes.SHA256())
        )
        return cls(
            root_cert=root_cert,
            root_key=root_key,
            intermediate_cert=intermediate_cert,
            intermediate_key=intermediate_key,
        )

    @classmethod
    def from_pem(
        cls,
        *,
        root_pem: str,
        root_key_pem: str,
        intermediate_pem: str,
        intermediate_key_pem: str,
    ) -> "LocalDevPKI":
        """Load a previously-generated hierarchy from four PEM bodies.

        :raises PKIError: If any PEM is malformed or the intermediate
            isn't directly issued by the root.
        """
        try:
            root_cert = x509.load_pem_x509_certificate(root_pem.encode())
            root_key = load_pem_private_key(root_key_pem.encode(), password=None)
            int_cert = x509.load_pem_x509_certificate(intermediate_pem.encode())
            int_key = load_pem_private_key(
                intermediate_key_pem.encode(), password=None
            )
        except (ValueError, TypeError) as exc:
            raise PKIError(f"could not load pinned PEMs: {exc}") from exc
        if not isinstance(root_key, EllipticCurvePrivateKey):
            raise PKIError(
                f"root key must be EC P-256, got {type(root_key).__name__}"
            )
        if not isinstance(int_key, EllipticCurvePrivateKey):
            raise PKIError(
                f"intermediate key must be EC P-256, got {type(int_key).__name__}"
            )
        try:
            int_cert.verify_directly_issued_by(root_cert)
        except Exception as exc:
            raise PKIError(
                f"pinned intermediate is not signed by pinned root: {exc}"
            ) from exc
        return cls(
            root_cert=root_cert,
            root_key=root_key,
            intermediate_cert=int_cert,
            intermediate_key=int_key,
        )

    # ------------------------------------------------------------------
    # Operator-facing PEM accessors (so an auto-generated hierarchy can
    # be copied out and pinned via env for the next process).
    # ------------------------------------------------------------------

    @property
    def root_pem(self) -> str:
        """Root cert in PEM. Stable for the life of the backend."""
        return _cert_pem(self._root_cert)

    @property
    def root_key_pem(self) -> str:
        """Root private key in PEM. **Never** log or persist outside dev."""
        return _key_pem(self._root_key)

    @property
    def intermediate_pem(self) -> str:
        """Intermediate cert in PEM."""
        return _cert_pem(self._intermediate_cert)

    @property
    def intermediate_key_pem(self) -> str:
        """Intermediate private key in PEM. **Never** log."""
        return _key_pem(self._intermediate_key)

    @property
    def ca_bundle_pem(self) -> str:
        """Intermediate + root, in trust-anchor order (intermediate first).

        Including the intermediate in the bundle keeps the contract
        simple — a TLS client trusting this file accepts a leaf even
        if the peer fails to forward the intermediate on the wire.
        Test :meth:`test_ca_bundle_parses_as_a_chain` pins
        "last cert is self-signed", which still holds.
        """
        return self.intermediate_pem + self.root_pem

    # ------------------------------------------------------------------
    # Issuance
    # ------------------------------------------------------------------

    def _issue(
        self,
        *,
        common_name: str,
        sans: list[str],
        ttl_seconds: int,
        eku: x509.ExtendedKeyUsage,
    ) -> Cert:
        """Issue a leaf signed by the intermediate."""
        leaf_key = _new_ec_key()
        now = datetime.now(timezone.utc)
        not_before = now - timedelta(minutes=1)
        not_after = now + timedelta(seconds=ttl_seconds)
        serial = x509.random_serial_number()
        try:
            leaf = (
                x509.CertificateBuilder()
                .subject_name(_name(common_name))
                .issuer_name(self._intermediate_cert.subject)
                .public_key(leaf_key.public_key())
                .serial_number(serial)
                .not_valid_before(not_before)
                .not_valid_after(not_after)
                .add_extension(
                    x509.BasicConstraints(ca=False, path_length=None),
                    critical=True,
                )
                .add_extension(_san_extension(sans), critical=False)
                .add_extension(eku, critical=False)
                .sign(self._intermediate_key, hashes.SHA256())
            )
        except (ValueError, TypeError) as exc:
            raise PKIError(f"failed to sign leaf: {exc}") from exc
        return Cert(
            cert_pem=_cert_pem(leaf),
            private_pem=_key_pem(leaf_key),
            chain_pem=self.intermediate_pem + self.root_pem,
            serial=serial,
            common_name=common_name,
            sans=tuple(sans),
            not_before=not_before.replace(tzinfo=timezone.utc),
            not_after=not_after.replace(tzinfo=timezone.utc),
        )

    def issue_server_cert(
        self, *, common_name: str, sans: list[str], ttl_seconds: int
    ) -> Cert:
        """Issue a serverAuth leaf cert."""
        return self._issue(
            common_name=common_name,
            sans=sans,
            ttl_seconds=ttl_seconds,
            eku=x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
        )

    def issue_client_cert(
        self, *, common_name: str, sans: list[str], ttl_seconds: int
    ) -> Cert:
        """Issue a clientAuth leaf cert."""
        return self._issue(
            common_name=common_name,
            sans=sans,
            ttl_seconds=ttl_seconds,
            eku=x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
        )

    # ------------------------------------------------------------------
    # Revocation
    # ------------------------------------------------------------------

    def revoke_cert(self, *, serial: int) -> None:
        """Record ``serial`` as revoked. Future :meth:`crl_pem` reflects it."""
        self._revoked.add(serial)

    def crl_pem(self) -> str:
        """Return the CRL signed by the intermediate, in PEM form."""
        now = datetime.now(timezone.utc)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self._intermediate_cert.subject)
            .last_update(now)
            .next_update(now + timedelta(days=7))
        )
        for serial in sorted(self._revoked):
            builder = builder.add_revoked_certificate(
                x509.RevokedCertificateBuilder()
                .serial_number(serial)
                .revocation_date(now)
                .build()
            )
        try:
            crl = builder.sign(self._intermediate_key, hashes.SHA256())
        except (ValueError, TypeError) as exc:
            raise PKIError(f"failed to sign CRL: {exc}") from exc
        return crl.public_bytes(serialization.Encoding.PEM).decode("ascii")


# ---------------------------------------------------------------------------
# Vault backend
# ---------------------------------------------------------------------------


_HEX_COLON_TRANS = str.maketrans("", "", ":")


def _hex_colon_to_int(serial_hex: str) -> int:
    """Convert Vault's ``ab:cd:ef`` serial string to an integer."""
    return int(serial_hex.translate(_HEX_COLON_TRANS), 16)


def _int_to_hex_colon(serial: int) -> str:
    """Format ``serial`` as the colon-separated hex Vault revocation takes."""
    raw = f"{serial:x}"
    if len(raw) % 2:
        raw = "0" + raw
    return ":".join(raw[i : i + 2] for i in range(0, len(raw), 2))


class VaultPKI:
    """Vault PKI backend with a two-tier root → intermediate hierarchy.

    The CA private keys never leave Vault. We hold an authenticated
    :class:`hvac.Client` and the mount + role names that
    :meth:`bootstrap` (or an operator running ``make pki-bootstrap``)
    previously configured. Each :meth:`issue_*` / :meth:`revoke_cert`
    call makes one Vault round-trip.
    """

    name = "vault"

    def __init__(
        self,
        *,
        client: hvac.Client,
        root_mount: str,
        intermediate_mount: str,
        server_role: str,
        client_role: str,
        ca_bundle_pem: str,
    ) -> None:
        """Bind to an already-bootstrapped pair of mounts. Prefer :meth:`bootstrap`."""
        self._client = client
        self._root_mount = root_mount
        self._int_mount = intermediate_mount
        self._server_role = server_role
        self._client_role = client_role
        self._ca_bundle_pem = ca_bundle_pem

    # ------------------------------------------------------------------
    # Bootstrap
    # ------------------------------------------------------------------

    @classmethod
    def bootstrap(
        cls,
        *,
        client: hvac.Client,
        root_mount: str,
        intermediate_mount: str,
        server_role: str,
        client_role: str,
        allowed_domains: str = "",
        max_ttl: str = "8760h",
    ) -> "VaultPKI":
        """Configure root + intermediate + the two roles idempotently.

        Safe to call repeatedly: each step either succeeds outright or
        swallows the specific "already exists" shape Vault returns.

        :param client: An authenticated :class:`hvac.Client`.
        :param root_mount: Mount path for the root PKI engine. The
            cookbook convention is ``pki``.
        :param intermediate_mount: Mount path for the intermediate
            PKI engine — the surface wg-manager issues leaves from.
            The cookbook convention is ``pki_int``.
        :param server_role: Role name created on the intermediate mount
            for ``serverAuth`` leaves (API + MySQL server certs).
        :param client_role: Role name created on the intermediate mount
            for ``clientAuth`` leaves (operator + CLI certs).
        :param allowed_domains: Comma-separated list of domain names
            the *server* role accepts. Empty (the default) is
            interpreted as "any name" — appropriate for IP-only
            fleets and the first ``make pki-bootstrap`` run.
            Production deployments with stable DNS should pass the
            real list (``"wg.local,vpn.example.com"``).
        :param max_ttl: ``max_ttl`` set on both roles. Defaults to
            1 year so renewal jobs (CP4) have headroom; the per-issue
            ``ttl_seconds`` arg controls actual leaf lifetimes.
        :raises PKIError: If Vault rejects the configuration for a
            reason other than "already exists".
        """
        try:
            # 1. Enable both mounts (root + intermediate) and tune their
            #    max-lease TTL so the long-lived CA certs aren't capped
            #    at Vault's default 32-day system max. Without the tune
            #    the 10y root TTL we ask for gets silently clipped to
            #    ~768h; leaves issued under that role then can't outlive
            #    the cap either, defeating the point of a CA.
            for mount, max_lease in (
                (root_mount, "87600h"),  # 10y for the root
                (intermediate_mount, "43800h"),  # 5y for the intermediate
            ):
                try:
                    client.sys.enable_secrets_engine(
                        backend_type="pki",
                        path=mount,
                        config={"max_lease_ttl": max_lease},
                    )
                except InvalidRequest as exc:
                    if "path is already in use" not in str(exc):
                        raise
                # Tune on every bootstrap so re-runs after an operator
                # extends the TTL pick up the new value.
                client.sys.tune_mount_configuration(
                    path=mount, max_lease_ttl=max_lease
                )

            # 2. Generate the root if missing. ``generate_root`` is
            # 204-on-rerun in modern Vault, 400-with-already-exists in
            # older versions. Treat both as success.
            try:
                client.secrets.pki.generate_root(
                    type="internal",
                    common_name="wg-manager PKI root",
                    extra_params={"ttl": "87600h"},  # 10 years
                    mount_point=root_mount,
                )
            except InvalidRequest as exc:
                if (
                    "already exists" not in str(exc).lower()
                    and "cannot be generated" not in str(exc).lower()
                ):
                    raise

            # 3. Generate the intermediate's CSR (returns the CSR body).
            #    On re-runs against a bootstrapped mount, the
            #    intermediate already exists and ``ca_chain`` already
            #    resolves — skip the sign/install steps in that case.
            existing_chain = cls._read_int_ca_chain(client, intermediate_mount)
            if not existing_chain:
                csr_resp = client.secrets.pki.generate_intermediate(
                    type="internal",
                    common_name="wg-manager PKI intermediate",
                    extra_params={"key_type": "ec", "key_bits": 256},
                    mount_point=intermediate_mount,
                )
                csr_pem = csr_resp["data"]["csr"]
                # 4. Sign the CSR with the root.
                signed = client.secrets.pki.sign_intermediate(
                    csr=csr_pem,
                    common_name="wg-manager PKI intermediate",
                    extra_params={"ttl": "43800h"},  # 5 years
                    mount_point=root_mount,
                )
                int_cert_pem = signed["data"]["certificate"]
                # 5. Install the signed cert back on the intermediate
                # *with the root concatenated* so ``/<int>/ca_chain``
                # returns the full path back to a self-signed anchor.
                # Without the root concatenation, Vault stores only
                # the intermediate and TLS clients trusting the bundle
                # can't build a path: leaf → int → ??? (the test
                # `test_chain_validates_back_to_bundle_root` pins this
                # contract).
                root_pem = cls._read_root_cert_pem(client, root_mount)
                client.secrets.pki.set_signed_intermediate(
                    certificate=int_cert_pem.rstrip() + "\n" + root_pem,
                    mount_point=intermediate_mount,
                )

            # 6. Create / update the two leaf roles.
            cls._upsert_role(
                client=client,
                mount=intermediate_mount,
                role=server_role,
                allowed_domains=allowed_domains,
                server_flag=True,
                client_flag=False,
                max_ttl=max_ttl,
            )
            cls._upsert_role(
                client=client,
                mount=intermediate_mount,
                role=client_role,
                allowed_domains=allowed_domains,
                server_flag=False,
                client_flag=True,
                max_ttl=max_ttl,
            )
        except VaultError as exc:
            raise PKIError(
                f"PKI bootstrap failed (root={root_mount!r}, "
                f"int={intermediate_mount!r}): {exc}"
            ) from exc

        bundle = cls._read_int_ca_chain(client, intermediate_mount)
        if not bundle:
            raise PKIError(
                f"intermediate at {intermediate_mount!r} reports no ca_chain — "
                "bootstrap installed nothing"
            )
        return cls(
            client=client,
            root_mount=root_mount,
            intermediate_mount=intermediate_mount,
            server_role=server_role,
            client_role=client_role,
            ca_bundle_pem=bundle,
        )

    @staticmethod
    def _upsert_role(
        *,
        client: hvac.Client,
        mount: str,
        role: str,
        allowed_domains: str,
        server_flag: bool,
        client_flag: bool,
        max_ttl: str,
    ) -> None:
        """Create or overwrite a leaf role with the right flags.

        Server roles enforce ``allowed_domains`` so an attacker can't
        coerce the CA into minting ``mysql.attacker.example``-style
        impersonation certs. Client roles run with ``allow_any_name``
        so operator-style CNs (``ops@wg.local``) and email-shape
        identifiers work — the test suite covers both shapes.
        """
        params: dict[str, Any] = {
            "max_ttl": max_ttl,
            "ttl": max_ttl,
            "key_type": "ec",
            "key_bits": 256,
            "allow_ip_sans": True,
            "allow_subdomains": True,
            # ``allow_bare_domains`` is the inverse of the cliff that
            # bit Phase 2c CP4.2.1: without it, asking the server role
            # for a SAN of the bare allowed-domain (``wg.local`` when
            # ``allowed_domains=[wg.local]``) is silently dropped from
            # the issued cert. The test
            # ``test_server_cert_sans_match_request`` pins the contract
            # "every requested SAN ends up in the cert".
            "allow_bare_domains": True,
            "server_flag": server_flag,
            "client_flag": client_flag,
            "enforce_hostnames": False,
        }
        if allowed_domains:
            params["allowed_domains"] = [
                d.strip() for d in allowed_domains.split(",") if d.strip()
            ]
            # Server certs must live inside the allowed set; client
            # certs get a permissive shape so operator CNs work.
            params["allow_any_name"] = client_flag
        else:
            # No allowed_domains pinned → accept any name. Dev /
            # IP-only fleets land here.
            params["allow_any_name"] = True

        client.secrets.pki.create_or_update_role(
            name=role,
            extra_params=params,
            mount_point=mount,
        )

    @staticmethod
    def _read_root_cert_pem(client: hvac.Client, mount: str) -> str:
        """Fetch the root cert PEM body from ``/v1/<root_mount>/ca/pem``.

        Returns an empty string on absence — the bootstrap is the only
        caller and treats that as a hard error, but we keep the
        function permissive so the failure shows up in the caller's
        context rather than as a ``VaultError`` raised here.
        """
        try:
            resp = client.adapter.get(f"/v1/{mount}/ca/pem")
        except (InvalidPath, InvalidRequest):
            return ""
        text = getattr(resp, "text", None) or ""
        return text if "BEGIN CERTIFICATE" in text else ""

    @staticmethod
    def _read_int_ca_chain(client: hvac.Client, mount: str) -> str:
        """Read the intermediate's PEM ``ca_chain`` body.

        Returns an empty string when the intermediate hasn't been
        bootstrapped yet — the absence shows up in three different
        shapes depending on Vault version:

        * 404 with no body (raises :class:`InvalidPath`),
        * 400 with ``no default issuer currently configured`` (raises
          :class:`InvalidRequest` / generic :class:`VaultError`),
        * 200 with an empty body.

        Treat all three as "not bootstrapped" so :meth:`bootstrap` can
        cleanly tell "first run" from "re-run after success".

        We hit ``/v1/<mount>/ca_chain`` (raw PEM body returned as
        ``Response.text``) rather than ``/v1/<mount>/cert/ca_chain``
        (returns JSON whose ``data.ca_chain`` is empty on Vault 1.18 —
        the JSON endpoint surfaces issuer metadata, not the bundle).
        """
        try:
            resp = client.adapter.get(f"/v1/{mount}/ca_chain")
        except (InvalidPath, InvalidRequest):
            return ""
        except VaultError as exc:
            if "no default issuer" in str(exc).lower():
                return ""
            raise
        # On hvac, an endpoint that returns JSON yields a plain dict
        # (already parsed); a raw-text endpoint yields a Response with
        # ``.text``. ``/ca_chain`` is text-bearing, so the dict shape
        # here means Vault sent us back an empty body.
        text = getattr(resp, "text", None)
        if text and "BEGIN CERTIFICATE" in text:
            return text
        return ""

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def ca_bundle_pem(self) -> str:
        """The trust-anchor bundle resolved at bootstrap time."""
        return self._ca_bundle_pem

    # ------------------------------------------------------------------
    # Issuance
    # ------------------------------------------------------------------

    def _issue(
        self, *, role: str, common_name: str, sans: list[str], ttl_seconds: int
    ) -> Cert:
        """Single Vault issue round-trip."""
        import ipaddress

        dns_sans: list[str] = []
        ip_sans: list[str] = []
        for raw in sans:
            try:
                ipaddress.ip_address(raw)
                ip_sans.append(raw)
            except ValueError:
                dns_sans.append(raw)

        extra: dict[str, Any] = {"ttl": f"{ttl_seconds}s"}
        if dns_sans:
            extra["alt_names"] = ",".join(dns_sans)
        if ip_sans:
            extra["ip_sans"] = ",".join(ip_sans)

        from wg_manager.metrics import vault_call

        try:
            with vault_call(engine="pki", operation="issue"):
                resp = self._client.secrets.pki.generate_certificate(
                    name=role,
                    common_name=common_name,
                    extra_params=extra,
                    mount_point=self._int_mount,
                )
        except VaultError as exc:
            raise PKIError(
                f"vault refused to issue ({role}, cn={common_name!r}): {exc}"
            ) from exc

        data = resp["data"]
        cert_pem = data["certificate"]
        private_pem = data["private_key"]
        serial = _hex_colon_to_int(data["serial_number"])

        # Vault returns the issuing chain as a list (modern) or single
        # PEM string (older). Normalise to one PEM blob.
        ca_chain = data.get("ca_chain") or []
        if isinstance(ca_chain, str):
            chain_pem = ca_chain
        else:
            chain_pem = "".join(ca_chain)
        if not chain_pem:
            # Some Vault versions still surface only ``issuing_ca`` when
            # there's a single intermediate above the leaf.
            chain_pem = data.get("issuing_ca", "")

        parsed = x509.load_pem_x509_certificate(cert_pem.encode())
        return Cert(
            cert_pem=cert_pem,
            private_pem=private_pem,
            chain_pem=chain_pem,
            serial=serial,
            common_name=common_name,
            sans=tuple(sans),
            not_before=parsed.not_valid_before_utc,
            not_after=parsed.not_valid_after_utc,
        )

    def issue_server_cert(
        self, *, common_name: str, sans: list[str], ttl_seconds: int
    ) -> Cert:
        """Issue a ``serverAuth`` leaf via the configured server role."""
        return self._issue(
            role=self._server_role,
            common_name=common_name,
            sans=sans,
            ttl_seconds=ttl_seconds,
        )

    def issue_client_cert(
        self, *, common_name: str, sans: list[str], ttl_seconds: int
    ) -> Cert:
        """Issue a ``clientAuth`` leaf via the configured client role."""
        return self._issue(
            role=self._client_role,
            common_name=common_name,
            sans=sans,
            ttl_seconds=ttl_seconds,
        )

    # ------------------------------------------------------------------
    # Revocation
    # ------------------------------------------------------------------

    def revoke_cert(self, *, serial: int) -> None:
        """Mark ``serial`` revoked on the intermediate mount."""
        from wg_manager.metrics import vault_call

        try:
            with vault_call(engine="pki", operation="revoke"):
                self._client.secrets.pki.revoke_certificate(
                    serial_number=_int_to_hex_colon(serial),
                    mount_point=self._int_mount,
                )
        except VaultError as exc:
            raise PKIError(
                f"vault refused to revoke serial {serial}: {exc}"
            ) from exc

    def crl_pem(self) -> str:
        """Read the intermediate's current CRL in PEM form."""
        from wg_manager.metrics import vault_call

        try:
            with vault_call(engine="pki", operation="read-crl"):
                resp = self._client.adapter.get(f"/v1/{self._int_mount}/crl/pem")
        except VaultError as exc:
            raise PKIError(f"could not read CRL: {exc}") from exc
        text = getattr(resp, "text", None) or ""
        if "BEGIN X509 CRL" not in text:
            raise PKIError(
                f"unexpected CRL body from vault (first 40 chars: {text[:40]!r})"
            )
        return text


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


# Per-process cache for :class:`LocalDevPKI`. Keyed by the tuple of
# pinned PEMs (or ``None`` when nothing is pinned). Mirrors the cache
# pattern in :mod:`wg_manager.ssh_ca` — without it, the API process and
# the Celery worker would each hold a different root and mTLS
# verification would break on the second hop.
_LOCAL_PKI_CACHE: dict[tuple[str | None, ...], LocalDevPKI] = {}


def make_pki_backend(settings: Settings | None = None) -> PKIBackend:
    """Return the backend selected by ``settings.pki_backend``.

    Mirrors :func:`wg_manager.crypto.make_backend` and
    :func:`wg_manager.ssh_ca.make_ssh_ca_backend` so the three layers
    feel uniform to read.

    The local backend is memoised per-process (see
    :data:`_LOCAL_PKI_CACHE`): the first call builds (or loads) the
    hierarchy, every subsequent call with the same pinned PEM tuple
    returns the same backend instance.

    :param settings: Optional explicit settings instance; defaults to a
        fresh :class:`Settings` (which re-reads ``.env`` and environment).
    :raises ValueError: If ``pki_backend`` isn't one of ``"local"`` /
        ``"vault"``.
    :raises PKIError: If the selected backend can't be constructed
        (Vault unreachable, mismatched pinned PEMs, …).
    """
    if settings is None:
        settings = Settings()
    backend = settings.pki_backend.lower()
    if backend == "local":
        pinned = (
            settings.pki_local_dev_root_pem,
            settings.pki_local_dev_root_key_pem,
            settings.pki_local_dev_int_pem,
            settings.pki_local_dev_int_key_pem,
        )
        cached = _LOCAL_PKI_CACHE.get(pinned)
        if cached is not None:
            return cached
        if any(pinned) and not all(pinned):
            raise PKIError(
                "PKI_LOCAL_DEV_* must be set as a complete set "
                "(root_pem, root_key_pem, int_pem, int_key_pem) or none"
            )
        if all(pinned):
            ca = LocalDevPKI.from_pem(
                root_pem=pinned[0],  # type: ignore[arg-type]
                root_key_pem=pinned[1],  # type: ignore[arg-type]
                intermediate_pem=pinned[2],  # type: ignore[arg-type]
                intermediate_key_pem=pinned[3],  # type: ignore[arg-type]
            )
        else:
            ca = LocalDevPKI.generate()
        _LOCAL_PKI_CACHE[pinned] = ca
        return ca
    if backend == "vault":
        if not settings.crypto_vault_token:
            raise PKIError(
                "VAULT_TOKEN (or CRYPTO_VAULT_TOKEN) is required for the "
                "vault PKI backend"
            )
        client = hvac.Client(
            url=settings.crypto_vault_addr,
            token=settings.crypto_vault_token,
        )
        bundle = VaultPKI._read_int_ca_chain(
            client, settings.pki_vault_int_mount
        )
        if not bundle:
            raise PKIError(
                f"intermediate at {settings.pki_vault_int_mount!r} is not "
                "bootstrapped — run `make pki-bootstrap` first"
            )
        return VaultPKI(
            client=client,
            root_mount=settings.pki_vault_root_mount,
            intermediate_mount=settings.pki_vault_int_mount,
            server_role=settings.pki_vault_server_role,
            client_role=settings.pki_vault_client_role,
            ca_bundle_pem=bundle,
        )
    raise ValueError(
        f"unknown PKI backend {settings.pki_backend!r}; "
        "expected 'local' or 'vault'"
    )
