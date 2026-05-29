# Dockerfile for the wg-manager e2e sshd target (Phase 2c CP5).
#
# A deliberately bare-bones OpenSSH server we point the cert-based
# SSH path at from ``tests/e2e/``. The image is *not* trying to be a
# WireGuard host — WireGuard provisioning needs kernel modules that
# Docker Desktop (macOS) doesn't expose. CP5's acceptance criterion
# is "the cert path works end-to-end against a real sshd," not "we
# re-validate Phase 1's WireGuard," so the runtime here is just sshd
# + a couple of harmless commands the tests can shell out to.
#
# Design notes
# ------------
# * ``TrustedUserCAKeys`` and ``HostCertificate`` are wired up to
#   bind-mounted paths under ``/wg-manager-e2e/``. The test fixture
#   writes the Vault CA pubkey and the host cert into that volume
#   *after* the container starts, so the image itself stays free of
#   per-session material (no rebuilds between sessions).
# * The entrypoint pre-creates the two files as empty placeholders.
#   ``TrustedUserCAKeys`` pointing at an empty (but existing) file
#   is OK with sshd — it just trusts nothing until the fixture
#   writes the real pubkey in.
# * Host keys are generated on every container start (``ssh-keygen -A``)
#   so each session gets a fresh keypair; the test fixture pulls the
#   ed25519 pubkey out before asking the CA to sign it.
# * The non-root login user is ``wguser`` with passwordless sudo so
#   tests can mirror the production task path (which calls
#   ``runner.sudo(...)``). No SSH password is set — cert auth only.

FROM debian:bookworm-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        openssh-server \
        sudo \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd /wg-manager-e2e \
    && useradd --create-home --shell /bin/bash wguser \
    # Set the password field to "*" so the account is *unlocked* but
    # has no valid password — sshd's account-locked check passes,
    # password auth still can't succeed (it's also disabled in the
    # sshd drop-in below), and cert-based pubkey auth becomes the
    # only legal path. Without this, useradd's default ``!`` password
    # leaves the account "locked" and sshd refuses cert auth too
    # (logs ``User wguser not allowed because account is locked``).
    && usermod -p '*' wguser \
    && echo "wguser ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/wguser \
    && chmod 0440 /etc/sudoers.d/wguser

# sshd drop-in: cert auth only, point ``TrustedUserCAKeys`` and the
# host cert at the bind-mounted directory the fixture controls.
RUN printf '%s\n' \
    'PasswordAuthentication no' \
    'PubkeyAuthentication yes' \
    'PermitRootLogin no' \
    'ChallengeResponseAuthentication no' \
    'UsePAM no' \
    'TrustedUserCAKeys /wg-manager-e2e/user-ca.pub' \
    'HostCertificate /wg-manager-e2e/ssh_host_ed25519_key-cert.pub' \
    'HostKey /etc/ssh/ssh_host_ed25519_key' \
    > /etc/ssh/sshd_config.d/wg-manager-e2e.conf

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 22

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
