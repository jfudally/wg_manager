#!/bin/sh
# Phase 2c CP5 e2e sshd entrypoint.
#
# Generate fresh host keys, prime empty placeholder files for the
# bind-mounted ``TrustedUserCAKeys`` and ``HostCertificate`` paths
# (sshd refuses to start if the configured paths are missing), then
# exec sshd in the foreground.
#
# The test fixture in ``tests/e2e/conftest.py`` overwrites the
# placeholders after the container is up and SIGHUPs sshd to pick up
# the new material. Doing it that way (rather than baking the CA into
# the image) keeps the image session-independent — one image, every
# test run gets a fresh CA / host cert combo.
set -eu

ssh-keygen -A

# Pre-create both bind-mounted files. Sshd parses ``TrustedUserCAKeys``
# at every connection, so writing the real pubkey in later "just works"
# without a daemon reload; we SIGHUP the host-cert update below anyway
# so the daemon re-reads ``HostCertificate``.
touch /wg-manager-e2e/user-ca.pub
touch /wg-manager-e2e/ssh_host_ed25519_key-cert.pub
chmod 0644 /wg-manager-e2e/user-ca.pub /wg-manager-e2e/ssh_host_ed25519_key-cert.pub

exec /usr/sbin/sshd -D -e
