"""Phase 2c CP5 end-to-end suite.

These tests boot the dockerised ``sshd-e2e`` container declared in
the root ``docker-compose.yml`` (under the ``e2e`` profile) and the
dev Vault container that ``make vault-up`` brings up. They prove
that the cert-based SSH path lands a working connection against a
real OpenSSH server — i.e., the Phase 2c contract holds outside the
``FakeSSHRunner`` world the rest of the suite uses.

Run with ``make test-e2e`` (sets ``-m e2e`` to opt in past the
default ``-m 'not e2e'`` deselection in ``pyproject.toml``). The
fast suite (``make test``) skips them entirely so day-to-day work
doesn't need docker + Vault running.
"""
