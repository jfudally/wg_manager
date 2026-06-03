# wg-manager API + worker image (Phase 2f cycle 1).
#
# Multi-stage build:
#  * ``builder`` — installs uv, runs ``uv sync --frozen --no-dev``
#    against the pyproject.toml + uv.lock that cycle 3's lockfile gate
#    enforces. The whole ``.venv`` lands here.
#  * ``runtime`` — slim Python image with only the ``.venv`` and
#    ``src/`` copied over. No uv, no build-essential. Runs as the
#    non-root ``wgmanager`` user.
#
# Default CMD launches the API (``python -m wg_manager`` — the
# canonical mTLS-enforcing entrypoint). Compose service overrides
# launch the Celery worker by replacing the CMD. The CLI
# (``wg-manager …``) is on PATH inside the .venv so docker compose
# exec calls work without extra wrapping.
#
# Cycle 1 builds locally and via the image-build CI workflow. Cycle
# 2 publishes; cycles 3-4 sign + SBOM.

# ---------------------------------------------------------------------------
# Stage 1 — builder: install uv + sync the locked .venv
# ---------------------------------------------------------------------------
# Python version matches pyproject.toml's ``requires-python >= 3.13``.
# Pinning the literal version (not an ARG) keeps the test
# (``tests/test_dockerfile.py``) honest — a future bump must edit the
# FROM line, where it's reviewable, rather than slipping under an arg
# default.
FROM python:3.13-slim-bookworm AS builder

# uv is the canonical installer (matches the local dev workflow + the
# CI gates that already run ``uv sync --frozen``). Pinning the version
# keeps the image build reproducible across rebuilds.
ENV UV_VERSION=0.5.0
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -LsSf https://astral.sh/uv/${UV_VERSION}/install.sh | sh \
    && mv /root/.local/bin/uv /usr/local/bin/uv \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy only the files uv needs to resolve before the source — keeps the
# layer cache hot when src/ changes but deps don't.
COPY pyproject.toml uv.lock README.md ./
COPY src ./src

# ``--frozen`` refuses to update the lockfile (matches cycle 3 gate).
# ``--no-dev`` skips dev deps so the runtime image stays small.
RUN uv sync --frozen --no-dev

# ---------------------------------------------------------------------------
# Stage 2 — runtime: slim base + .venv + src + non-root user
# ---------------------------------------------------------------------------
FROM python:3.13-slim-bookworm AS runtime

# Create the non-root user the runtime stage drops to. Fixed UID/GID so
# bind-mounted volumes from a host operator's home directory have
# predictable ownership.
RUN groupadd --system --gid 1001 wgmanager \
    && useradd --system --uid 1001 --gid wgmanager --create-home wgmanager

WORKDIR /app

# Copy the synced .venv from the builder. The .venv carries every
# runtime dependency — no apt installs needed in this stage.
COPY --from=builder --chown=wgmanager:wgmanager /app/.venv /app/.venv
COPY --from=builder --chown=wgmanager:wgmanager /app/src /app/src
COPY --from=builder --chown=wgmanager:wgmanager /app/pyproject.toml /app/pyproject.toml
COPY --from=builder --chown=wgmanager:wgmanager /app/README.md /app/README.md

# Put the .venv on PATH so ``wg-manager``, ``python``, ``uvicorn``,
# and ``celery`` all resolve without explicit prefixes.
ENV PATH="/app/.venv/bin:${PATH}"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

USER wgmanager

# Default: run the API. The Phase 2d CP2 ``python -m wg_manager``
# entrypoint enforces mTLS and refuses to start without the TLS env
# vars (``TLS_CERT_PEM`` / ``TLS_KEY_PEM`` / ``TLS_CA_BUNDLE_PEM``).
# Operators inject those via env / mounted secrets at run time.
CMD ["python", "-m", "wg_manager"]
