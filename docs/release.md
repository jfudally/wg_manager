# Cutting a release

This is the operator runbook for shipping a tagged release. The
release workflow (`.github/workflows/release.yml`) handles the
actual publish; this doc walks the human side.

## What a release ships

A single `git push origin v<X.Y.Z>` produces:

- Two Docker images on GHCR:
  - `ghcr.io/<owner>/wg-manager:v<X.Y.Z>` — API + worker
  - `ghcr.io/<owner>/wg-manager-web:v<X.Y.Z>` — dashboard
- Each image carries the full semver tag set (`vX.Y.Z`, `vX.Y`,
  `vX`), the commit SHA, and the `latest` floating tag, so
  consumers pin to whatever granularity they want.
- A GitHub release at `v<X.Y.Z>` whose body is the matching
  `## [v<X.Y.Z>]` section from `CHANGELOG.md` plus a footer with
  the image-pull lines.

Phase 2f cycle 2 ships this much. Cycle 3 layers cosign keyless
signing on top; cycle 4 attaches SBOMs to the GitHub release.

## Pre-flight checklist

Before tagging:

- [ ] `make lockfiles` passes — pyproject.toml/uv.lock and
      web/package*.json are in sync (CI re-checks this).
- [ ] `make test` passes — backend suite + dashboard vitest.
- [ ] `git status` is clean on `main`.
- [ ] `CHANGELOG.md` is up to date and has the version's
      content in the `## [Unreleased]` section.

## Promote `## [Unreleased]` → `## [vX.Y.Z]`

The release workflow extracts release notes by walking
`CHANGELOG.md` for a `## [v<X.Y.Z>]` heading. A missing heading
fails the workflow with a clear "no `## [vX.Y.Z]` heading" error —
the workflow refuses to publish a release with empty notes.

Promote with a small commit:

```bash
DATE=$(date -u +%Y-%m-%d)
VERSION=v0.1.0   # adjust

# Replace the Unreleased heading with the versioned one + add a
# fresh empty Unreleased section above for next time.
python - <<EOF
from pathlib import Path
path = Path("CHANGELOG.md")
body = path.read_text()
versioned = f"## [{VERSION}] - $DATE"
fresh = "## [Unreleased]\n\n### Added\n\n"
path.write_text(body.replace(
    "## [Unreleased]",
    fresh + "\n" + versioned,
    1,
))
EOF

# Preview the extracted notes locally before tagging:
python scripts/extract_changelog.py "${VERSION}"

git add CHANGELOG.md
git commit -m "chore: promote Unreleased to ${VERSION}"
git push origin main
```

## Tag + push

```bash
VERSION=v0.1.0   # adjust

git tag --annotate --message "Release ${VERSION}" "${VERSION}"
git push origin "${VERSION}"
```

The push fires the `Release` workflow at
[Actions → Release](https://github.com/jfudally/wg_manager/actions/workflows/release.yml).

## What happens next

The workflow runs four jobs in this order:

1. **Extract release notes** — walks `CHANGELOG.md`, sets the
   matching `## [vX.Y.Z]` body as the `notes` output. **Fails the
   workflow if the heading is missing**, before any image build
   starts, so a half-published release is not possible.
2. **Build + push API + worker image** — `docker/build-push-action`
   builds from the root `Dockerfile`, logs into GHCR via the
   workflow's `GITHUB_TOKEN`, pushes with the full tag set.
3. **Build + push dashboard image** — same shape against
   `web/Dockerfile`.
4. **Create GitHub release** — `gh release create` with the
   extracted notes + image-pull footer. `--verify-tag` ensures the
   tag exists and matches the workflow's ref.

The two image builds run in parallel; the release job blocks on
both. Cycle 3's cosign signing will land between the image push
and the release creation (signing each pushed image, then
attaching the signature evidence to the release body).

## If a release fails mid-flight

The workflow does **not** `cancel-in-progress` — partial GHCR
pushes are messy enough that letting the job finish is always
preferable to killing it. But two specific failure modes need
human follow-up:

- **One image pushed, the other failed.** GHCR has a half-shipped
  release. Delete the partial tag via the GitHub UI (Packages →
  the image → version → Delete) and re-run the workflow once the
  cause is fixed.
- **Both images pushed, release step failed.** Images are live but
  the GitHub release is missing. Re-run the workflow's `release`
  job; the existing image tags satisfy GHCR's idempotency.

If a release is **incorrect** (bad notes, wrong artifact), do not
re-use the same tag. Cut a `v<X.Y.Z>+1` or `v<X.Y.Z+1>` instead;
GHCR tags are immutable in practice and consumers may have
already pulled `v<X.Y.Z>`.

## Local preview

```bash
make release-notes VERSION=v0.1.0
```

Wraps `python scripts/extract_changelog.py` so the operator can
preview the body the workflow will use before pushing the tag.

## Verifying a published image (Phase 2f cycle 3)

Every image the release workflow publishes is signed via
[cosign](https://github.com/sigstore/cosign) keyless OIDC against
GitHub Actions' Fulcio issuer. The signature lives in GHCR as a
sibling artefact (the same registry/digest, with the
``.sig`` tag suffix).

Two ways to verify:

### From a downstream environment

Before pulling an image into production:

```bash
cosign verify \
    --certificate-identity-regexp \
        'https://github.com/<owner>/wg_manager/.github/workflows/release.yml@.*' \
    --certificate-oidc-issuer \
        'https://token.actions.githubusercontent.com' \
    ghcr.io/<owner>/wg-manager:v0.1.0
```

A successful verification returns the signature payload + a
``Verification for ghcr.io/...`` confirmation line. A failed
verification (tampered image, identity mismatch, wrong issuer)
exits non-zero with a clear error — the consumer pipeline should
gate the pull behind this check.

### From CI

[`.github/workflows/image-verify.yml`](../.github/workflows/image-verify.yml)
runs the same verify against both the API + web images on:

- **`workflow_dispatch`** — operator-driven, takes a ``tag`` input
  (defaults to ``latest``). Useful before a planned production
  rollout: queue the workflow against the rollout target tag, watch
  it pass, then push the deploy.
- **Daily cron** (14:00 UTC) — catches supply-chain attacks
  against already-published images (the GHCR artefact gets
  replaced server-side; the replacement's signature doesn't match
  the canonical identity).

The cron failure mode is exactly the alerting trigger an operator
wants: a previously-verified image no longer verifies → someone
tampered with it after the fact. Wire the workflow's failure
notification into your usual on-call channel.

### What the identity binding catches

The verify step pins two things:

- ``--certificate-identity-regexp`` — the Fulcio cert's identity
  must reference the canonical release workflow path in this repo.
  Catches: a signature from a fork's workflow, a stolen-token
  attack from a different repo, a malicious mirror that signed
  with their own OIDC identity.
- ``--certificate-oidc-issuer`` — the Fulcio cert must come from
  GitHub Actions' OIDC issuer. Catches: a Fulcio cert from a
  different OIDC provider (Google, GitLab, ...) being passed off
  as a release signature.

## Software Bill of Materials (Phase 2f cycle 4)

Every release ships two CycloneDX 1.5 SBOMs — one per image —
covering the runtime dep closure of each image. The SBOMs are
delivered two ways:

- **As release assets.** Each GitHub release attaches
  ``sbom-api.cdx.json`` (Python deps from the synced ``.venv``,
  ``--no-dev``) and ``sbom-web.cdx.json`` (Node deps from
  ``web/package-lock.json``, ``--omit dev``). Click the asset link
  on the release page, or `gh release download v0.1.0 --pattern '*.cdx.json'`.
- **As in-toto attestations on the image.** The release workflow
  runs ``cosign attest --type cyclonedx --predicate sbom-*.cdx.json
  <image>@<digest>`` against each pushed image. Same Fulcio
  identity as the signature, so a future verify-attestation gate
  can prove SBOM provenance from the canonical workflow path.

### Verifying the SBOM attestation

```bash
cosign verify-attestation \
    --type cyclonedx \
    --certificate-identity-regexp \
        'https://github.com/<owner>/wg_manager/.github/workflows/release.yml@.*' \
    --certificate-oidc-issuer \
        'https://token.actions.githubusercontent.com' \
    ghcr.io/<owner>/wg-manager:v0.1.0
```

A successful verify returns the in-toto envelope with the
embedded CycloneDX payload — pipe through ``jq -r
'.payload | @base64d | fromjson | .predicate'`` to see the SBOM
itself.

### Diffing two releases

The CycloneDX SBOM round-trips through any SBOM tool that
consumes CycloneDX. To compare two releases for added /
removed deps:

```bash
gh release download v0.1.0 --pattern 'sbom-api.cdx.json' --dir /tmp/old
gh release download v0.2.0 --pattern 'sbom-api.cdx.json' --dir /tmp/new
jq -r '.components[] | "\(.name)@\(.version)"' /tmp/old/sbom-api.cdx.json | sort > /tmp/old.txt
jq -r '.components[] | "\(.name)@\(.version)"' /tmp/new/sbom-api.cdx.json | sort > /tmp/new.txt
diff /tmp/old.txt /tmp/new.txt
```

Same shape for ``sbom-web.cdx.json``.
