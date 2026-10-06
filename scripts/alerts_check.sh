#!/usr/bin/env bash
# =====================================================================
# Validate docs/observability/prometheus-alerts.yaml with the real
# promtool (Phase 3d cycle 5e). Entry point for `make alerts-check`;
# tests/test_prometheus_alerts.py runs it too.
#
#   1. `promtool check rules` on the shipped file.
#   2. `promtool test rules` on prometheus-alerts.test.yaml, against a
#      copy of the rules with annotations stripped. promtool compares
#      annotations exactly, and pinning paragraphs of prose would make
#      every wording fix a test change. The tests pin what matters for
#      paging: expressions, `for:` durations and labels.
#
# promtool runs from the Prometheus image, so nothing is installed on
# the host.
#
# Env:
#   PROMTOOL_IMAGE   (default: prom/prometheus:v3.5.0)
#   DOCKER           (default: docker)
#   PYTHON           a python with PyYAML (default: python3)
# =====================================================================

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OBS="$REPO_DIR/docs/observability"
PROMTOOL_IMAGE="${PROMTOOL_IMAGE:-prom/prometheus:v3.5.0}"
DOCKER="${DOCKER:-docker}"
PYTHON="${PYTHON:-python3}"

promtool() {
    local dir="$1"; shift
    "$DOCKER" run --rm -v "$dir:/rules:ro" -w /rules --entrypoint promtool "$PROMTOOL_IMAGE" "$@"
}

echo "==> promtool check rules"
promtool "$OBS" check rules prometheus-alerts.yaml

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
chmod 755 "$work"
cp "$OBS/prometheus-alerts.test.yaml" "$work/"
"$PYTHON" - "$OBS/prometheus-alerts.yaml" "$work/prometheus-alerts.yaml" <<'PY'
import sys
import yaml

with open(sys.argv[1]) as fh:
    doc = yaml.safe_load(fh)
for group in doc.get("groups", []):
    for rule in group.get("rules", []):
        rule.pop("annotations", None)
with open(sys.argv[2], "w") as fh:
    yaml.safe_dump(doc, fh, sort_keys=False)
PY
chmod 644 "$work"/*

echo "==> promtool test rules (annotations stripped)"
promtool "$work" test rules prometheus-alerts.test.yaml
