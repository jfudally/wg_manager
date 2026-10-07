#!/usr/bin/env bash
#
# terraform_check.sh: fmt-check, init (no backend) and validate every
# Terraform root under deploy/terraform. Backs `make terraform-check`.
#
# Uses a local `terraform` when one is on PATH, otherwise the pinned
# hashicorp/terraform image via Docker, so contributors don't need
# Terraform installed. `init` downloads providers from the registry, so
# this needs network access; set TF_PLUGIN_CACHE_DIR to reuse downloads.
#
# Exit status: non-zero on the first formatting or validation failure.

set -euo pipefail

TERRAFORM_IMAGE="${TERRAFORM_IMAGE:-hashicorp/terraform:1.13}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TF_ROOT="deploy/terraform"
# Directories that are Terraform roots (the module and each example).
TF_DIRS=(
  "wg-manager-enrollment-token"
  "examples/aws-instance"
)

tf() {
  if command -v terraform >/dev/null 2>&1; then
    (cd "${REPO_ROOT}/${TF_ROOT}" && terraform "$@")
  else
    local cache="${TF_PLUGIN_CACHE_DIR:-${REPO_ROOT}/.terraform-plugin-cache}"
    mkdir -p "${cache}"
    docker run --rm \
      -u "$(id -u):$(id -g)" \
      -e HOME=/tmp \
      -e TF_PLUGIN_CACHE_DIR=/cache \
      -v "${cache}:/cache" \
      -v "${REPO_ROOT}/${TF_ROOT}:/w" \
      -w /w \
      "${TERRAFORM_IMAGE}" "$@"
  fi
}

echo "terraform fmt -check"
tf fmt -check -recursive -diff

for dir in "${TF_DIRS[@]}"; do
  echo "terraform validate: ${dir}"
  # -upgrade: resolve providers fresh from the version constraints. No
  # lock files are committed (see .gitignore), so a stale local one must
  # not pin an old choice.
  tf -chdir="${dir}" init -upgrade -backend=false -input=false -no-color >/dev/null
  tf -chdir="${dir}" validate -no-color
done
