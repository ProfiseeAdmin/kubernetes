#!/usr/bin/env bash
set -euo pipefail

REPO_OWNER="${1:-}"
REPO_NAME="${2:-}"
REPO_PATH="${3:-}"
BRANCH="${4:-}"
INCLUDE_OPTIONAL="${5:-false}"

if [[ -z "$REPO_OWNER" || -z "$REPO_NAME" || -z "$REPO_PATH" || -z "$BRANCH" ]]; then
  echo "Usage: $0 <GITHUB_ORG> <REPO_NAME> <PATH_IN_REPO> <BRANCH_OR_TAG> [include_optional:true|false]"
  exit 1
fi

BASE_RAW="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${BRANCH}/${REPO_PATH}"

core_files=(
  "FullyPrivateEKS.yaml"
  "deployprofisee-aws.ps1"
  "deployprofisee-aws-stack.ps1"
  "Settings-aws.yaml"
  "traefik-values.yaml"
  "traefik-values-public.yaml"
)

optional_files=(
  "smb-csi-values.yaml"
  "smb-secret.yaml"
  "smb-storageclass.yaml"
  "smb-pvc.yaml"
  "profisee-ingress.yaml"
  "cert-manager-route53-issuer.yaml"
  "cert-manager-certificate.yaml"
  "route53-credentials-secret.yaml"
  "secretsmanager-cert.example.json"
)

download_file() {
  local file="$1"
  local url="${BASE_RAW}/${file}"
  echo "Downloading ${url}"
  curl -fsSL -o "${file}" "${url}"
}

for f in "${core_files[@]}"; do
  download_file "${f}"
done

if [[ "${INCLUDE_OPTIONAL}" == "true" ]]; then
  for f in "${optional_files[@]}"; do
    download_file "${f}"
  done
fi

echo "Download complete."
