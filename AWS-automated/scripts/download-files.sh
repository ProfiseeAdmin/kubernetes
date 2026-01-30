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
  "infra/FullyPrivateEKS.yaml|FullyPrivateEKS.yaml"
  "scripts/deployprofisee-aws.ps1|deployprofisee-aws.ps1"
  "scripts/deployprofisee-aws-stack.ps1|deployprofisee-aws-stack.ps1"
  "values/Settings-aws.yaml|Settings-aws.yaml"
  "values/traefik-values.yaml|traefik-values.yaml"
  "values/traefik-values-public.yaml|traefik-values-public.yaml"
)

optional_files=(
  "values/smb-csi-values.yaml|smb-csi-values.yaml"
  "manifests/smb-secret.yaml|smb-secret.yaml"
  "manifests/smb-storageclass.yaml|smb-storageclass.yaml"
  "manifests/smb-pvc.yaml|smb-pvc.yaml"
  "manifests/profisee-ingress.yaml|profisee-ingress.yaml"
  "manifests/cert-manager-route53-issuer.yaml|cert-manager-route53-issuer.yaml"
  "manifests/cert-manager-certificate.yaml|cert-manager-certificate.yaml"
  "manifests/route53-credentials-secret.yaml|route53-credentials-secret.yaml"
  "examples/secretsmanager-cert.example.json|secretsmanager-cert.example.json"
)

download_file() {
  local remote="$1"
  local local_name="$2"
  local url="${BASE_RAW}/${remote}"
  echo "Downloading ${url}"
  curl -fsSL -o "${local_name}" "${url}"
}

for f in "${core_files[@]}"; do
  IFS="|" read -r remote local_name <<< "${f}"
  download_file "${remote}" "${local_name}"
done

if [[ "${INCLUDE_OPTIONAL}" == "true" ]]; then
  for f in "${optional_files[@]}"; do
    IFS="|" read -r remote local_name <<< "${f}"
    download_file "${remote}" "${local_name}"
  done
fi

echo "Download complete."
