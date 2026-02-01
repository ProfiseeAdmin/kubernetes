param(
  [Parameter(Mandatory = $true)]
  [string]$DeploymentName,

  [string]$RepoRoot,
  [string]$BackendConfigPath,
  [string]$VarFilePath,
  [string]$KubeconfigPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Get-Command tofu -ErrorAction SilentlyContinue)) {
  throw "OpenTofu (tofu) is not on PATH. Install OpenTofu and try again."
}
if (-not (Get-Command aws -ErrorAction SilentlyContinue)) {
  throw "AWS CLI (aws) is not on PATH. Install AWS CLI and try again."
}

$resolvedRepoRoot = if ($RepoRoot) { Resolve-Path $RepoRoot } else { Resolve-Path (Join-Path $PSScriptRoot "..") }
$deploymentPath = Join-Path $resolvedRepoRoot "customer-deployments\$DeploymentName"

$backendConfig = if ($BackendConfigPath) { $BackendConfigPath } else { Join-Path $deploymentPath "backend.hcl" }
$varFile = if ($VarFilePath) { $VarFilePath } else { Join-Path $deploymentPath "config.auto.tfvars.json" }

if (-not (Test-Path -LiteralPath $backendConfig)) {
  throw "backend.hcl not found: $backendConfig"
}
if (-not (Test-Path -LiteralPath $varFile)) {
  throw "config.auto.tfvars.json not found: $varFile"
}

$infraRoot = Join-Path $resolvedRepoRoot "infra\root"
if (-not (Test-Path -LiteralPath $infraRoot)) {
  throw "Infra root not found: $infraRoot"
}

$clusterName = $null
$region = $null
$endpointPublic = $null
$endpointPrivate = $null

Push-Location $infraRoot
try {
  tofu init "-backend-config=$backendConfig" | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw "OpenTofu init failed (exit code $LASTEXITCODE)."
  }
  $outputs = tofu output -json outputs_contract | ConvertFrom-Json
  $clusterName = $outputs.cluster_name
  $region = $outputs.region
} catch {
  # Non-fatal; fall back to the var file below.
} finally {
  Pop-Location
}

try {
  $cfg = Get-Content -Raw -Path $varFile | ConvertFrom-Json
  if (-not $clusterName) { $clusterName = $cfg.eks.cluster_name }
  if (-not $region) { $region = $cfg.region }
  $endpointPublic = $cfg.eks.endpoint_public_access
  $endpointPrivate = $cfg.eks.endpoint_private_access
} catch {
  # Ignore config parse errors; we'll fail if we can't resolve essentials.
}

if (-not $clusterName) {
  throw "Cluster name not found in outputs or config."
}
if (-not $region) {
  throw "Region not found in outputs or config."
}

if ($endpointPublic -eq $false -and $endpointPrivate -eq $true) {
  Write-Host "Note: EKS API is private-only. Run this from inside the VPC (jumpbox/VPN/Direct Connect)."
}

$args = @("eks", "update-kubeconfig", "--name", $clusterName, "--region", $region)
if ($KubeconfigPath) {
  $args += @("--kubeconfig", $KubeconfigPath)
}

aws @args
if ($LASTEXITCODE -ne 0) {
  throw "aws eks update-kubeconfig failed (exit code $LASTEXITCODE)."
}

Write-Host ("Kubeconfig updated for cluster {0} in {1}." -f $clusterName, $region)
if ($KubeconfigPath) {
  Write-Host ("Kubeconfig path: {0}" -f $KubeconfigPath)
}

