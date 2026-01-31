param(
  [Parameter(Mandatory = $true)]
  [string]$DeploymentName,

  [string]$RepoRoot,
  [string]$BackendConfigPath,
  [string]$VarFilePath,
  [string]$ExtraVarFile,
  [switch]$AutoApprove,
  [string]$DeployRoleName = "opentofu-deploy",
  [string]$JumpboxRoleArn
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Get-Command tofu -ErrorAction SilentlyContinue)) {
  throw "OpenTofu (tofu) is not on PATH. Install OpenTofu and try again."
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

tofu -chdir=$infraRoot init -backend-config=$backendConfig

$applyArgs = @("-chdir=$infraRoot", "apply", "-var-file=$varFile")
if ($ExtraVarFile) {
  $applyArgs += "-var-file=$ExtraVarFile"
}
if ($AutoApprove) {
  $applyArgs += "-auto-approve"
}
tofu @applyArgs

$trustScript = Join-Path $resolvedRepoRoot "scripts\add-jumpbox-trust.ps1"
if (Test-Path -LiteralPath $trustScript) {
  $shouldUpdateTrust = $false
  if ($JumpboxRoleArn -and $JumpboxRoleArn -ne "") {
    $shouldUpdateTrust = $true
  } else {
    try {
      $outputs = tofu -chdir=$infraRoot output -json outputs_contract | ConvertFrom-Json
      if ($outputs.jumpbox_role_arn -and $outputs.jumpbox_role_arn -ne "") {
        $JumpboxRoleArn = $outputs.jumpbox_role_arn
        $shouldUpdateTrust = $true
      }
    } catch {
      $shouldUpdateTrust = $false
    }
  }

  if ($shouldUpdateTrust) {
    & $trustScript `
      -DeploymentName $DeploymentName `
      -DeployRoleName $DeployRoleName `
      -RepoRoot $resolvedRepoRoot `
      -BackendConfigPath $backendConfig `
      -VarFilePath $varFile `
      -JumpboxRoleArn $JumpboxRoleArn
  } else {
    Write-Host "Jumpbox trust update skipped (jumpbox role not found or jumpbox disabled)."
  }
} else {
  Write-Host "Jumpbox trust update skipped (script not found: $trustScript)."
}

