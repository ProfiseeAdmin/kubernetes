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

# If the user changed the deploy role name, derive it from config when possible.
try {
  $cfg = Get-Content -Raw -Path $varFile | ConvertFrom-Json
  $cfgAssumeArn = $cfg.jumpbox.assume_role_arn
  if ($cfgAssumeArn -and $DeployRoleName -eq "opentofu-deploy") {
    $derivedRoleName = ($cfgAssumeArn -split "/")[-1]
    if ($derivedRoleName -and $derivedRoleName -ne $DeployRoleName) {
      Write-Host ("Using deploy role name from config: {0}" -f $derivedRoleName)
      $DeployRoleName = $derivedRoleName
    }
  }
} catch {
  # Non-fatal; keep DeployRoleName as-is.
}

$infraRoot = Join-Path $resolvedRepoRoot "infra\root"

if (-not (Test-Path -LiteralPath $infraRoot)) {
  throw "Infra root not found: $infraRoot"
}

Push-Location $infraRoot
try {
  tofu init "-backend-config=$backendConfig"

  $applyArgs = @("apply", "-var-file=$varFile")
  if ($ExtraVarFile) {
    $applyArgs += "-var-file=$ExtraVarFile"
  }
  if ($AutoApprove) {
    $applyArgs += "-auto-approve"
  }
  tofu @applyArgs
  if ($LASTEXITCODE -ne 0) {
    throw "OpenTofu apply failed (exit code $LASTEXITCODE)."
  }
} finally {
  Pop-Location
}

$trustScript = Join-Path $resolvedRepoRoot "scripts\add-jumpbox-trust.ps1"
if (Test-Path -LiteralPath $trustScript) {
  $shouldUpdateTrust = $false
  if ($JumpboxRoleArn -and $JumpboxRoleArn -ne "") {
    $shouldUpdateTrust = $true
  } else {
    try {
      Push-Location $infraRoot
      try {
        $outputs = tofu output -json outputs_contract | ConvertFrom-Json
      } finally {
        Pop-Location
      }
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

