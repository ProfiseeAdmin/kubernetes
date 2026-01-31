param(
  [Parameter(Mandatory = $true)]
  [string]$Region,

  [Parameter(Mandatory = $true)]
  [string]$StateBucketName,

  [string]$StateLockTableName = "opentofu-state-locks",
  [string]$StateKmsAlias = "alias/opentofu-state",
  [string]$StateKey = "infra/root.tfstate",

  [switch]$StateBucketForceDestroy,
  [switch]$CreateDeployRole,
  [string]$DeployRoleName = "opentofu-deploy",
  [string[]]$DeployRoleTrustedPrincipalArns = @(),
  [string[]]$DeployRolePolicyArns = @(),

  [hashtable]$Tags = @{},
  [string]$BackendOutPath,
  [switch]$AutoApprove
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Get-Command tofu -ErrorAction SilentlyContinue)) {
  throw "OpenTofu (tofu) is not on PATH. Install OpenTofu and try again."
}

if ($CreateDeployRole) {
  if ($DeployRoleTrustedPrincipalArns.Count -eq 0) {
    throw "CreateDeployRole requires -DeployRoleTrustedPrincipalArns."
  }
  if ($DeployRolePolicyArns.Count -eq 0) {
    throw "CreateDeployRole requires -DeployRolePolicyArns."
  }
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$bootstrapDir = Join-Path $repoRoot "bootstrap"

$vars = @{
  region                            = $Region
  state_bucket_name                 = $StateBucketName
  state_lock_table_name             = $StateLockTableName
  state_kms_alias                   = $StateKmsAlias
  state_key                         = $StateKey
  state_bucket_force_destroy        = [bool]$StateBucketForceDestroy
  tags                              = $Tags
  create_deploy_role                = [bool]$CreateDeployRole
  deploy_role_name                  = $DeployRoleName
  deploy_role_trusted_principal_arns = $DeployRoleTrustedPrincipalArns
  deploy_role_policy_arns           = $DeployRolePolicyArns
}

$tempVarsPath = Join-Path $env:TEMP ("bootstrap-vars-{0}.tfvars.json" -f ([guid]::NewGuid()))
$vars | ConvertTo-Json -Depth 6 | Set-Content -Path $tempVarsPath -Encoding UTF8

try {
  tofu -chdir=$bootstrapDir init

  $applyArgs = @("-chdir=$bootstrapDir", "apply", "-var-file=$tempVarsPath")
  if ($AutoApprove) {
    $applyArgs += "-auto-approve"
  }
  tofu @applyArgs

  $backendHcl = tofu -chdir=$bootstrapDir output -raw backend_hcl

  if ($BackendOutPath) {
    $outDir = Split-Path -Parent $BackendOutPath
    if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
      New-Item -ItemType Directory -Path $outDir | Out-Null
    }
    Set-Content -Path $BackendOutPath -Value $backendHcl -Encoding UTF8
    Write-Host "Wrote backend config to: $BackendOutPath"
  } else {
    Write-Host ""
    Write-Host "backend.hcl content:"
    Write-Host "--------------------"
    Write-Host $backendHcl
  }
} finally {
  if (Test-Path -LiteralPath $tempVarsPath) {
    Remove-Item -LiteralPath $tempVarsPath -Force
  }
}

