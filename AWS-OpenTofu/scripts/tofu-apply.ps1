param(
  [Parameter(Mandatory = $true)]
  [string]$DeploymentName,

  [string]$RepoRoot,
  [string]$BackendConfigPath,
  [string]$VarFilePath,
  [string]$ExtraVarFile,
  [switch]$AutoApprove,
  [string]$DeployRoleName = "opentofu-deploy",
  [string]$JumpboxRoleArn,
  [bool]$EnsureJumpboxKey = $true
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

# Safe property access under StrictMode
function Get-PropValue($obj, [string]$name) {
  if ($null -eq $obj) { return $null }
  $prop = $obj.PSObject.Properties[$name]
  if ($null -eq $prop) { return $null }
  return $prop.Value
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

if ($EnsureJumpboxKey) {
  if (-not (Get-Command aws -ErrorAction SilentlyContinue)) {
    throw "AWS CLI (aws) is not on PATH. Install AWS CLI and try again."
  }

  $jumpboxCfg = Get-PropValue $cfg "jumpbox"
  $jumpboxEnabled = Get-PropValue $jumpboxCfg "enabled"
  if ($jumpboxEnabled -eq $true) {
    $region = Get-PropValue $cfg "region"
    if (-not $region -or $region -eq "") { $region = "us-east-1" }

    $keyName = Get-PropValue $jumpboxCfg "key_name"
    if (-not $keyName -or $keyName -eq "") {
      $createKeyScript = Join-Path $resolvedRepoRoot "scripts\create-jumpbox-key.ps1"
      if (-not (Test-Path -LiteralPath $createKeyScript)) {
        throw "create-jumpbox-key.ps1 not found: $createKeyScript"
      }
      & $createKeyScript -DeploymentName $DeploymentName -RepoRoot $resolvedRepoRoot
    } else {
      $keyExists = $true
      aws ec2 describe-key-pairs --region $region --key-names $keyName | Out-Null
      if ($LASTEXITCODE -ne 0) { $keyExists = $false }

      if (-not $keyExists) {
        $createKeyScript = Join-Path $resolvedRepoRoot "scripts\create-jumpbox-key.ps1"
        if (-not (Test-Path -LiteralPath $createKeyScript)) {
          throw "create-jumpbox-key.ps1 not found: $createKeyScript"
        }
        & $createKeyScript -DeploymentName $DeploymentName -KeyName $keyName -RepoRoot $resolvedRepoRoot
      } else {
        $secretsDir = Join-Path $deploymentPath "secrets"
        $keyPath = Join-Path $secretsDir ("{0}.pem" -f $keyName)
        if (-not (Test-Path -LiteralPath $keyPath)) {
          Write-Host "Warning: Key pair '$keyName' exists in AWS but PEM not found at $keyPath."
          Write-Host "         AWS does not allow re-downloading an existing key. Create a new key name if needed."
        }
      }
    }
  }
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

# ---------------------------------------------------------------------------
# Update Settings.yaml with post-apply outputs (SQL endpoint, EBS volume)
# ---------------------------------------------------------------------------
$settingsPath = Join-Path $deploymentPath "Settings.yaml"
if (Test-Path -LiteralPath $settingsPath) {
  try {
    Push-Location $infraRoot
    try {
      $outputs = tofu output -json outputs_contract | ConvertFrom-Json
    } finally {
      Pop-Location
    }

    $settingsContent = Get-Content -Raw -Path $settingsPath
    $updated = $false

    $rdsEndpoint = Get-PropValue $outputs "rds_endpoint"
    if ($rdsEndpoint -and $settingsContent -match "\$SQLNAME") {
      $settingsContent = $settingsContent.Replace('$SQLNAME', $rdsEndpoint)
      $updated = $true
    }

    $ebsId = $null
    foreach ($candidate in @("ebs_volume_id", "app_ebs_volume_id", "fileshare_ebs_volume_id", "profisee_ebs_volume_id")) {
      $value = Get-PropValue $outputs $candidate
      if ($value) { $ebsId = $value; break }
    }
    if ($ebsId) {
      $settingsContent = [regex]::Replace($settingsContent, '(?m)^(\s*ebsVolumeId:\s*).*$',
        { param($m) ($m.Groups[1].Value + '"' + $ebsId + '"') })
      $updated = $true
    }

    if ($updated) {
      [System.IO.File]::WriteAllText($settingsPath, $settingsContent, (New-Object System.Text.UTF8Encoding($false)))
      Write-Host ("Updated Settings.yaml with post-apply values: {0}" -f $settingsPath)
    } else {
      Write-Host "Settings.yaml not updated (no matching outputs or placeholders)."
    }
  } catch {
    Write-Host ("Warning: failed to update Settings.yaml with outputs. {0}" -f $_.Exception.Message)
  }
} else {
  Write-Host ("Settings.yaml not found; skipping post-apply update: {0}" -f $settingsPath)
}

