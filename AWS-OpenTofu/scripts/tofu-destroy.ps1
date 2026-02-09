param(
  [Parameter(Mandatory = $true)]
  [string]$DeploymentName,

  [string]$RepoRoot,
  [string]$BackendConfigPath,
  [string]$VarFilePath,
  [string]$ExtraVarFile,
  [switch]$AutoApprove
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Get-Command tofu -ErrorAction SilentlyContinue)) {
  throw "OpenTofu (tofu) is not on PATH. Install OpenTofu and try again."
}

function Get-OptionalProperty($obj, [string]$Name) {
  if ($null -eq $obj) { return $null }
  $prop = $obj.PSObject.Properties[$Name]
  if ($null -eq $prop) { return $null }
  return $prop.Value
}

function Remove-S3BucketContents([string]$Bucket, [string]$Region) {
  $awsCmd = Get-Command aws -ErrorAction SilentlyContinue
  if (-not $awsCmd) {
    Write-Host "AWS CLI not found; skipping S3 purge for $Bucket."
    return
  }

  Write-Host ("Purging S3 bucket contents (including versions): {0}" -f $Bucket)
  $listArgs = @("s3api", "list-object-versions", "--bucket", $Bucket, "--region", $Region, "--output", "json")
  $raw = & aws @listArgs 2>$null
  if ($LASTEXITCODE -ne 0) {
    throw "Failed to list objects in S3 bucket $Bucket (exit code $LASTEXITCODE)."
  }
  if (-not $raw) {
    Write-Host "No objects found in bucket."
    return
  }

  $data = $raw | ConvertFrom-Json
  $objects = @()
  $versions = Get-OptionalProperty $data "Versions"
  $markers = Get-OptionalProperty $data "DeleteMarkers"
  if ($versions) {
    foreach ($v in $versions) {
      $objects += @{ Key = $v.Key; VersionId = $v.VersionId }
    }
  }
  if ($markers) {
    foreach ($m in $markers) {
      $objects += @{ Key = $m.Key; VersionId = $m.VersionId }
    }
  }

  if ($objects.Count -eq 0) {
    Write-Host "Bucket already empty."
    return
  }

  $chunkSize = 1000
  for ($i = 0; $i -lt $objects.Count; $i += $chunkSize) {
    $chunk = $objects[$i..([Math]::Min($i + $chunkSize - 1, $objects.Count - 1))]
    $payload = @{ Objects = $chunk } | ConvertTo-Json -Compress
    $tmp = [System.IO.Path]::GetTempFileName()
    try {
      # Write JSON without BOM to avoid AWS CLI parse errors
      [System.IO.File]::WriteAllText($tmp, $payload, [System.Text.UTF8Encoding]::new($false))
      & aws s3api delete-objects --bucket $Bucket --region $Region --delete ("file://{0}" -f $tmp) | Out-Null
      if ($LASTEXITCODE -ne 0) {
        throw "Failed to delete objects in S3 bucket $Bucket (exit code $LASTEXITCODE)."
      }
    } finally {
      Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    }
  }
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

$config = Get-Content -Raw -Path $varFile | ConvertFrom-Json
$settingsBucket = Get-OptionalProperty $config "settings_bucket"
$settingsEnabled = Get-OptionalProperty $settingsBucket "enabled"
if ($null -eq $settingsEnabled) { $settingsEnabled = $true }
$settingsForceDestroy = [bool](Get-OptionalProperty $settingsBucket "force_destroy")
$settingsBucketName = Get-OptionalProperty $settingsBucket "name"
$region = Get-OptionalProperty $config "region"
if (-not $region) { $region = "us-east-1" }

if ($settingsEnabled -and $settingsForceDestroy -and $settingsBucketName) {
  Remove-S3BucketContents -Bucket $settingsBucketName -Region $region
}

$infraRoot = Join-Path $resolvedRepoRoot "infra\root"
if (-not (Test-Path -LiteralPath $infraRoot)) {
  throw "Infra root not found: $infraRoot"
}

Push-Location $infraRoot
try {
  tofu init "-backend-config=$backendConfig" | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw "OpenTofu init failed (exit code $LASTEXITCODE)."
  }

  $destroyArgs = @("destroy", "-var-file=$varFile")
  if ($ExtraVarFile) {
    $destroyArgs += "-var-file=$ExtraVarFile"
  }
  if ($AutoApprove) {
    $destroyArgs += "-auto-approve"
  }
  tofu @destroyArgs
  if ($LASTEXITCODE -ne 0) {
    throw "OpenTofu destroy failed (exit code $LASTEXITCODE)."
  }
} finally {
  Pop-Location
}

