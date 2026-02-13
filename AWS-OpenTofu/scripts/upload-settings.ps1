param(
  [Parameter(Mandatory = $true)]
  [string]$DeploymentName,

  [string]$RepoRoot,
  [string]$BucketName,
  [string]$Key,
  [string]$Region
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-PropValue {
  param(
    [object]$Obj,
    [string]$Name
  )
  if ($null -eq $Obj -or -not $Name) { return $null }
  $prop = $Obj.PSObject.Properties[$Name]
  if ($null -eq $prop) { return $null }
  return $prop.Value
}

if (-not (Get-Command aws -ErrorAction SilentlyContinue)) {
  throw "AWS CLI (aws) is not on PATH. Install AWS CLI and try again."
}

$resolvedRepoRoot = if ($RepoRoot) { Resolve-Path $RepoRoot } else { Resolve-Path (Join-Path $PSScriptRoot "..") }
$deploymentPath = Join-Path $resolvedRepoRoot "customer-deployments\$DeploymentName"
$settingsPath = Join-Path $deploymentPath "Settings.yaml"
$configPath = Join-Path $deploymentPath "config.auto.tfvars.json"

if (-not (Test-Path -LiteralPath $settingsPath)) {
  throw "Settings.yaml not found: $settingsPath"
}

$cfg = $null
if (Test-Path -LiteralPath $configPath) {
  $cfg = Get-Content -Raw -Path $configPath | ConvertFrom-Json
}

if (-not $BucketName -or $BucketName -eq "") {
  $BucketName = $cfg.settings_bucket.name
}
if (-not $BucketName -or $BucketName -eq "") {
  throw "App Settings S3 bucket name not provided and not found in config.auto.tfvars.json (settings_bucket.name)."
}

if (-not $Key -or $Key -eq "") {
  $cfgKey = $null
  $pd = Get-PropValue $cfg "platform_deployer"
  $cfgKey = Get-PropValue $pd "settings_key"
  $clusterName = $null
  $eks = Get-PropValue $cfg "eks"
  $clusterName = Get-PropValue $eks "cluster_name"
  if ($cfgKey) {
    $Key = $cfgKey
  } elseif ($clusterName) {
    $Key = "settings/$clusterName/Settings.yaml"
  } else {
    $Key = "settings/$DeploymentName/Settings.yaml"
  }
}

if (-not $Region -or $Region -eq "") {
  $Region = if ($cfg.region) { $cfg.region } else { "us-east-1" }
}

$s3Uri = "s3://$BucketName/$Key"
Write-Host ("Uploading Settings.yaml to {0}" -f $s3Uri)
aws s3 cp $settingsPath $s3Uri --region $Region | Out-Null
if ($LASTEXITCODE -ne 0) {
  throw "Failed to upload Settings.yaml to $s3Uri"
}

Write-Host "Upload complete."
