param(
  [Parameter(Mandatory = $true)]
  [string]$DeploymentName,

  [string]$KeyName,
  [string]$KeyPath,
  [string]$RepoRoot,
  [string]$VarFilePath,
  [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Get-Command aws -ErrorAction SilentlyContinue)) {
  throw "AWS CLI (aws) is not on PATH. Install AWS CLI and try again."
}

$resolvedRepoRoot = if ($RepoRoot) { Resolve-Path $RepoRoot } else { Resolve-Path (Join-Path $PSScriptRoot "..") }
$deploymentPath = Join-Path $resolvedRepoRoot "customer-deployments\$DeploymentName"
$varFile = if ($VarFilePath) { $VarFilePath } else { Join-Path $deploymentPath "config.auto.tfvars.json" }

if (-not (Test-Path -LiteralPath $varFile)) {
  throw "config.auto.tfvars.json not found: $varFile"
}

$cfg = Get-Content -Raw -Path $varFile | ConvertFrom-Json

function Get-PropValue($obj, [string]$name) {
  if ($null -eq $obj) { return $null }
  $prop = $obj.PSObject.Properties[$name]
  if ($null -eq $prop) { return $null }
  return $prop.Value
}

if (-not $KeyName -or $KeyName -eq "") {
  $KeyName = Get-PropValue (Get-PropValue $cfg "jumpbox") "key_name"
}
if (-not $KeyName -or $KeyName -eq "") {
  $KeyName = "$DeploymentName-jumpbox-key"
}

$region = $cfg.region
if (-not $region -or $region -eq "") {
  $region = "us-east-1"
}

if (-not $KeyPath -or $KeyPath -eq "") {
  $KeyPath = Join-Path "C:\keys" ("{0}.pem" -f $KeyName)
}

$keyDir = Split-Path -Parent $KeyPath
if (-not (Test-Path -LiteralPath $keyDir)) {
  New-Item -ItemType Directory -Path $keyDir -Force | Out-Null
}

if ((Test-Path -LiteralPath $KeyPath) -and -not $Force) {
  throw "Key file already exists: $KeyPath (use -Force to overwrite)"
}

$keyMaterial = aws ec2 create-key-pair --region $region --key-name $KeyName --query "KeyMaterial" --output text
if ($LASTEXITCODE -ne 0) {
  throw "aws ec2 create-key-pair failed (exit code $LASTEXITCODE)."
}

[System.IO.File]::WriteAllText($KeyPath, $keyMaterial, [System.Text.Encoding]::ASCII)

$jumpbox = Get-PropValue $cfg "jumpbox"
if ($null -eq $jumpbox) {
  $jumpbox = [ordered]@{}
  $cfg | Add-Member -MemberType NoteProperty -Name jumpbox -Value $jumpbox
}

$existingKey = Get-PropValue $jumpbox "key_name"
if (-not $existingKey -or $existingKey -ne $KeyName) {
  $jumpbox | Add-Member -MemberType NoteProperty -Name key_name -Value $KeyName -Force
  $jsonOut = $cfg | ConvertTo-Json -Depth 10
  [System.IO.File]::WriteAllText($varFile, $jsonOut, (New-Object System.Text.UTF8Encoding($false)))
}

Write-Host ("Created EC2 key pair: {0}" -f $KeyName)
Write-Host ("Saved private key: {0}" -f $KeyPath)
Write-Host ("Updated config: {0}" -f $varFile)
