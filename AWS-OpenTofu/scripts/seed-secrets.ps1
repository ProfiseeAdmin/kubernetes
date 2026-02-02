param(
  [Parameter(Mandatory = $true)]
  [string]$DeploymentName,

  [string]$RepoRoot,
  [string]$Region,
  [string]$Prefix,
  [switch]$UpdateConfig
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Get-Command aws -ErrorAction SilentlyContinue)) {
  throw "AWS CLI (aws) is not on PATH. Install AWS CLI and try again."
}

function Read-Value([string]$Label, $Current) {
  $display = if ($null -eq $Current -or $Current -eq "") { "" } else { " [$Current]" }
  $input = Read-Host ("{0}{1}" -f $Label, $display)
  if ($input -eq "") { return $Current }
  return $input
}

function Read-SecretValue([string]$Label) {
  return Read-Host $Label
}

function Get-SecretArn([string]$SecretName, [string]$Region) {
  $arn = aws secretsmanager describe-secret --secret-id $SecretName --query Arn --output text --region $Region 2>$null
  if ($LASTEXITCODE -eq 0 -and $arn) { return $arn }
  return $null
}

function Put-Secret([string]$SecretName, [string]$SecretValue, [string]$Region) {
  $arn = Get-SecretArn $SecretName $Region
  if ($arn) {
    aws secretsmanager put-secret-value --secret-id $SecretName --secret-string $SecretValue --region $Region | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to update secret: $SecretName" }
    return $arn
  }
  $create = aws secretsmanager create-secret --name $SecretName --secret-string $SecretValue --region $Region --query Arn --output text
  if ($LASTEXITCODE -ne 0 -or -not $create) { throw "Failed to create secret: $SecretName" }
  return $create
}

$resolvedRepoRoot = if ($RepoRoot) { Resolve-Path $RepoRoot } else { Resolve-Path (Join-Path $PSScriptRoot "..") }
$deploymentPath = Join-Path $resolvedRepoRoot "customer-deployments\$DeploymentName"
$configPath = Join-Path $deploymentPath "config.auto.tfvars.json"
$seedPath = Join-Path $deploymentPath "secrets\\seed-secrets.json"

if (-not (Test-Path -LiteralPath $deploymentPath)) {
  throw "Deployment folder not found: $deploymentPath"
}

$cfg = $null
if (Test-Path -LiteralPath $configPath) {
  $cfg = Get-Content -Raw -Path $configPath | ConvertFrom-Json
}

$seed = $null
if (Test-Path -LiteralPath $seedPath) {
  try {
    $seed = Get-Content -Raw -Path $seedPath | ConvertFrom-Json
    Write-Host ("Loaded seed values from {0}" -f $seedPath)
  } catch {
    Write-Host ("Warning: failed to parse seed file: {0}" -f $seedPath)
  }
}

if (-not $Region -or $Region -eq "") {
  $Region = if ($cfg.region) { $cfg.region } else { "us-east-1" }
}

if (-not $Prefix -or $Prefix -eq "") {
  $Prefix = "profisee/$DeploymentName"
}

Write-Host ("Seeding Secrets Manager in region {0} with prefix {1}" -f $Region, $Prefix)

$secretArns = @{}

# License
$licensePath = if ($seed -and $seed.license_path) { $seed.license_path } else { Join-Path $deploymentPath "secrets\\license.txt" }
if (-not (Test-Path -LiteralPath $licensePath)) {
  Write-Host ("Note: license file not found at {0}. Skipping license secret." -f $licensePath)
} else {
  $license = Get-Content -Raw -Path $licensePath
  $secretName = "$Prefix/license"
  $secretArns.license = Put-Secret $secretName $license $Region
}

# ACR credentials
$acrUser = if ($seed -and $seed.acr.username) { $seed.acr.username } else { Read-Value "ACR username" $null }
$acrPassword = if ($seed -and $seed.acr.password) { $seed.acr.password } else { Read-SecretValue "ACR password" }
$acrAuth = if ($seed -and $seed.acr.auth) { $seed.acr.auth } else { Read-Value "ACR auth" $null }
$acrEmail = if ($seed -and $seed.acr.email) { $seed.acr.email } else { Read-Value "ACR email" "support@profisee.com" }
$acrRegistry = if ($seed -and $seed.acr.registry) { $seed.acr.registry } else { Read-Value "ACR registry" "profisee.azurecr.io" }
if ($acrUser -or $acrPassword -or $acrAuth) {
  $acrPayload = @{
    username = $acrUser
    password = $acrPassword
    auth     = $acrAuth
    email    = $acrEmail
    registry = $acrRegistry
  } | ConvertTo-Json -Depth 4
  $secretName = "$Prefix/acr"
  $secretArns.acr = Put-Secret $secretName $acrPayload $Region
}

# OIDC (Entra/Okta)
$oidcProvider = if ($seed -and $seed.oidc.provider) { $seed.oidc.provider } else { Read-Value "OIDC provider (Entra or Okta)" "Entra" }
$oidcAuthority = if ($seed -and $seed.oidc.authority) { $seed.oidc.authority } else { $null }
$oidcTenant = if ($seed -and $seed.oidc.tenant_id) { $seed.oidc.tenant_id } else { $null }
if (-not $oidcAuthority) {
  if ($oidcProvider -match "entra|azure") {
    if (-not $oidcTenant) { $oidcTenant = Read-Value "Entra tenant ID" "" }
    if ($oidcTenant) { $oidcAuthority = "https://login.microsoftonline.com/$oidcTenant" }
  } else {
    $oidcAuthority = Read-Value "Okta authority URL (e.g., https://mycompany.okta.com)" ""
  }
}
$oidcClientId = if ($seed -and $seed.oidc.client_id) { $seed.oidc.client_id } else { Read-Value "OIDC client ID" "" }
$oidcClientSecret = if ($seed -and $seed.oidc.client_secret) { $seed.oidc.client_secret } else { Read-SecretValue "OIDC client secret" }
if ($oidcClientId -or $oidcClientSecret) {
  $oidcPayload = @{
    provider      = $oidcProvider
    tenant_id     = $oidcTenant
    authority     = $oidcAuthority
    client_id     = $oidcClientId
    client_secret = $oidcClientSecret
  } | ConvertTo-Json -Depth 4
  $secretName = "$Prefix/oidc"
  $secretArns.oidc = Put-Secret $secretName $oidcPayload $Region
}

# TLS cert/key (manual)
$useTls = Read-Value "Provide manual TLS cert/key? (y/n)" "n"
$certPath = if ($seed -and $seed.tls.cert_path) { $seed.tls.cert_path } else { $null }
$keyPath = if ($seed -and $seed.tls.key_path) { $seed.tls.key_path } else { $null }
if ($useTls -match "^(y|yes|true|1)$") {
  if (-not $certPath) { $certPath = Read-Value "Path to TLS cert PEM" "" }
  if (-not $keyPath) { $keyPath = Read-Value "Path to TLS key PEM" "" }
  if ($certPath -and (Test-Path -LiteralPath $certPath) -and $keyPath -and (Test-Path -LiteralPath $keyPath)) {
    $tlsPayload = @{
      cert = Get-Content -Raw -Path $certPath
      key  = Get-Content -Raw -Path $keyPath
    } | ConvertTo-Json -Depth 4
    $secretName = "$Prefix/tls"
    $secretArns.tls = Put-Secret $secretName $tlsPayload $Region
  } else {
    Write-Host "TLS cert/key not found; skipping TLS secret."
  }
}

# Optional app SQL credentials (not RDS master)
$storeSql = Read-Value "Store app SQL username/password? (y/n)" "n"
if ($storeSql -match "^(y|yes|true|1)$") {
  $sqlUser = if ($seed -and $seed.sql.username) { $seed.sql.username } else { Read-Value "App SQL username" "" }
  $sqlPass = if ($seed -and $seed.sql.password) { $seed.sql.password } else { Read-SecretValue "App SQL password" }
  if ($sqlUser -and $sqlPass) {
    $sqlPayload = @{ username = $sqlUser; password = $sqlPass } | ConvertTo-Json -Depth 4
    $secretName = "$Prefix/sql"
    $secretArns.sql = Put-Secret $secretName $sqlPayload $Region
  }
}

if ($UpdateConfig -and $cfg) {
  if (-not $cfg.platform_deployer) {
    $cfg | Add-Member -NotePropertyName "platform_deployer" -NotePropertyValue @{}
  }
  $cfg.platform_deployer.secret_arns = $secretArns
  $jsonOut = $cfg | ConvertTo-Json -Depth 10
  [System.IO.File]::WriteAllText($configPath, $jsonOut, (New-Object System.Text.UTF8Encoding($false)))
  Write-Host ("Updated config with secret ARNs: {0}" -f $configPath)
}

Write-Host "Secrets seeded."
