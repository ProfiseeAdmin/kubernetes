param(
  [string]$DeploymentName,
  [string]$RepoRoot,
  [switch]$NoPrompt,
  [switch]$ForceDestroySettingsBucket,
  [bool]$SeedSecrets = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Note([string]$Message) {
  Write-Host ""
  Write-Host $Message -ForegroundColor Yellow
  Write-Host ""
}

function Write-InputFormatLegend() {
  Write-Host ""
  Write-Host "Note: Information collected will be presented in the following format: " -ForegroundColor Yellow -NoNewline
  Write-Host "in white" -ForegroundColor White -NoNewline
  Write-Host ", the parameter that needs a value/answer; " -ForegroundColor Yellow -NoNewline
  Write-Host "in green" -ForegroundColor Green -NoNewline
  Write-Host ", your selected value from a prior run; in yellow, a note that requires your attention." -ForegroundColor Yellow
  Write-Host ""
}

Write-InputFormatLegend
Write-Note "Note: RDS identifier must be lowercase letters, numbers, and hyphens, and start with a letter."
Write-Note "Note: List fields (AZs, subnet CIDRs, EKS instance types, CloudFront aliases, RDP CIDRs) should be comma-separated."
Write-Note "Note: This script normalizes identifiers and converts lists to proper JSON arrays before writing the config."

$defaultDbInitImage = "profisee.azurecr.io/profiseeplatformdev:aws-ecs-tools-latest"

function Read-PromptWithDefault([string]$Label, [string]$DefaultText) {
  if ($null -ne $DefaultText -and $DefaultText -ne "") {
    Write-Host ("{0} [" -f $Label) -NoNewline
    Write-Host $DefaultText -NoNewline -ForegroundColor Green
    Write-Host "]:" -NoNewline
    return Read-Host
  }
  return Read-Host ("{0}:" -f $Label)
}

function Read-Value([string]$Label, $Current) {
  $defaultText = if ($null -eq $Current -or $Current -eq "") { "" } else { [string]$Current }
  $input = Read-PromptWithDefault $Label $defaultText
  if ($input -eq "") { return $Current }
  return $input
}

function Mask-Secret([string]$Value, [int]$Prefix = 3) {
  if ($null -eq $Value -or $Value -eq "") { return "" }
  if ($Value.Length -le $Prefix) { return ("*" * $Value.Length) }
  $stars = "*" * ($Value.Length - $Prefix)
  return ($Value.Substring(0, $Prefix) + $stars)
}

function Read-ValueMasked([string]$Label, $Current) {
  $masked = Mask-Secret $Current
  $defaultText = if ($null -eq $masked -or $masked -eq "") { "" } else { $masked }
  $input = Read-PromptWithDefault $Label $defaultText
  if ($input -eq "") { return $Current }
  return $input
}

function Read-List([string]$Label, $Current) {
  $currentText = if ($null -eq $Current) { "" } elseif ($Current -is [string]) { $Current } else { ($Current -join ",") }
  $input = Read-PromptWithDefault $Label $currentText
  if ($input -eq "") { return $Current }
  $list = @($input -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })
  return ,$list
}

function Read-Number([string]$Label, $Current) {
  $defaultText = if ($null -eq $Current -or $Current -eq "") { "" } else { [string]$Current }
  $input = Read-PromptWithDefault $Label $defaultText
  if ($input -eq "") { return $Current }
  return [int]$input
}

function Read-Bool([string]$Label, $Current) {
  $defaultText = if ($Current) { "y" } else { "n" }
  Write-Host ("{0} [y/n, default " -f $Label) -NoNewline
  Write-Host $defaultText -NoNewline -ForegroundColor Green
  Write-Host "]:" -NoNewline
  $input = Read-Host
  if ($input -eq "") { return $Current }
  return ($input.ToLower() -in @("y", "yes", "true", "1"))
}

function To-BoolOrDefault($Value, [bool]$Default) {
  if ($null -eq $Value -or $Value -eq "") { return $Default }
  try { return [System.Convert]::ToBoolean($Value) } catch { return $Default }
}

function Get-PropValue($obj, [string]$Name) {
  if ($null -eq $obj) { return $null }
  $prop = $obj.PSObject.Properties[$Name]
  if ($null -eq $prop) { return $null }
  return $prop.Value
}

function Ensure-ObjectProperty($obj, [string]$Name, $DefaultValue) {
  if ($null -eq $obj.PSObject.Properties[$Name]) {
    $obj | Add-Member -NotePropertyName $Name -NotePropertyValue $DefaultValue
  }
  return $obj.PSObject.Properties[$Name].Value
}

function Normalize-RdsIdentifier([string]$Value) {
  if (-not $Value) { return $Value }
  $v = $Value.ToLower()
  $v = $v -replace "[^a-z0-9-]", "-"
  $v = $v -replace "-{2,}", "-"
  $v = $v.Trim("-")
  if ($v -eq "") { return $Value }
  if ($v -notmatch "^[a-z]") { $v = "db-$v" }
  return $v
}

function Normalize-RuntimeSqlMode([string]$Value) {
  if (-not $Value) { return "rds_dbadmin" }
  $v = $Value.Trim().ToLower()
  switch ($v) {
    "rds_dbadmin" { return "rds_dbadmin" }
    "dbadmin" { return "rds_dbadmin" }
    "master" { return "rds_dbadmin" }
    "dedicated_db_user" { return "dedicated_db_user" }
    "dedicated" { return "dedicated_db_user" }
    "db_user" { return "dedicated_db_user" }
    default { return "rds_dbadmin" }
  }
}

function Coerce-List([string]$Label, $Value) {
  if ($null -eq $Value) { return ,@() }
  if ($Value -is [string]) {
    $s = $Value.Trim()
    if ($s -eq "") { return ,@() }
    if ($s.Contains(",")) {
      $list = @($s -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })
      Write-Host ("Adjusted {0} to list: {1}" -f $Label, ($list -join ", "))
      return ,$list
    }
    Write-Host ("Adjusted {0} to list: {1}" -f $Label, $s)
    return ,@($s)
  }
  if ($Value -is [System.Collections.IEnumerable]) {
    $list = @($Value)
    return ,$list
  }
  return ,@($Value)
}

function Ensure-Dir([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -ItemType Directory -Path $Path | Out-Null
  }
}

function Replace-Token([string]$Content, [string]$Token, [string]$Value) {
  if ($null -eq $Value) { return $Content }
  return $Content.Replace(('$' + $Token), $Value)
}

function Replace-TokenBlock([string]$Content, [string]$Token, [string]$Value) {
  if ($null -eq $Value) { return $Content }
  $pattern = "(?m)^(\\s*)\\$" + [regex]::Escape($Token) + "\\s*$"
  return [regex]::Replace($Content, $pattern, {
    param($m)
    $indent = $m.Groups[1].Value
    $lines = $Value -split "`r?`n"
    if ($lines.Count -eq 0) { return $indent }
    $first = $lines[0]
    if ($lines.Count -eq 1) { return ($indent + $first) }
    $rest = $lines[1..($lines.Count - 1)] | ForEach-Object { $indent + $_ }
    return ($indent + $first + "`n" + ($rest -join "`n"))
  })
}

function Read-FileRaw([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) { return $null }
  return Get-Content -Raw -Path $Path
}

function Try-Get-Outputs([string]$InfraRoot, [string]$BackendConfigPath) {
  if (-not (Get-Command tofu -ErrorAction SilentlyContinue)) { return $null }
  if (-not (Test-Path -LiteralPath $InfraRoot)) { return $null }
  if (-not (Test-Path -LiteralPath $BackendConfigPath)) { return $null }
  Push-Location $InfraRoot
  try {
    tofu init "-backend-config=$BackendConfigPath" 2>$null | Out-Null
    $raw = tofu output -json outputs_contract 2>$null
    if (-not $raw) { return $null }
    return $raw | ConvertFrom-Json
  } catch {
    return $null
  } finally {
    Pop-Location
  }
}

function Save-Config([string]$Path, $Obj) {
  $jsonOut = $Obj | ConvertTo-Json -Depth 10
  [System.IO.File]::WriteAllText($Path, $jsonOut, (New-Object System.Text.UTF8Encoding($false)))
  Write-Host ("Saved progress: {0}" -f $Path)
}

$resolvedRepoRoot = if ($RepoRoot) { Resolve-Path $RepoRoot } else { Resolve-Path (Join-Path $PSScriptRoot "..") }
$templateDir = Join-Path $resolvedRepoRoot "deployments\_template"

if (-not (Test-Path -LiteralPath $templateDir)) {
  throw "Template directory not found: $templateDir"
}

if (-not $DeploymentName -or $DeploymentName -eq "") {
  $DeploymentName = Read-Host "Deployment name (e.g., acme-prod)"
}
if (-not $DeploymentName -or $DeploymentName -eq "") {
  throw "Deployment name is required."
}

$targetDir = Join-Path $resolvedRepoRoot ("customer-deployments\{0}" -f $DeploymentName)
if (-not (Test-Path -LiteralPath $targetDir)) {
  New-Item -ItemType Directory -Path $targetDir | Out-Null
}

Copy-Item -Recurse -Force (Join-Path $templateDir "*") $targetDir

$examplePath = Join-Path $targetDir "config.auto.tfvars.json.example"
$configPath = Join-Path $targetDir "config.auto.tfvars.json"

if (-not (Test-Path -LiteralPath $examplePath)) {
  throw "Template config not found: $examplePath"
}

$settingsUrl = "https://raw.githubusercontent.com/Profisee/kubernetes/master/Azure-ARM/Settings.yaml"
$settingsPath = Join-Path $targetDir "Settings.yaml"
$settingsDownloadJob = $null
try {
  $settingsDownloadJob = Start-Job -ScriptBlock {
    param($Url, $Path)
    try {
      Invoke-WebRequest -Uri $Url -OutFile $Path -ErrorAction Stop | Out-Null
      [pscustomobject]@{ Success = $true; Error = "" }
    } catch {
      [pscustomobject]@{ Success = $false; Error = $_.Exception.Message }
    }
  } -ArgumentList $settingsUrl, $settingsPath
} catch {
  try {
    Invoke-WebRequest -Uri $settingsUrl -OutFile $settingsPath -ErrorAction Stop | Out-Null
    Write-Host ("Downloaded Settings.yaml to: {0}" -f $settingsPath)
  } catch {
    throw "Failed to download Settings.yaml from $settingsUrl"
  }
}

  if (-not (Test-Path -LiteralPath $configPath)) {
    Copy-Item -Force $examplePath $configPath
  }

  $json = Get-Content -Raw -Path $configPath | ConvertFrom-Json
  Ensure-ObjectProperty $json "cloudfront" @{} | Out-Null
  Ensure-ObjectProperty $json.cloudfront "enabled" $true | Out-Null
  Ensure-ObjectProperty $json.cloudfront "aliases" @() | Out-Null
  Ensure-ObjectProperty $json.cloudfront "origin_domain_name" $null | Out-Null
  Ensure-ObjectProperty $json.cloudfront "origin_custom_headers" @{} | Out-Null
  Ensure-ObjectProperty $json "route53" @{} | Out-Null
  Ensure-ObjectProperty $json.route53 "enabled" $true | Out-Null
  Ensure-ObjectProperty $json.route53 "hosted_zone_id" $null | Out-Null
  Ensure-ObjectProperty $json.route53 "record_name" $null | Out-Null
  Ensure-ObjectProperty $json "db_init" @{} | Out-Null
  $dbInit = $json.db_init
  Ensure-ObjectProperty $dbInit "enabled" $true | Out-Null
  Ensure-ObjectProperty $dbInit "image_uri" $defaultDbInitImage | Out-Null
  Ensure-ObjectProperty $dbInit "cpu" 512 | Out-Null
  Ensure-ObjectProperty $dbInit "memory" 1024 | Out-Null
  Ensure-ObjectProperty $dbInit "environment" ([pscustomobject]@{}) | Out-Null
  $dbInitEnv = $dbInit.environment
  $runtimeSqlMode = Normalize-RuntimeSqlMode (Get-PropValue $dbInitEnv "RUNTIME_SQL_MODE")
  Ensure-ObjectProperty $dbInitEnv "RUNTIME_SQL_MODE" $runtimeSqlMode | Out-Null
  $dbInitEnv.RUNTIME_SQL_MODE = $runtimeSqlMode

  if (-not $NoPrompt) {
    $json.region = Read-Value "Primary region" $json.region
    $json.use1_region = Read-Value "us-east-1 region (ACM/CloudFront)" $json.use1_region

  $json.tags.Project = Read-Value "Tag: Project" $json.tags.Project
  $json.tags.Environment = Read-Value "Tag: Environment" $json.tags.Environment

  Ensure-ObjectProperty $json "settings_bucket" @{} | Out-Null
  $settingsBucket = $json.settings_bucket
  Ensure-ObjectProperty $settingsBucket "enabled" $true | Out-Null
  Ensure-ObjectProperty $settingsBucket "name" $null | Out-Null
  Ensure-ObjectProperty $settingsBucket "force_destroy" $true | Out-Null
  Ensure-ObjectProperty $settingsBucket "kms_key_arn" $null | Out-Null

  $settingsBucket.enabled = $true
  $settingsBucket.name = Read-Value "App Settings S3 bucket name" $settingsBucket.name
  if ($ForceDestroySettingsBucket) {
    $settingsBucket.force_destroy = $true
  } else {
  }
  $settingsBucket.kms_key_arn = Read-Value "App Settings bucket KMS key ARN (optional)" $settingsBucket.kms_key_arn

  $dbInit.enabled = $true

  $json.vpc.name = Read-Value "VPC name" $json.vpc.name
  $json.vpc.cidr_block = Read-Value "VPC CIDR block" $json.vpc.cidr_block
  $json.vpc.azs = Read-List "VPC AZs (comma-separated)" $json.vpc.azs
  $json.vpc.public_subnet_cidrs = Read-List "Public subnet CIDRs (comma-separated)" $json.vpc.public_subnet_cidrs
  $json.vpc.private_subnet_cidrs = Read-List "Private subnet CIDRs (comma-separated)" $json.vpc.private_subnet_cidrs

  if ($json.vpc.azs.Count -ne $json.vpc.public_subnet_cidrs.Count -or
      $json.vpc.azs.Count -ne $json.vpc.private_subnet_cidrs.Count) {
    Write-Host "Warning: AZ count does not match subnet CIDR count. Please review."
  }

  $json.eks.cluster_name = Read-Value "EKS cluster name" $json.eks.cluster_name
  $json.eks.cluster_version = Read-Value "EKS cluster version" $json.eks.cluster_version

  Save-Config $configPath $json
}

$json.eks.linux_node_group.instance_types = Coerce-List "EKS linux instance types" $json.eks.linux_node_group.instance_types
$json.eks.windows_node_group.instance_types = Coerce-List "EKS windows instance types" $json.eks.windows_node_group.instance_types
if (-not $NoPrompt) {
  $json.eks.linux_node_group.instance_types = Read-List "Linux node instance types" $json.eks.linux_node_group.instance_types
  $json.eks.linux_node_group.min_size = Read-Number "Linux node min size" $json.eks.linux_node_group.min_size
  $json.eks.linux_node_group.max_size = Read-Number "Linux node max size" $json.eks.linux_node_group.max_size
  $json.eks.linux_node_group.desired_size = Read-Number "Linux node desired size" $json.eks.linux_node_group.desired_size

  $json.eks.windows_node_group.instance_types = Read-List "Windows node instance types" $json.eks.windows_node_group.instance_types
  $json.eks.windows_node_group.min_size = Read-Number "Windows node min size" $json.eks.windows_node_group.min_size
  $json.eks.windows_node_group.max_size = Read-Number "Windows node max size" $json.eks.windows_node_group.max_size
  $json.eks.windows_node_group.desired_size = Read-Number "Windows node desired size" $json.eks.windows_node_group.desired_size
}

Ensure-ObjectProperty $json "rds_sqlserver" @{} | Out-Null
Ensure-ObjectProperty $json.rds_sqlserver "db_name" "Profisee" | Out-Null
$json.rds_sqlserver.identifier = if (-not $NoPrompt) { Read-Value "RDS identifier" $json.rds_sqlserver.identifier } else { $json.rds_sqlserver.identifier }
$normalizedIdentifier = Normalize-RdsIdentifier $json.rds_sqlserver.identifier
if (-not $normalizedIdentifier) {
  $normalizedIdentifier = Normalize-RdsIdentifier ("db-" + $DeploymentName)
}
if ($normalizedIdentifier -ne $json.rds_sqlserver.identifier) {
  Write-Host ("Adjusted RDS identifier to a valid value: {0}" -f $normalizedIdentifier)
  $json.rds_sqlserver.identifier = $normalizedIdentifier
}
if (-not $NoPrompt) {
  $json.rds_sqlserver.engine_version = Read-Value "RDS SQL Server engine version" $json.rds_sqlserver.engine_version
  $json.rds_sqlserver.instance_class = Read-Value "RDS instance class" $json.rds_sqlserver.instance_class
  $json.rds_sqlserver.allocated_storage = Read-Number "RDS allocated storage (GB)" $json.rds_sqlserver.allocated_storage
  $json.rds_sqlserver.master_username = Read-Value "RDS master username" $json.rds_sqlserver.master_username
  $json.rds_sqlserver.db_name = Read-Value "Application database name (created by db_init)" $json.rds_sqlserver.db_name
  $json.rds_sqlserver.publicly_accessible = Read-Bool "RDS publicly accessible" $json.rds_sqlserver.publicly_accessible

  $json.acm.domain_name = Read-Value "ACM domain name" $json.acm.domain_name
  $json.acm.hosted_zone_id = Read-Value "ACM hosted zone ID" $json.acm.hosted_zone_id

    $json.jumpbox.enabled = Read-Bool "Jumpbox enabled" $json.jumpbox.enabled
  if ($json.jumpbox.enabled) {
    $json.jumpbox.instance_type = Read-Value "Jumpbox instance type" $json.jumpbox.instance_type
    $json.jumpbox.key_name = Read-Value "Jumpbox key pair name (optional, for RDP)" $json.jumpbox.key_name
    $json.jumpbox.associate_public_ip = Read-Bool "Jumpbox public IP" $json.jumpbox.associate_public_ip
    $json.jumpbox.enable_rdp_ingress = Read-Bool "Jumpbox inbound RDP" $json.jumpbox.enable_rdp_ingress
    $json.jumpbox.allowed_rdp_cidrs = Read-List "Jumpbox RDP CIDRs (comma-separated)" $json.jumpbox.allowed_rdp_cidrs
    $json.jumpbox.assume_role_arn = Read-Value "Jumpbox assume role ARN" $json.jumpbox.assume_role_arn
  }

  Save-Config $configPath $json
}

$json.vpc.azs = Coerce-List "VPC AZs" $json.vpc.azs
$json.vpc.public_subnet_cidrs = Coerce-List "Public subnet CIDRs" $json.vpc.public_subnet_cidrs
$json.vpc.private_subnet_cidrs = Coerce-List "Private subnet CIDRs" $json.vpc.private_subnet_cidrs
$json.eks.linux_node_group.instance_types = Coerce-List "EKS linux instance types" $json.eks.linux_node_group.instance_types
$json.eks.windows_node_group.instance_types = Coerce-List "EKS windows instance types" $json.eks.windows_node_group.instance_types
$json.cloudfront.aliases = Coerce-List "CloudFront aliases" $json.cloudfront.aliases
$json.jumpbox.allowed_rdp_cidrs = Coerce-List "Jumpbox RDP CIDRs" $json.jumpbox.allowed_rdp_cidrs

if ($json.db_init -and $json.db_init.enabled -eq $true -and (-not $json.db_init.image_uri -or $json.db_init.image_uri -eq "")) {
  $json.db_init.image_uri = $defaultDbInitImage
  Write-Host ("db_init.image_uri not set; defaulting to {0}" -f $json.db_init.image_uri)
}

if ($json.db_init -and $json.db_init.image_uri -eq $defaultDbInitImage) {
  $json.db_init.PSObject.Properties.Remove("image_uri")
}

if ($json.db_init) {
  if ($json.db_init.cpu -eq 512) { $json.db_init.PSObject.Properties.Remove("cpu") }
  if ($json.db_init.memory -eq 1024) { $json.db_init.PSObject.Properties.Remove("memory") }
}

if ($ForceDestroySettingsBucket) {
  Ensure-ObjectProperty $json "settings_bucket" @{} | Out-Null
  $settingsBucket = $json.settings_bucket
  Ensure-ObjectProperty $settingsBucket "force_destroy" $true | Out-Null
  $settingsBucket.force_destroy = $true
}
$dbInitEnv.RUNTIME_SQL_MODE = $runtimeSqlMode

Save-Config $configPath $json

# ---------------------------------------------------------------------------
# Settings.yaml (Azure-ARM base) download + replacement
# ---------------------------------------------------------------------------
if ($null -ne $settingsDownloadJob) {
  $settingsDownloadResult = Receive-Job -Job $settingsDownloadJob -Wait -AutoRemoveJob
  if (-not $settingsDownloadResult.Success) {
    throw "Failed to download Settings.yaml from ${settingsUrl}: $($settingsDownloadResult.Error)"
  }
  Write-Host ("Downloaded Settings.yaml to: {0}" -f $settingsPath)
} elseif (-not (Test-Path -LiteralPath $settingsPath)) {
  throw "Failed to download Settings.yaml from $settingsUrl"
}

$settingsContent = Get-Content -Raw -Path $settingsPath

$secretsDir = Join-Path $targetDir "secrets"
Ensure-Dir $secretsDir
$licensePath = Join-Path $secretsDir "license.txt"
$seedPath = Join-Path $secretsDir "seed-secrets.json"

# If infra has already been applied, pull outputs to prefill values.
$sqlEndpointFromOutputs = $null
$backendConfig = Join-Path $targetDir "backend.hcl"
$infraRoot = Join-Path $resolvedRepoRoot "infra\root"
$outputs = Try-Get-Outputs $infraRoot $backendConfig
if ($outputs) {
  $sqlEndpointFromOutputs = Get-PropValue $outputs "rds_endpoint"
}

$externalDnsName = $json.route53.record_name
if (-not $externalDnsName -or $externalDnsName -eq "") { $externalDnsName = $json.acm.domain_name }
if ($externalDnsName -and $externalDnsName.StartsWith("*.")) {
  $externalDnsName = $externalDnsName.Substring(2)
}
$externalDnsUrl = if ($externalDnsName) { "https://$externalDnsName" } else { "" }

$sqlName = $null
$sqlDbName = if ($json.rds_sqlserver.db_name) { $json.rds_sqlserver.db_name } else { "Profisee" }
$sqlUsername = $null
$sqlPassword = $null
$useLetsEncrypt = $true
$adminAccount = $null
$infraAdminAccount = $null
$webAppName = "profisee"
$oidcProvider = "Entra"
$oidcName = $null
$oidcUrl = $null
$oidcTenantId = $null
$oidcClientId = $null
$oidcClientSecret = $null
$oidcUserNameClaim = $null
$oidcUserIdClaim = $null
$oidcFirstNameClaim = $null
$oidcLastNameClaim = $null
$oidcEmailClaim = $null
$podCount = "1"
$acrRepoName = "profiseeplatform"
$acrRepoLabel = $null
$acrUser = $null
$acrPassword = $null
$acrAuth = $null
$acrEmail = $null
$acrRegistry = "profisee.azurecr.io"
$useOwnTls = $false
$tlsCert = $null
$tlsKey = $null
$tlsCertPath = $null
$tlsKeyPath = $null
$usePurview = $false
$purviewAtlasEndpoint = $null
$purviewCollectionId = $null
$purviewTenantId = $null
$purviewClientId = $null
$purviewClientSecret = $null

if (Test-Path -LiteralPath $seedPath) {
  try {
    $seedDefaults = Get-Content -Raw -Path $seedPath | ConvertFrom-Json
    if ($seedDefaults.app.super_admin_email) { $adminAccount = $seedDefaults.app.super_admin_email }
    if ($seedDefaults.app.infra_admin_email) { $infraAdminAccount = $seedDefaults.app.infra_admin_email }
    if ($seedDefaults.app.web_app_name) { $webAppName = $seedDefaults.app.web_app_name }
    if ($seedDefaults.app.pod_count) { $podCount = $seedDefaults.app.pod_count }
    if ($seedDefaults.sql.username) { $sqlUsername = $seedDefaults.sql.username }
    if ($seedDefaults.sql.password) { $sqlPassword = $seedDefaults.sql.password }
    if ($seedDefaults.acr.username) { $acrUser = $seedDefaults.acr.username }
    if ($seedDefaults.acr.password) { $acrPassword = $seedDefaults.acr.password }
    if ($seedDefaults.acr.auth) { $acrAuth = $seedDefaults.acr.auth }
    if ($seedDefaults.acr.label) { $acrRepoLabel = $seedDefaults.acr.label }
    if (-not $acrRepoLabel -and $seedDefaults.acr.image_tag) { $acrRepoLabel = $seedDefaults.acr.image_tag }
    if ($seedDefaults.acr.email) { $acrEmail = $seedDefaults.acr.email }
    if ($seedDefaults.acr.registry) { $acrRegistry = $seedDefaults.acr.registry }
    if ($seedDefaults.oidc.provider) { $oidcProvider = $seedDefaults.oidc.provider }
    if ($seedDefaults.oidc.client_id) { $oidcClientId = $seedDefaults.oidc.client_id }
    if ($seedDefaults.oidc.client_secret) { $oidcClientSecret = $seedDefaults.oidc.client_secret }
    if ($seedDefaults.oidc.authority) { $oidcUrl = $seedDefaults.oidc.authority }
    if ($seedDefaults.oidc.tenant_id) { $oidcTenantId = $seedDefaults.oidc.tenant_id }
    $seedPurview = Get-PropValue $seedDefaults "purview"
    if ($seedPurview) {
      $usePurview = To-BoolOrDefault (Get-PropValue $seedPurview "use_purview") $false
      $purviewAtlasEndpoint = Get-PropValue $seedPurview "atlas_endpoint"
      $purviewCollectionId = Get-PropValue $seedPurview "collection_id"
      $purviewTenantId = Get-PropValue $seedPurview "tenant_id"
      $purviewClientId = Get-PropValue $seedPurview "client_id"
      $purviewClientSecret = Get-PropValue $seedPurview "client_secret"
    }
    if ($seedDefaults.tls.cert_path) { $tlsCertPath = $seedDefaults.tls.cert_path }
    if ($seedDefaults.tls.key_path) { $tlsKeyPath = $seedDefaults.tls.key_path }
  } catch {
    Write-Host ("Warning: could not parse seed-secrets.json at {0}" -f $seedPath)
  }
}

if (-not $sqlName -and $sqlEndpointFromOutputs) {
  $sqlName = $sqlEndpointFromOutputs
}

if (-not $NoPrompt) {
  $sqlName = Read-Value "SQL Server endpoint (leave blank, it'll auto-fill after tofu-apply)" $sqlName
  Write-Note "Note: App SQL username/password are collected and stored now. In rds_dbadmin mode they are not used at runtime. In the future, Profisee will switch to a database-level user and the RDS admin account will no longer be required for deployment."
  $runtimeSqlMode = Normalize-RuntimeSqlMode (Read-Value "Runtime SQL identity mode (rds_dbadmin|dedicated_db_user)" $runtimeSqlMode)
  if ($runtimeSqlMode -eq "dedicated_db_user") {
    Write-Note "Note: dedicated_db_user selected. If deployment still needs dbadmin runtime rights, switch back to rds_dbadmin."
  }
  $sqlUsername = Read-ValueMasked "App SQL username (not RDS master)" $sqlUsername
  $sqlPassword = Read-ValueMasked "App SQL password" $sqlPassword
  $useLetsEncrypt = Read-Bool "Use Let's Encrypt (recommended)" $useLetsEncrypt
  if ($useLetsEncrypt) {
    $useOwnTls = $false
    $tlsCertPath = ""
    $tlsKeyPath = ""
    $tlsCert = $null
    $tlsKey = $null
    Write-Note "Let's Encrypt selected; custom TLS cert prompts are skipped."
  }
  $adminAccount = Read-Value "Profisee SuperAdmin email" $adminAccount
  $infraAdminAccount = Read-Value "Infra admin account email (default to SuperAdmin)" $adminAccount
  if (-not $infraAdminAccount -or $infraAdminAccount -eq "") { $infraAdminAccount = $adminAccount }
  $webAppName = Read-Value "Web app name (path segment)" $webAppName

  $oidcProvider = Read-Value "OIDC provider (Entra or Okta)" $oidcProvider
  if ($oidcProvider -match "entra|azure") {
    $oidcName = "Entra"
    $oidcTenantId = Read-ValueMasked "Entra tenant ID" $oidcTenantId
    if ($oidcTenantId) { $oidcUrl = "https://login.microsoftonline.com/$oidcTenantId" }
    $oidcClientId = Read-ValueMasked "Entra app registration client ID" $oidcClientId
    $oidcClientSecret = Read-ValueMasked "Entra app registration client secret" $oidcClientSecret
    $oidcUserNameClaim = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
    $oidcUserIdClaim = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"
    $oidcFirstNameClaim = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"
    $oidcLastNameClaim = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"
    $oidcEmailClaim = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
    if ($externalDnsName -and $webAppName) {
      Write-Host ("Entra ID: Register the app as Web, enable ID tokens, and add redirect URL: https://{0}/{1}/auth/signin-microsoft" -f $externalDnsName, $webAppName)
    }
  } elseif ($oidcProvider -match "okta") {
    $oidcName = "Okta"
    $oidcUrl = Read-Value "Okta authority URL (e.g., https://mycompany.okta.com)" $oidcUrl
    $oidcClientId = Read-ValueMasked "Okta client ID" $oidcClientId
    $oidcClientSecret = Read-ValueMasked "Okta client secret" $oidcClientSecret
    $oidcUserNameClaim = "preferred_username"
    $oidcUserIdClaim = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"
    $oidcFirstNameClaim = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"
    $oidcLastNameClaim = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"
    $oidcEmailClaim = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
    if ($externalDnsName -and $webAppName) {
      Write-Host ("Okta: Enable ID tokens and set redirect URI: https://{0}/{1}/auth/signin-microsoft" -f $externalDnsName, $webAppName)
      Write-Host ("Okta: Set sign-out URL: https://{0}/{1}/Account/Logout" -f $externalDnsName, $webAppName)
    }
  }

  $identityTenantLabel = if ($oidcProvider -match "okta") { "Okta tenant ID" } else { "Entra tenant ID" }

  $usePurview = Read-Bool "Use Purview" $usePurview
  if ($usePurview) {
    $purviewAtlasEndpoint = Read-Value "Purview Atlas Endpoint (https://.../catalog)" $purviewAtlasEndpoint
    $purviewCollectionId = Read-ValueMasked "Purview Collection ID" $purviewCollectionId
    if ($oidcTenantId) {
      $sameTenantDefault = $true
      if ($purviewTenantId -and $purviewTenantId -ne $oidcTenantId) { $sameTenantDefault = $false }
      $useSamePurviewTenant = Read-Bool ("Use same tenant ID as {0}" -f $identityTenantLabel) $sameTenantDefault
      if ($useSamePurviewTenant) {
        $purviewTenantId = $oidcTenantId
      } else {
        $purviewTenantId = Read-ValueMasked "Purview Tenant ID" $purviewTenantId
      }
    } else {
      Write-Host ("No {0} available from OIDC settings; enter Purview Tenant ID." -f $identityTenantLabel)
      $purviewTenantId = Read-ValueMasked "Purview Tenant ID" $purviewTenantId
    }
    Write-Host ("Purview Tenant ID set as: {0}" -f (Mask-Secret $purviewTenantId))
    $purviewClientId = Read-ValueMasked "Purview Application Registration Client ID" $purviewClientId
    $purviewClientSecret = Read-ValueMasked "Purview Application Registration Client Secret" $purviewClientSecret
  } else {
    $purviewAtlasEndpoint = ""
    $purviewCollectionId = ""
    $purviewTenantId = ""
    $purviewClientId = ""
    $purviewClientSecret = ""
  }

  $podCount = Read-Value "Cluster node count (app pods)" $podCount

  $acrRepoName = Read-Value "ACR repository name" $acrRepoName
  $acrRepoLabel = Read-Value "ACR image tag/label" $acrRepoLabel
  $acrRegistry = Read-ValueMasked "ACR registry" $acrRegistry
  $acrUser = Read-ValueMasked "ACR username" $acrUser
  $acrPassword = Read-ValueMasked "ACR password" $acrPassword
  $acrAuth = Read-ValueMasked "ACR auth" $acrAuth
  $acrEmail = Read-Value "ACR email" $acrEmail

  if (-not $useLetsEncrypt) {
    $useOwnTls = $true
    $tlsCertPath = Read-Value "Path to TLS cert PEM" $tlsCertPath
    $tlsKeyPath = Read-Value "Path to TLS key PEM" $tlsKeyPath
    if (-not $tlsCertPath -or -not (Test-Path -LiteralPath $tlsCertPath)) {
      throw "Use Let's Encrypt is disabled, so a valid TLS cert PEM path is required."
    }
    if (-not $tlsKeyPath -or -not (Test-Path -LiteralPath $tlsKeyPath)) {
      throw "Use Let's Encrypt is disabled, so a valid TLS key PEM path is required."
    }
    $tlsCert = Get-Content -Raw -Path $tlsCertPath
    $tlsKey = Get-Content -Raw -Path $tlsKeyPath
    if (-not $tlsCert -or -not $tlsKey) {
      throw "Use Let's Encrypt is disabled, but TLS cert/key content could not be read."
    }
  }
}

if (-not $NoPrompt) {
  $dbInitCfgCheck = Get-PropValue $json "db_init"
  if ($dbInitCfgCheck -and $dbInitCfgCheck.enabled -eq $true) {
    if (-not $sqlUsername -or -not $sqlPassword) {
      throw "App SQL username/password are required when db_init is enabled."
    }
  }
  if ($usePurview) {
    if (-not $purviewAtlasEndpoint -or -not $purviewCollectionId -or -not $purviewTenantId -or -not $purviewClientId -or -not $purviewClientSecret) {
      throw "Purview is enabled, but one or more required Purview values are missing."
    }
    if ($purviewAtlasEndpoint -notmatch "/catalog/?$") {
      Write-Host "Warning: Purview Atlas Endpoint does not end with '/catalog'."
    }
  }
}

$dbInitEnv.RUNTIME_SQL_MODE = $runtimeSqlMode
Save-Config $configPath $json

$licenseRaw = Read-FileRaw $licensePath
if (-not $licenseRaw) {
  Write-Note ("Note: license file not found at {0}. Place your license file there as license.txt." -f $licensePath)
}

if (-not $NoPrompt) {
  $seedPayload = @{
    app = @{
      super_admin_email = $adminAccount
      infra_admin_email = $infraAdminAccount
      web_app_name      = $webAppName
      pod_count         = $podCount
    }
    license_path = $licensePath
    sql = @{
      username = $sqlUsername
      password = $sqlPassword
    }
    acr = @{
      username = $acrUser
      password = $acrPassword
      label    = $acrRepoLabel
      auth     = $acrAuth
      email    = $acrEmail
      registry = $acrRegistry
    }
    oidc = @{
      provider      = $oidcName
      tenant_id     = $oidcTenantId
      authority     = $oidcUrl
      client_id     = $oidcClientId
      client_secret = $oidcClientSecret
    }
    purview = @{
      use_purview   = $usePurview
      atlas_endpoint = $purviewAtlasEndpoint
      collection_id = $purviewCollectionId
      tenant_id     = $purviewTenantId
      client_id     = $purviewClientId
      client_secret = $purviewClientSecret
    }
    tls = @{
      cert_path = $tlsCertPath
      key_path  = $tlsKeyPath
    }
  }
  $seedJson = $seedPayload | ConvertTo-Json -Depth 6
  [System.IO.File]::WriteAllText($seedPath, $seedJson, (New-Object System.Text.UTF8Encoding($false)))
  Write-Host ("Wrote secrets seed file: {0}" -f $seedPath)
}

# Replace core tokens
$settingsContent = Replace-Token $settingsContent "SQLNAME" $sqlName
$settingsContent = Replace-Token $settingsContent "SQLDBNAME" $sqlDbName
$settingsContent = Replace-Token $settingsContent "USELETSENCRYPT" ($useLetsEncrypt.ToString().ToLower())
$settingsContent = Replace-Token $settingsContent "ADMINACCOUNTNAME" $adminAccount
$settingsContent = Replace-Token $settingsContent "INFRAADMINACCOUNT" $infraAdminAccount
$settingsContent = Replace-Token $settingsContent "FILEREPOACCOUNTNAME" ""
$settingsContent = Replace-Token $settingsContent "FILEREPOUSERNAME" "user manager\\containeradministrator"
$settingsContent = Replace-Token $settingsContent "FILEREPOPASSWORD" ""
$settingsContent = Replace-Token $settingsContent "FILEREPOSHARENAME" ""
$settingsContent = Replace-Token $settingsContent "FILEREPOURL" "c:\\fileshare"
$settingsContent = Replace-Token $settingsContent "EXTERNALDNSURL" $externalDnsUrl
$settingsContent = Replace-Token $settingsContent "EXTERNALDNSNAME" $externalDnsName
$settingsContent = Replace-Token $settingsContent "WEBAPPNAME" $webAppName

$settingsContent = Replace-Token $settingsContent "OIDCNAME" $oidcName
$settingsContent = Replace-Token $settingsContent "OIDCCMUserName" $oidcUserNameClaim
$settingsContent = Replace-Token $settingsContent "OIDCCMUserID" $oidcUserIdClaim
$settingsContent = Replace-Token $settingsContent "OIDCCMFirstName" $oidcFirstNameClaim
$settingsContent = Replace-Token $settingsContent "OIDCCMLastName" $oidcLastNameClaim
$settingsContent = Replace-Token $settingsContent "OIDCCMEmailAddress" $oidcEmailClaim

$settingsContent = Replace-Token $settingsContent "PodCount" $podCount
$settingsContent = Replace-Token $settingsContent "CPULIMITSVALUE" "1000"
$settingsContent = Replace-Token $settingsContent "MEMORYLIMITSVALUE" "10T"

$settingsContent = Replace-Token $settingsContent "ACRREPONAME" $acrRepoName
$settingsContent = Replace-Token $settingsContent "ACRREPOLABEL" $acrRepoLabel

$settingsContent = Replace-Token $settingsContent "preInitScriptData" "Cg=="
$settingsContent = Replace-Token $settingsContent "postInitScriptData" "Cg=="
$settingsContent = Replace-TokenBlock $settingsContent "OIDCFileData" "{`n    }"


# Azure-specific fields (set to empty and disable)
$settingsContent = Replace-Token $settingsContent "USEKEYVAULT" "false"
$settingsContent = Replace-Token $settingsContent "KEYVAULTIDENTITCLIENTID" ""
$settingsContent = Replace-Token $settingsContent "KEYVAULTIDENTITYRESOURCEID" '""'
$settingsContent = Replace-Token $settingsContent "SQL_USERNAMESECRET" '""'
$settingsContent = Replace-Token $settingsContent "SQL_USERPASSWORDSECRET" '""'
$settingsContent = Replace-Token $settingsContent "TLS_CERTSECRET" '""'
$settingsContent = Replace-Token $settingsContent "LICENSE_DATASECRET" '""'
$settingsContent = Replace-Token $settingsContent "KEYVAULTNAME" ""
$settingsContent = Replace-Token $settingsContent "KEYVAULTRESOURCEGROUP" ""
$settingsContent = Replace-Token $settingsContent "AZURESUBSCRIPTIONID" ""
$settingsContent = Replace-Token $settingsContent "AZURETENANTID" ""
$settingsContent = Replace-Token $settingsContent "KUBERNETESCLIENTID" ""
$purviewUrlValue = ""
if ($usePurview) { $purviewUrlValue = $purviewAtlasEndpoint }
$settingsContent = Replace-Token $settingsContent "PURVIEWURL" $purviewUrlValue
if (-not $usePurview) {
  $settingsContent = Replace-Token $settingsContent "PURVIEWTENANTID" ""
  $settingsContent = Replace-Token $settingsContent "PURVIEWCOLLECTIONID" ""
  $settingsContent = Replace-Token $settingsContent "PURVIEWCLIENTID" ""
  $settingsContent = Replace-Token $settingsContent "PURVIEWCLIENTSECRET" ""
}

# Force cloud provider flags for AWS
$settingsContent = $settingsContent -replace '(?m)^(\s*azure:\s*\r?\n\s*isProvider:\s*)true', '${1}false'
$settingsContent = $settingsContent -replace '(?m)^(\s*aws:\s*\r?\n\s*isProvider:\s*)false', '${1}true'

# Make EBS volume explicit placeholder for later update
$settingsContent = $settingsContent -replace '(?m)^(\s*ebsVolumeId:\s*).*$','$1"$EBSVOLUMEID"'

[System.IO.File]::WriteAllText($settingsPath, $settingsContent, (New-Object System.Text.UTF8Encoding($false)))
Write-Host ("Wrote settings: {0}" -f $settingsPath)

if ($SeedSecrets) {
  $seedScript = Join-Path $resolvedRepoRoot "scripts\\seed-secrets.ps1"
  if (-not (Test-Path -LiteralPath $seedScript)) {
    throw "seed-secrets.ps1 not found: $seedScript"
  }
  $seedPath = Join-Path $secretsDir "seed-secrets.json"
  if ($NoPrompt -and -not (Test-Path -LiteralPath $seedPath)) {
    throw "seed-secrets.json not found. Run without -NoPrompt to generate it, or create it manually before seeding."
  }
  & $seedScript -DeploymentName $DeploymentName -RepoRoot $resolvedRepoRoot -UpdateConfig
}
