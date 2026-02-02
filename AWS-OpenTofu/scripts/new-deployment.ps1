param(
  [string]$DeploymentName,
  [string]$RepoRoot,
  [switch]$NoPrompt
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "Note: RDS identifier must be lowercase letters, numbers, and hyphens, and start with a letter."
Write-Host "Note: List fields (AZs, subnet CIDRs, EKS instance types, CloudFront aliases, RDP CIDRs) should be comma-separated."
Write-Host "      This script will normalize identifiers and coerce lists before writing the config."

function Read-Value([string]$Label, $Current) {
  $display = if ($null -eq $Current -or $Current -eq "") { "" } else { " [$Current]" }
  $input = Read-Host ("{0}{1}" -f $Label, $display)
  if ($input -eq "") { return $Current }
  return $input
}

function Read-List([string]$Label, $Current) {
  $currentText = if ($null -eq $Current) { "" } elseif ($Current -is [string]) { $Current } else { ($Current -join ",") }
  $input = Read-Host ("{0} [{1}]" -f $Label, $currentText)
  if ($input -eq "") { return $Current }
  $list = @($input -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })
  return ,$list
}

function Read-Number([string]$Label, $Current) {
  $input = Read-Host ("{0} [{1}]" -f $Label, $Current)
  if ($input -eq "") { return $Current }
  return [int]$input
}

function Read-Bool([string]$Label, $Current) {
  $defaultText = if ($Current) { "y" } else { "n" }
  $input = Read-Host ("{0} [y/n, default {1}]" -f $Label, $defaultText)
  if ($input -eq "") { return $Current }
  return ($input.ToLower() -in @("y", "yes", "true", "1"))
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

if (-not (Test-Path -LiteralPath $configPath)) {
  Copy-Item -Force $examplePath $configPath
}

$json = Get-Content -Raw -Path $configPath | ConvertFrom-Json

if (-not $NoPrompt) {
  $json.region = Read-Value "Primary region" $json.region
  $json.use1_region = Read-Value "us-east-1 region (ACM/CloudFront)" $json.use1_region

  $json.tags.Project = Read-Value "Tag: Project" $json.tags.Project
  $json.tags.Environment = Read-Value "Tag: Environment" $json.tags.Environment

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
  $json.eks.endpoint_public_access = Read-Bool "EKS public endpoint" $json.eks.endpoint_public_access
  $json.eks.endpoint_private_access = Read-Bool "EKS private endpoint" $json.eks.endpoint_private_access
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
  $json.rds_sqlserver.publicly_accessible = Read-Bool "RDS publicly accessible" $json.rds_sqlserver.publicly_accessible

  $json.acm.domain_name = Read-Value "ACM domain name" $json.acm.domain_name
  $json.acm.hosted_zone_id = Read-Value "ACM hosted zone ID" $json.acm.hosted_zone_id

  $json.route53.hosted_zone_id = Read-Value "Route53 hosted zone ID" $json.route53.hosted_zone_id
  $json.route53.record_name = Read-Value "Route53 record name" $json.route53.record_name

  $json.cloudfront.enabled = Read-Bool "CloudFront enabled (Stage E)" $json.cloudfront.enabled
  $json.route53.enabled = Read-Bool "Route53 enabled (Stage E)" $json.route53.enabled

  if ($json.cloudfront.enabled) {
    $json.cloudfront.aliases = Read-List "CloudFront aliases (comma-separated)" $json.cloudfront.aliases
    $json.cloudfront.origin_domain_name = Read-Value "CloudFront origin domain (NLB DNS)" $json.cloudfront.origin_domain_name
  }

  $json.jumpbox.enabled = Read-Bool "Jumpbox enabled" $json.jumpbox.enabled
  if ($json.jumpbox.enabled) {
    $json.jumpbox.instance_type = Read-Value "Jumpbox instance type" $json.jumpbox.instance_type
    $json.jumpbox.key_name = Read-Value "Jumpbox key pair name (optional, for RDP)" $json.jumpbox.key_name
    $json.jumpbox.associate_public_ip = Read-Bool "Jumpbox public IP" $json.jumpbox.associate_public_ip
    $json.jumpbox.enable_rdp_ingress = Read-Bool "Jumpbox inbound RDP" $json.jumpbox.enable_rdp_ingress
    $json.jumpbox.allowed_rdp_cidrs = Read-List "Jumpbox RDP CIDRs (comma-separated)" $json.jumpbox.allowed_rdp_cidrs
    $json.jumpbox.assume_role_arn = Read-Value "Jumpbox assume role ARN" $json.jumpbox.assume_role_arn
  }
}

$json.vpc.azs = Coerce-List "VPC AZs" $json.vpc.azs
$json.vpc.public_subnet_cidrs = Coerce-List "Public subnet CIDRs" $json.vpc.public_subnet_cidrs
$json.vpc.private_subnet_cidrs = Coerce-List "Private subnet CIDRs" $json.vpc.private_subnet_cidrs
$json.eks.linux_node_group.instance_types = Coerce-List "EKS linux instance types" $json.eks.linux_node_group.instance_types
$json.eks.windows_node_group.instance_types = Coerce-List "EKS windows instance types" $json.eks.windows_node_group.instance_types
$json.cloudfront.aliases = Coerce-List "CloudFront aliases" $json.cloudfront.aliases
$json.jumpbox.allowed_rdp_cidrs = Coerce-List "Jumpbox RDP CIDRs" $json.jumpbox.allowed_rdp_cidrs

$jsonOut = $json | ConvertTo-Json -Depth 10
[System.IO.File]::WriteAllText($configPath, $jsonOut, (New-Object System.Text.UTF8Encoding($false)))

Write-Host "Wrote config: $configPath"

# ---------------------------------------------------------------------------
# Settings.yaml (Azure-ARM base) download + replacement
# ---------------------------------------------------------------------------
$settingsUrl = "https://raw.githubusercontent.com/Profisee/kubernetes/master/Azure-ARM/Settings.yaml"
$settingsPath = Join-Path $targetDir "Settings.yaml"

try {
  Invoke-WebRequest -Uri $settingsUrl -OutFile $settingsPath | Out-Null
  Write-Host ("Downloaded Settings.yaml to: {0}" -f $settingsPath)
} catch {
  throw "Failed to download Settings.yaml from $settingsUrl"
}

$settingsContent = Get-Content -Raw -Path $settingsPath

$secretsDir = Join-Path $targetDir "secrets"
Ensure-Dir $secretsDir
$licensePath = Join-Path $secretsDir "license.txt"

$externalDnsName = $json.route53.record_name
if (-not $externalDnsName -or $externalDnsName -eq "") { $externalDnsName = $json.acm.domain_name }
if ($externalDnsName -and $externalDnsName.StartsWith("*.")) {
  $externalDnsName = $externalDnsName.Substring(2)
}
$externalDnsUrl = if ($externalDnsName) { "https://$externalDnsName" } else { "" }

$sqlName = $null
$sqlDbName = "Profisee"
$sqlUsername = $json.rds_sqlserver.master_username
$sqlPassword = $null
$useLetsEncrypt = $true
$adminAccount = $null
$infraAdminAccount = $null
$webAppName = "profisee"
$oidcProvider = $null
$oidcName = $null
$oidcUrl = $null
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
$acrEmail = "support@profisee.com"
$useOwnTls = $false
$tlsCert = $null
$tlsKey = $null

if (-not $NoPrompt) {
  $sqlName = Read-Value "SQL Server endpoint (leave blank to fill after tofu-apply)" $sqlName
  $sqlDbName = Read-Value "SQL database name" $sqlDbName
  $useLetsEncrypt = Read-Bool "Use Let's Encrypt (recommended)" $useLetsEncrypt
  $adminAccount = Read-Value "Profisee SuperAdmin email" $adminAccount
  $infraAdminAccount = Read-Value "Infra admin account email (default to SuperAdmin)" $adminAccount
  if (-not $infraAdminAccount -or $infraAdminAccount -eq "") { $infraAdminAccount = $adminAccount }
  $webAppName = Read-Value "Web app name (path segment)" $webAppName

  $oidcProvider = Read-Value "OIDC provider (Entra or Okta)" "Entra"
  if ($oidcProvider -match "entra|azure") {
    $oidcName = "Entra"
    $tenantId = Read-Value "Entra tenant ID" ""
    if ($tenantId) { $oidcUrl = "https://login.microsoftonline.com/$tenantId" }
    $oidcClientId = Read-Value "Entra app registration client ID" $oidcClientId
    $oidcClientSecret = Read-Value "Entra app registration client secret" $oidcClientSecret
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
    $oidcClientId = Read-Value "Okta client ID" $oidcClientId
    $oidcClientSecret = Read-Value "Okta client secret" $oidcClientSecret
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

  $podCount = Read-Value "Cluster node count (app pods)" $podCount

  $acrRepoName = Read-Value "ACR repository name" $acrRepoName
  $acrRepoLabel = Read-Value "ACR image tag/label" $acrRepoLabel
  $acrUser = Read-Value "ACR username" $acrUser
  $acrPassword = Read-Value "ACR password" $acrPassword
  $acrAuth = Read-Value "ACR auth" $acrAuth
  $acrEmail = Read-Value "ACR email" $acrEmail

  $useOwnTls = Read-Bool "Use your own TLS cert (no internal CA certs)" $useOwnTls
  if ($useOwnTls) {
    $certPath = Read-Value "Path to TLS cert PEM" ""
    $keyPath = Read-Value "Path to TLS key PEM" ""
    if ($certPath -and (Test-Path -LiteralPath $certPath)) {
      $tlsCert = Get-Content -Raw -Path $certPath
    }
    if ($keyPath -and (Test-Path -LiteralPath $keyPath)) {
      $tlsKey = Get-Content -Raw -Path $keyPath
    }
    if ($tlsCert -and $tlsKey) {
      $useLetsEncrypt = $false
    }
  }
}

$licenseRaw = Read-FileRaw $licensePath
if (-not $licenseRaw) {
  Write-Host ("Note: license file not found at {0}. Place your license file there as license.txt." -f $licensePath)
}

# Replace core tokens
$settingsContent = Replace-Token $settingsContent "SQLNAME" $sqlName
$settingsContent = Replace-Token $settingsContent "SQLDBNAME" $sqlDbName
$settingsContent = Replace-Token $settingsContent "SQLUSERNAME" $sqlUsername
$settingsContent = Replace-Token $settingsContent "SQLUSERPASSWORD" $sqlPassword
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
$settingsContent = Replace-Token $settingsContent "OIDCURL" $oidcUrl
$settingsContent = Replace-Token $settingsContent "CLIENTID" $oidcClientId
$settingsContent = Replace-Token $settingsContent "OIDCCLIENTSECRET" $oidcClientSecret
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
$settingsContent = Replace-Token $settingsContent "ACRUSER" $acrUser
$settingsContent = Replace-Token $settingsContent "ACRPASSWORD" $acrPassword
$settingsContent = Replace-Token $settingsContent "ACREMAIL" $acrEmail
$settingsContent = Replace-Token $settingsContent "ACRAUTH" $acrAuth

if ($licenseRaw) {
  $settingsContent = Replace-Token $settingsContent "LICENSEDATA" $licenseRaw
}

$settingsContent = Replace-Token $settingsContent "preInitScriptData" "Cg=="
$settingsContent = Replace-Token $settingsContent "postInitScriptData" "Cg=="
$settingsContent = Replace-TokenBlock $settingsContent "OIDCFileData" "{`n    }"

if ($useOwnTls -and $tlsCert) {
  $settingsContent = Replace-TokenBlock $settingsContent "TLSCERT" $tlsCert.Trim()
}
if ($useOwnTls -and $tlsKey) {
  $settingsContent = Replace-TokenBlock $settingsContent "TLSKEY" $tlsKey.Trim()
}

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
$settingsContent = Replace-Token $settingsContent "PURVIEWTENANTID" ""
$settingsContent = Replace-Token $settingsContent "PURVIEWURL" ""
$settingsContent = Replace-Token $settingsContent "PURVIEWCOLLECTIONID" ""
$settingsContent = Replace-Token $settingsContent "PURVIEWCLIENTID" ""
$settingsContent = Replace-Token $settingsContent "PURVIEWCLIENTSECRET" ""

# Force cloud provider flags for AWS
$settingsContent = $settingsContent -replace '(?m)^(\s*azure:\s*\r?\n\s*isProvider:\s*)true', '${1}false'
$settingsContent = $settingsContent -replace '(?m)^(\s*aws:\s*\r?\n\s*isProvider:\s*)false', '${1}true'

# Make EBS volume explicit placeholder for later update
$settingsContent = $settingsContent -replace '(?m)^(\s*ebsVolumeId:\s*).*$','$1"$EBSVOLUMEID"'

[System.IO.File]::WriteAllText($settingsPath, $settingsContent, (New-Object System.Text.UTF8Encoding($false)))
Write-Host ("Wrote settings: {0}" -f $settingsPath)
