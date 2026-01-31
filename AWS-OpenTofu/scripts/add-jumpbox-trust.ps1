param(
  [Parameter(Mandatory = $true)]
  [string]$DeploymentName,

  [Parameter(Mandatory = $true)]
  [string]$DeployRoleName,

  [string]$RepoRoot,
  [string]$BackendConfigPath,
  [string]$VarFilePath,
  [string]$JumpboxRoleArn
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Get-Command tofu -ErrorAction SilentlyContinue)) {
  throw "OpenTofu (tofu) is not on PATH. Install OpenTofu and try again."
}

if (-not (Get-Command aws -ErrorAction SilentlyContinue)) {
  throw "AWS CLI (aws) is not on PATH. Install AWS CLI and try again."
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

tofu -chdir=$infraRoot init -backend-config=$backendConfig | Out-Null

if (-not $JumpboxRoleArn) {
  $outputs = tofu -chdir=$infraRoot output -json outputs_contract | ConvertFrom-Json
  if (-not $outputs.jumpbox_role_arn -or $outputs.jumpbox_role_arn -eq "") {
    throw "jumpbox_role_arn not found in outputs. Ensure jumpbox.enabled=true and apply infra first."
  }
  $JumpboxRoleArn = $outputs.jumpbox_role_arn
}

$roleInfo = aws iam get-role --role-name $DeployRoleName --output json | ConvertFrom-Json
$assumeDoc = $roleInfo.Role.AssumeRolePolicyDocument

if ($assumeDoc -is [string]) {
  if ($assumeDoc -match "%") {
    $assumeDoc = [System.Net.WebUtility]::UrlDecode($assumeDoc)
  }
  $assumeDoc = $assumeDoc | ConvertFrom-Json
}

if (-not $assumeDoc.Statement) {
  $assumeDoc | Add-Member -MemberType NoteProperty -Name Statement -Value @()
}

$statements = @($assumeDoc.Statement)
$exists = $false

foreach ($stmt in $statements) {
  $actions = $stmt.Action
  if ($actions -is [string]) { $actions = @($actions) }
  if ($stmt.Effect -ne "Allow" -or $actions -notcontains "sts:AssumeRole") { continue }
  $principal = $stmt.Principal
  if (-not $principal) { continue }
  $awsPrincipal = $principal.AWS
  if ($awsPrincipal -is [string]) {
    if ($awsPrincipal -eq $JumpboxRoleArn) { $exists = $true; break }
  } elseif ($awsPrincipal -is [System.Collections.IEnumerable]) {
    if ($awsPrincipal -contains $JumpboxRoleArn) { $exists = $true; break }
  }
}

if (-not $exists) {
  $newStmt = [ordered]@{
    Effect    = "Allow"
    Action    = "sts:AssumeRole"
    Principal = @{ AWS = $JumpboxRoleArn }
  }
  $assumeDoc.Statement = @($assumeDoc.Statement + $newStmt)
}

$tempPolicyPath = Join-Path $env:TEMP ("assume-role-{0}.json" -f ([guid]::NewGuid()))
$assumeDoc | ConvertTo-Json -Depth 10 | Set-Content -Path $tempPolicyPath -Encoding UTF8

try {
  aws iam update-assume-role-policy --role-name $DeployRoleName --policy-document file://$tempPolicyPath | Out-Null
  Write-Host "Updated trust policy for role: $DeployRoleName"
} finally {
  if (Test-Path -LiteralPath $tempPolicyPath) {
    Remove-Item -LiteralPath $tempPolicyPath -Force
  }
}
