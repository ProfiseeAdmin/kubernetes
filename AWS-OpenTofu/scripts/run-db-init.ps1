param(
  [Parameter(Mandatory = $true)]
  [string]$DeploymentName,

  [string]$RepoRoot,
  [string]$Region,
  [string]$ClusterArn,
  [string]$TaskDefinitionArn,
  [string]$SubnetIds,
  [string]$SecurityGroupIds,
  [switch]$AssignPublicIp
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Get-Command aws -ErrorAction SilentlyContinue)) {
  throw "AWS CLI (aws) is not on PATH. Install AWS CLI and try again."
}
if (-not (Get-Command tofu -ErrorAction SilentlyContinue)) {
  throw "OpenTofu (tofu) is not on PATH. Install OpenTofu and try again."
}

$resolvedRepoRoot = if ($RepoRoot) { Resolve-Path $RepoRoot } else { Resolve-Path (Join-Path $PSScriptRoot "..") }
$deploymentPath = Join-Path $resolvedRepoRoot "customer-deployments\$DeploymentName"
$backendConfig = Join-Path $deploymentPath "backend.hcl"
$varFile = Join-Path $deploymentPath "config.auto.tfvars.json"
$infraRoot = Join-Path $resolvedRepoRoot "infra\root"

if (-not (Test-Path -LiteralPath $backendConfig)) {
  throw "backend.hcl not found: $backendConfig"
}
if (-not (Test-Path -LiteralPath $varFile)) {
  throw "config.auto.tfvars.json not found: $varFile"
}

if (-not $Region -or $Region -eq "") {
  $cfg = Get-Content -Raw -Path $varFile | ConvertFrom-Json
  $Region = if ($cfg.region) { $cfg.region } else { "us-east-1" }
}

Push-Location $infraRoot
try {
  tofu init "-backend-config=$backendConfig" | Out-Null
  $outputs = tofu output -json outputs_contract | ConvertFrom-Json
} finally {
  Pop-Location
}

if (-not $ClusterArn) { $ClusterArn = $outputs.db_init_cluster_arn }
if (-not $TaskDefinitionArn) { $TaskDefinitionArn = $outputs.db_init_task_definition_arn }
if (-not $SubnetIds) { $SubnetIds = ($outputs.private_subnet_ids -join ",") }
if (-not $SecurityGroupIds) { $SecurityGroupIds = $outputs.db_init_security_group_id }

if (-not $ClusterArn) { throw "db_init_cluster_arn not found in outputs_contract." }
if (-not $TaskDefinitionArn) { throw "db_init_task_definition_arn not found in outputs_contract." }
if (-not $SubnetIds) { throw "private_subnet_ids not found in outputs_contract." }
if (-not $SecurityGroupIds) { throw "db_init_security_group_id not found in outputs_contract." }

$subnetList = @($SubnetIds -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })
$sgList = @($SecurityGroupIds -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })

$assignPublicIpValue = if ($AssignPublicIp) { "ENABLED" } else { "DISABLED" }

$networkConfig = @{
  awsvpcConfiguration = @{
    subnets        = $subnetList
    securityGroups = $sgList
    assignPublicIp = $assignPublicIpValue
  }
} | ConvertTo-Json -Depth 5 -Compress

Write-Host "Starting DB init Fargate task..."
aws ecs run-task `
  --cluster $ClusterArn `
  --launch-type FARGATE `
  --task-definition $TaskDefinitionArn `
  --network-configuration $networkConfig `
  --region $Region | Out-Null

if ($LASTEXITCODE -ne 0) {
  throw "Failed to start DB init Fargate task."
}

Write-Host "DB init task started."
