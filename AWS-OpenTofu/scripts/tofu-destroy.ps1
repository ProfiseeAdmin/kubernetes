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
  $raw = & aws @listArgs 2>&1
  if ($LASTEXITCODE -ne 0) {
    if ($raw -match "NoSuchBucket") {
      Write-Host "Bucket $Bucket does not exist; skipping purge."
      return
    }
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

function Get-VpcIdByName([string]$VpcName, [string]$Region) {
  if (-not $VpcName) { return $null }
  $awsCmd = Get-Command aws -ErrorAction SilentlyContinue
  if (-not $awsCmd) {
    Write-Host "AWS CLI not found; skipping VPC lookup."
    return $null
  }
  $tagName = "$VpcName-vpc"
  $args = @("ec2", "describe-vpcs", "--filters", "Name=tag:Name,Values=$tagName", "--query", "Vpcs[0].VpcId", "--output", "text", "--region", $Region)
  $raw = & aws @args 2>&1
  if ($LASTEXITCODE -ne 0) {
    Write-Host ("Failed to lookup VPC by tag Name={0}: {1}" -f $tagName, $raw)
    return $null
  }
  if ($raw -and $raw -ne "None") { return $raw.Trim() }
  return $null
}

function Remove-LoadBalancers([string]$VpcId, [string]$Region) {
  if (-not $VpcId) { return }
  $awsCmd = Get-Command aws -ErrorAction SilentlyContinue
  if (-not $awsCmd) {
    Write-Host "AWS CLI not found; skipping load balancer cleanup."
    return
  }

  Write-Host ("Checking for load balancers in VPC {0}..." -f $VpcId)

  # ELBv2 (ALB/NLB)
  $lbArgs = @("elbv2", "describe-load-balancers", "--region", $Region, "--query", "LoadBalancers[?VpcId=='$VpcId'].{Arn:LoadBalancerArn,Name:LoadBalancerName}", "--output", "json")
  $lbRaw = & aws @lbArgs 2>&1
  if ($LASTEXITCODE -ne 0) {
    throw "Failed to list ELBv2 load balancers in VPC $VpcId (exit code $LASTEXITCODE)."
  }
  $lbList = @()
  if ($lbRaw) { $lbList = @($lbRaw | ConvertFrom-Json) }
  foreach ($lb in $lbList) {
    $arn = $null
    $name = $null

    if ($lb -is [string]) {
      # Defensive fallback if JSON shape is unexpectedly a string.
      $arn = $lb
      $name = $lb
    } elseif ($lb -is [System.Collections.IList]) {
      if ($lb.Count -gt 0) { $arn = $lb[0] }
      if ($lb.Count -gt 1) { $name = $lb[1] }
    } else {
      $arn = Get-OptionalProperty $lb "Arn"
      if (-not $arn) { $arn = Get-OptionalProperty $lb "LoadBalancerArn" }
      $name = Get-OptionalProperty $lb "Name"
      if (-not $name) { $name = Get-OptionalProperty $lb "LoadBalancerName" }
    }

    if ($arn) {
      if ($arn -notmatch '^arn:') {
        Write-Host ("Skipping ELBv2 entry with non-ARN value: {0}" -f $arn)
        continue
      }
      Write-Host ("Deleting ELBv2 load balancer: {0} ({1})" -f $name, $arn)
      & aws elbv2 delete-load-balancer --load-balancer-arn $arn --region $Region | Out-Null
      if ($LASTEXITCODE -ne 0) {
        throw "Failed to delete ELBv2 load balancer $name (exit code $LASTEXITCODE)."
      }
    }
  }

  # Classic ELB
  $elbArgs = @("elb", "describe-load-balancers", "--region", $Region, "--query", "LoadBalancerDescriptions[?VPCId=='$VpcId'].LoadBalancerName", "--output", "json")
  $elbRaw = & aws @elbArgs 2>&1
  if ($LASTEXITCODE -ne 0) {
    throw "Failed to list classic ELBs in VPC $VpcId (exit code $LASTEXITCODE)."
  }
  $elbList = @()
  if ($elbRaw) { $elbList = $elbRaw | ConvertFrom-Json }
  foreach ($name in $elbList) {
    if ($name) {
      Write-Host ("Deleting classic ELB: {0}" -f $name)
      & aws elb delete-load-balancer --load-balancer-name $name --region $Region | Out-Null
      if ($LASTEXITCODE -ne 0) {
        throw "Failed to delete classic ELB $name (exit code $LASTEXITCODE)."
      }
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

$vpcCfg = Get-OptionalProperty $config "vpc"
$vpcName = Get-OptionalProperty $vpcCfg "name"
$vpcId = Get-VpcIdByName -VpcName $vpcName -Region $region
if ($vpcId) {
  Remove-LoadBalancers -VpcId $vpcId -Region $region
} else {
  Write-Host "VPC ID not found; skipping load balancer cleanup."
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

