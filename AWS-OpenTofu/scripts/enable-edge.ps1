param(
  [Parameter(Mandatory = $true)]
  [string]$DeploymentName,

  [string]$RepoRoot,
  [string]$NlbDns,
  [switch]$Apply
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-OptionalProperty($obj, [string]$Name) {
  if ($null -eq $obj) { return $null }
  $prop = $obj.PSObject.Properties[$Name]
  if ($null -eq $prop) { return $null }
  return $prop.Value
}

$resolvedRepoRoot = if ($RepoRoot) { Resolve-Path $RepoRoot } else { Resolve-Path (Join-Path $PSScriptRoot "..") }
$deploymentPath = Join-Path $resolvedRepoRoot "customer-deployments\$DeploymentName"
$configPath = Join-Path $deploymentPath "config.auto.tfvars.json"

if (-not (Test-Path -LiteralPath $configPath)) {
  throw "config.auto.tfvars.json not found: $configPath"
}

$cfg = Get-Content -Raw -Path $configPath | ConvertFrom-Json

if (-not $NlbDns -or $NlbDns -eq "") {
  $outputsPath = Join-Path $deploymentPath "outputs\\platform.json"
  if (Test-Path -LiteralPath $outputsPath) {
    try {
      $platform = Get-Content -Raw -Path $outputsPath | ConvertFrom-Json
      $NlbDns = Get-OptionalProperty $platform "traefik_nlb_dns"
      if (-not $cfg.route53.record_name) {
        $cfg.route53.record_name = Get-OptionalProperty $platform "fqdn"
      }
    } catch {
      Write-Host "Warning: failed to parse outputs/platform.json; will try S3."
    }
  }
}

if (-not $NlbDns -or $NlbDns -eq "") {
  $awsCmd = Get-Command aws -ErrorAction SilentlyContinue
  $settingsBucket = Get-OptionalProperty $cfg.settings_bucket "name"
  $clusterName = Get-OptionalProperty $cfg.eks "cluster_name"
  if ($awsCmd -and $settingsBucket -and $clusterName) {
    $key = "outputs/$clusterName/platform.json"
    $tmp = New-TemporaryFile
    try {
      & aws s3 cp ("s3://{0}/{1}" -f $settingsBucket, $key) $tmp | Out-Null
      if ($LASTEXITCODE -eq 0) {
        $platform = Get-Content -Raw -Path $tmp | ConvertFrom-Json
        $NlbDns = Get-OptionalProperty $platform "traefik_nlb_dns"
        if (-not $cfg.route53.record_name) {
          $cfg.route53.record_name = Get-OptionalProperty $platform "fqdn"
        }
      }
    } finally {
      Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue
    }
  }
}

if (-not $NlbDns -or $NlbDns -eq "") {
  throw "Could not determine NLB DNS. Provide -NlbDns or ensure outputs/platform.json or S3 platform.json exists."
}

$cfg.cloudfront.enabled = $true
$cfg.route53.enabled = $true
$cfg.cloudfront.origin_domain_name = $NlbDns

if (-not $cfg.cloudfront.aliases -or $cfg.cloudfront.aliases.Count -eq 0) {
  if ($cfg.route53.record_name) {
    $cfg.cloudfront.aliases = @($cfg.route53.record_name)
  }
}

[System.IO.File]::WriteAllText($configPath, ($cfg | ConvertTo-Json -Depth 10), (New-Object System.Text.UTF8Encoding($false)))
Write-Host ("Updated config for Stage E: {0}" -f $configPath)
Write-Host ("CloudFront origin set to: {0}" -f $NlbDns)

if ($Apply) {
  & (Join-Path $resolvedRepoRoot "scripts\\tofu-apply.ps1") -DeploymentName $DeploymentName
}
