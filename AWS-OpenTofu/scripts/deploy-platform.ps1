param(
  [Parameter(Mandatory = $true)]
  [string]$DeploymentName,

  [string]$RepoRoot,
  [string]$KubeconfigPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Get-Command kubectl -ErrorAction SilentlyContinue)) {
  throw "kubectl is not on PATH. Install kubectl and try again."
}
if (-not (Get-Command helm -ErrorAction SilentlyContinue)) {
  throw "helm is not on PATH. Install helm and try again."
}
if (-not (Get-Command aws -ErrorAction SilentlyContinue)) {
  throw "AWS CLI (aws) is not on PATH. Install AWS CLI and try again."
}

$resolvedRepoRoot = if ($RepoRoot) { Resolve-Path $RepoRoot } else { Resolve-Path (Join-Path $PSScriptRoot "..") }
$deploymentPath = Join-Path $resolvedRepoRoot "customer-deployments\$DeploymentName"
$configPath = Join-Path $deploymentPath "config.auto.tfvars.json"

if (-not (Test-Path -LiteralPath $configPath)) {
  throw "config.auto.tfvars.json not found: $configPath"
}

$cfg = Get-Content -Raw -Path $configPath | ConvertFrom-Json
$region = $cfg.region

# Ensure kubeconfig is ready (private clusters require running from jumpbox/VPN).
$kubeScript = Join-Path $resolvedRepoRoot "scripts\\kubeconfig.ps1"
if (Test-Path -LiteralPath $kubeScript) {
  if ($KubeconfigPath) {
    & $kubeScript -DeploymentName $DeploymentName -RepoRoot $resolvedRepoRoot -KubeconfigPath $KubeconfigPath
  } else {
    & $kubeScript -DeploymentName $DeploymentName -RepoRoot $resolvedRepoRoot
  }
}

$traefikValuesDir = Join-Path $resolvedRepoRoot "platform\\helm\\traefik"
$traefikValues = Join-Path $traefikValuesDir "values.yaml"
$traefikValuesCloudfront = Join-Path $traefikValuesDir "values-cloudfront.yaml"
if (-not (Test-Path -LiteralPath $traefikValues)) {
  throw "Traefik values file not found: $traefikValues"
}

Write-Host "Installing/Updating Traefik..."
& helm repo add traefik https://traefik.github.io/charts | Out-Null
& helm repo update | Out-Null

$valuesFile = if ($cfg.cloudfront.enabled -eq $true -and (Test-Path -LiteralPath $traefikValuesCloudfront)) { $traefikValuesCloudfront } else { $traefikValues }

& helm upgrade --install traefik traefik/traefik -n traefik --create-namespace -f $valuesFile
if ($LASTEXITCODE -ne 0) {
  throw "Traefik helm install failed (exit code $LASTEXITCODE)."
}

Write-Host "Waiting for Traefik LoadBalancer hostname..."
$lbHost = $null
$timeoutSeconds = 1200
$start = Get-Date
while (-not $lbHost) {
  $lbHost = & kubectl get svc -n traefik traefik -o jsonpath="{.status.loadBalancer.ingress[0].hostname}" 2>$null
  if ($lbHost) { break }
  if ((Get-Date) -gt $start.AddSeconds($timeoutSeconds)) {
    throw "Timed out waiting for Traefik LoadBalancer hostname."
  }
  Start-Sleep -Seconds 10
}

Write-Host ("Traefik NLB DNS: {0}" -f $lbHost)

# Update config with NLB DNS for later CloudFront stage (if not already set).
if ($cfg.cloudfront -and $lbHost) {
  if (-not $cfg.cloudfront.origin_domain_name -or $cfg.cloudfront.origin_domain_name -eq "" -or $cfg.cloudfront.origin_domain_name -match "nlb-.*\\.elb\\.amazonaws\\.com") {
    $cfg.cloudfront.origin_domain_name = $lbHost
  }
}

# Write a small outputs file for convenience.
$outputsDir = Join-Path $deploymentPath "outputs"
if (-not (Test-Path -LiteralPath $outputsDir)) {
  New-Item -ItemType Directory -Path $outputsDir | Out-Null
}
$platformOut = @{
  traefik_nlb_dns = $lbHost
  fqdn            = $cfg.route53.record_name
} | ConvertTo-Json -Depth 4
[System.IO.File]::WriteAllText((Join-Path $outputsDir "platform.json"), $platformOut, (New-Object System.Text.UTF8Encoding($false)))

# Update Route53 CNAME for the chosen FQDN (if hosted zone + record provided).
$hostedZoneId = $cfg.route53.hosted_zone_id
$recordName = $cfg.route53.record_name
if ($hostedZoneId -and $recordName -and $lbHost) {
  Write-Host ("Updating Route53 CNAME {0} -> {1}" -f $recordName, $lbHost)
  $changeBatch = @{
    Changes = @(
      @{
        Action = "UPSERT"
        ResourceRecordSet = @{
          Name = $recordName
          Type = "CNAME"
          TTL  = 60
          ResourceRecords = @(@{ Value = $lbHost })
        }
      }
    )
  } | ConvertTo-Json -Depth 6

  $tmp = New-TemporaryFile
  [System.IO.File]::WriteAllText($tmp, $changeBatch, (New-Object System.Text.UTF8Encoding($false)))
  & aws route53 change-resource-record-sets --hosted-zone-id $hostedZoneId --change-batch file://$tmp | Out-Null
  Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue
} else {
  Write-Host "Route53 details not set; skipping DNS update."
}

[System.IO.File]::WriteAllText($configPath, ($cfg | ConvertTo-Json -Depth 10), (New-Object System.Text.UTF8Encoding($false)))
Write-Host ("Updated config: {0}" -f $configPath)

