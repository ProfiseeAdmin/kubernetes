param(
  [Parameter(Mandatory = $true)]
  [string]$DeploymentName,

  [string]$RepoRoot,
  [string]$BackendConfigPath,
  [string]$VarFilePath,
  [string]$ExtraVarFile,
  [switch]$AutoApprove,
  [string]$DeployRoleName = "opentofu-deploy",
  [string]$JumpboxRoleArn,
  [bool]$EnsureJumpboxKey = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Get-Command tofu -ErrorAction SilentlyContinue)) {
  throw "OpenTofu (tofu) is not on PATH. Install OpenTofu and try again."
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

# Safe property access under StrictMode
function Get-PropValue($obj, [string]$name) {
  if ($null -eq $obj) { return $null }
  $prop = $obj.PSObject.Properties[$name]
  if ($null -eq $prop) { return $null }
  return $prop.Value
}

function Get-FileUri([string]$Path) {
  $full = [System.IO.Path]::GetFullPath($Path)
  if ($full -match '^[A-Za-z]:\\') {
    $normalized = $full -replace '\\','/'
    return "file://$normalized"
  }
  return "file://$full"
}

function Get-PropertyCount($obj) {
  if ($null -eq $obj) { return 0 }
  if ($obj -is [System.Collections.IDictionary]) { return $obj.Count }
  try {
    return @($obj.PSObject.Properties).Count
  } catch {
    return 0
  }
}

function Has-Entries($obj) {
  return (Get-PropertyCount $obj) -gt 0
}

function Has-SecretValues($obj) {
  if ($null -eq $obj) { return $false }
  $values = @()
  if ($obj -is [System.Collections.IDictionary]) {
    $values = @($obj.Values)
  } else {
    $values = @($obj.PSObject.Properties | ForEach-Object { $_.Value })
  }
  foreach ($v in $values) {
    if ($null -ne $v -and $v -ne "" -and $v -ne "None") { return $true }
  }
  return $false
}

function Get-ProfiseeDeployConfig($cfgObj) {
  return Get-PropValue $cfgObj "profisee_deploy"
}

$cachedOutputs = $null
function Get-Outputs([string]$InfraRoot, [string]$BackendConfigPath) {
  if ($null -ne $script:cachedOutputs) { return $script:cachedOutputs }
  Push-Location $InfraRoot
  try {
    tofu init "-backend-config=$BackendConfigPath" | Out-Null
    $script:cachedOutputs = tofu output -json outputs_contract | ConvertFrom-Json
  } finally {
    Pop-Location
  }
  return $script:cachedOutputs
}

function Read-JsonFileOrNull([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) { return $null }
  try {
    return Get-Content -Raw -Path $Path | ConvertFrom-Json
  } catch {
    return $null
  }
}

function Normalize-CloudFrontAliases($Aliases) {
  $result = @()
  foreach ($raw in @($Aliases)) {
    if ($null -eq $raw) { continue }
    $v = $raw.ToString().Trim().ToLower()
    if ($v -eq "") { continue }
    if ($v -match '^https?://') {
      $v = $v -replace '^https?://', ''
    }
    if ($v.Contains("/")) {
      $v = ($v -split '/')[0]
    }
    $v = $v.Trim(".")
    if ($v -eq "" -or $v -eq "app.example.com") { continue }
    if ($v -match '^[a-z0-9][a-z0-9.-]*[a-z0-9]$' -and $v.Contains(".")) {
      if ($result -notcontains $v) { $result += $v }
    }
  }
  return ,$result
}

# If the user changed the deploy role name, derive it from config when possible.
try {
  $cfg = Get-Content -Raw -Path $varFile | ConvertFrom-Json
  $cfgChanged = $false
  if ($null -ne (Get-PropValue $cfg "db_init")) {
    $cfg.PSObject.Properties.Remove("db_init")
    Write-Host "Removed legacy db_init block from config.auto.tfvars.json."
    $cfgChanged = $true
  }

  $cloudfrontCfgForPrecheck = Get-PropValue $cfg "cloudfront"
  if ($cloudfrontCfgForPrecheck) {
    $aliasesRaw = Get-PropValue $cloudfrontCfgForPrecheck "aliases"
    $aliasesNormalized = Normalize-CloudFrontAliases $aliasesRaw
    $route53CfgForPrecheck = Get-PropValue $cfg "route53"
    $route53NameForPrecheck = Get-PropValue $route53CfgForPrecheck "record_name"
    if ($aliasesNormalized.Count -eq 0 -and $route53NameForPrecheck) {
      $aliasesNormalized = Normalize-CloudFrontAliases @($route53NameForPrecheck)
    }

    $existingAliasesForCompare = @($aliasesRaw | ForEach-Object { $_.ToString().Trim().ToLower().Trim(".") } | Where-Object { $_ -ne "" })
    if (($aliasesNormalized -join ",") -ne ($existingAliasesForCompare -join ",")) {
      $cfg.cloudfront.aliases = $aliasesNormalized
      Write-Host ("Normalized CloudFront aliases in config: {0}" -f ($aliasesNormalized -join ", "))
      $cfgChanged = $true
    }
  }

  if ($cfgChanged) {
    [System.IO.File]::WriteAllText($varFile, ($cfg | ConvertTo-Json -Depth 10), (New-Object System.Text.UTF8Encoding($false)))
  }
  $cfgAssumeArn = $cfg.jumpbox.assume_role_arn
  if ($cfgAssumeArn -and $DeployRoleName -eq "opentofu-deploy") {
    $derivedRoleName = ($cfgAssumeArn -split "/")[-1]
    if ($derivedRoleName -and $derivedRoleName -ne $DeployRoleName) {
      Write-Host ("Using deploy role name from config: {0}" -f $derivedRoleName)
      $DeployRoleName = $derivedRoleName
    }
  }
} catch {
  # Non-fatal; keep DeployRoleName as-is.
}

if ($cfg) {
  $profiseeDeployCfgEarly = Get-ProfiseeDeployConfig $cfg
  $profiseeDeployEnabledEarly = Get-PropValue $profiseeDeployCfgEarly "enabled"
  if ($profiseeDeployEnabledEarly -eq $true) {
    $profiseeDeploySecretsEarly = Get-PropValue $profiseeDeployCfgEarly "secret_arns"
    if (-not (Has-Entries $profiseeDeploySecretsEarly) -or -not (Has-SecretValues $profiseeDeploySecretsEarly)) {
      throw "profisee_deploy.secret_arns is empty. Run scripts\\seed-secrets.ps1 -UpdateConfig before tofu-apply."
    }
  }
}

if ($EnsureJumpboxKey) {
  if (-not (Get-Command aws -ErrorAction SilentlyContinue)) {
    throw "AWS CLI (aws) is not on PATH. Install AWS CLI and try again."
  }

  $jumpboxCfg = Get-PropValue $cfg "jumpbox"
  $jumpboxEnabled = Get-PropValue $jumpboxCfg "enabled"
  if ($jumpboxEnabled -eq $true) {
    $region = Get-PropValue $cfg "region"
    if (-not $region -or $region -eq "") { $region = "us-east-1" }

    $keyName = Get-PropValue $jumpboxCfg "key_name"
    if (-not $keyName -or $keyName -eq "") {
      $createKeyScript = Join-Path $resolvedRepoRoot "scripts\create-jumpbox-key.ps1"
      if (-not (Test-Path -LiteralPath $createKeyScript)) {
        throw "create-jumpbox-key.ps1 not found: $createKeyScript"
      }
      & $createKeyScript -DeploymentName $DeploymentName -RepoRoot $resolvedRepoRoot
    } else {
      $keyExists = $true
      aws ec2 describe-key-pairs --region $region --key-names $keyName | Out-Null
      if ($LASTEXITCODE -ne 0) { $keyExists = $false }

      if (-not $keyExists) {
        $createKeyScript = Join-Path $resolvedRepoRoot "scripts\create-jumpbox-key.ps1"
        if (-not (Test-Path -LiteralPath $createKeyScript)) {
          throw "create-jumpbox-key.ps1 not found: $createKeyScript"
        }
        & $createKeyScript -DeploymentName $DeploymentName -KeyName $keyName -RepoRoot $resolvedRepoRoot
      } else {
        $secretsDir = Join-Path $deploymentPath "secrets"
        $keyPath = Join-Path $secretsDir ("{0}.pem" -f $keyName)
        if (-not (Test-Path -LiteralPath $keyPath)) {
          Write-Host "Warning: Key pair '$keyName' exists in AWS but PEM not found at $keyPath."
          Write-Host "         AWS does not allow re-downloading an existing key. Create a new key name if needed."
        }
      }
    }
  }
}

$infraRoot = Join-Path $resolvedRepoRoot "infra\root"

if (-not (Test-Path -LiteralPath $infraRoot)) {
  throw "Infra root not found: $infraRoot"
}

Push-Location $infraRoot
try {
  tofu init "-backend-config=$backendConfig"

  $applyArgs = @("apply", "-var-file=$varFile")
  if ($ExtraVarFile) {
    $applyArgs += "-var-file=$ExtraVarFile"
  }
  if ($AutoApprove) {
    $applyArgs += "-auto-approve"
  }
  tofu @applyArgs
  if ($LASTEXITCODE -ne 0) {
    throw "OpenTofu apply failed (exit code $LASTEXITCODE)."
  }
} finally {
  Pop-Location
}

$trustScript = Join-Path $resolvedRepoRoot "scripts\add-jumpbox-trust.ps1"
if (Test-Path -LiteralPath $trustScript) {
  $shouldUpdateTrust = $false
  if ($JumpboxRoleArn -and $JumpboxRoleArn -ne "") {
    $shouldUpdateTrust = $true
  } else {
    try {
      $outputs = Get-Outputs -InfraRoot $infraRoot -BackendConfigPath $backendConfig
      if ($outputs.jumpbox_role_arn -and $outputs.jumpbox_role_arn -ne "") {
        $JumpboxRoleArn = $outputs.jumpbox_role_arn
        $shouldUpdateTrust = $true
      }
    } catch {
      $shouldUpdateTrust = $false
    }
  }

  if ($shouldUpdateTrust) {
    & $trustScript `
      -DeploymentName $DeploymentName `
      -DeployRoleName $DeployRoleName `
      -RepoRoot $resolvedRepoRoot `
      -BackendConfigPath $backendConfig `
      -VarFilePath $varFile `
      -JumpboxRoleArn $JumpboxRoleArn
  } else {
    Write-Host "Jumpbox trust update skipped (jumpbox role not found or jumpbox disabled)."
  }
} else {
  Write-Host "Jumpbox trust update skipped (script not found: $trustScript)."
}

# ---------------------------------------------------------------------------
# Update Settings.yaml with post-apply outputs (SQL endpoint, EBS volume)
# ---------------------------------------------------------------------------
$settingsPath = Join-Path $deploymentPath "Settings.yaml"
if (Test-Path -LiteralPath $settingsPath) {
  try {
    $outputs = Get-Outputs -InfraRoot $infraRoot -BackendConfigPath $backendConfig

    $settingsContent = Get-Content -Raw -Path $settingsPath
    $updated = $false

    $rdsEndpoint = Get-PropValue $outputs "rds_endpoint"
    if ($rdsEndpoint -and $settingsContent -match '\$SQLNAME') {
      $settingsContent = $settingsContent.Replace('$SQLNAME', $rdsEndpoint)
      $updated = $true
    }

    $ebsId = $null
    foreach ($candidate in @("ebs_volume_id", "app_ebs_volume_id", "fileshare_ebs_volume_id", "profisee_ebs_volume_id")) {
      $value = Get-PropValue $outputs $candidate
      if ($value) { $ebsId = $value; break }
    }
    if ($ebsId) {
      $settingsContent = [regex]::Replace($settingsContent, '(?m)^(\s*ebsVolumeId:\s*).*$',
        { param($m) ($m.Groups[1].Value + '"' + $ebsId + '"') })
      $updated = $true
    }

    if ($updated) {
      [System.IO.File]::WriteAllText($settingsPath, $settingsContent, (New-Object System.Text.UTF8Encoding($false)))
      Write-Host ("Updated Settings.yaml with post-apply values: {0}" -f $settingsPath)
    } else {
      Write-Host "Settings.yaml not updated (no matching outputs or placeholders)."
    }
  } catch {
    Write-Host ("Warning: failed to update Settings.yaml with outputs. {0}" -f $_.Exception.Message)
  }
} else {
  Write-Host ("Settings.yaml not found; skipping post-apply update: {0}" -f $settingsPath)
}

# ---------------------------------------------------------------------------
# Upload Settings.yaml to S3 for ECS-based app deployment
# ---------------------------------------------------------------------------
$profiseeDeployCfgForSettings = Get-ProfiseeDeployConfig $cfg
$profiseeDeployEnabledForSettings = Get-PropValue $profiseeDeployCfgForSettings "enabled"
$settingsBucketCfg = Get-PropValue $cfg "settings_bucket"
$settingsBucketEnabled = Get-PropValue $settingsBucketCfg "enabled"
if ($null -eq $settingsBucketEnabled) { $settingsBucketEnabled = $true }
if ($profiseeDeployEnabledForSettings -eq $true -and $settingsBucketEnabled -eq $true) {
  if (Test-Path -LiteralPath $settingsPath) {
    $uploadSettingsScript = Join-Path $resolvedRepoRoot "scripts\upload-settings.ps1"
    if (-not (Test-Path -LiteralPath $uploadSettingsScript)) {
      throw "upload-settings.ps1 not found: $uploadSettingsScript"
    }

    Write-Host "Uploading Settings.yaml to settings bucket..."
    & $uploadSettingsScript -DeploymentName $DeploymentName -RepoRoot $resolvedRepoRoot
    Write-Host "Settings.yaml uploaded."
  } else {
    Write-Host ("Settings.yaml not found; skipping S3 upload: {0}" -f $settingsPath)
  }
}

# ---------------------------------------------------------------------------
# Auto-run profisee_deploy task (Fargate) when enabled
# ---------------------------------------------------------------------------
$profiseeDeployCfg = Get-ProfiseeDeployConfig $cfg
$profiseeDeployEnabled = Get-PropValue $profiseeDeployCfg "enabled"
$profiseeDeployTaskSucceeded = $false
if ($profiseeDeployEnabled -eq $true) {
  if (-not (Get-Command aws -ErrorAction SilentlyContinue)) {
    throw "AWS CLI (aws) is not on PATH. Install AWS CLI and try again."
  }

  $profiseeDeploySecrets = Get-PropValue $profiseeDeployCfg "secret_arns"
  if (-not (Has-Entries $profiseeDeploySecrets) -or -not (Has-SecretValues $profiseeDeploySecrets)) {
    throw "profisee_deploy.secret_arns is empty. Run scripts\\seed-secrets.ps1 -UpdateConfig before tofu-apply."
  }

  $region = Get-PropValue $cfg "region"
  if (-not $region -or $region -eq "") { $region = "us-east-1" }

  $outputs = Get-Outputs -InfraRoot $infraRoot -BackendConfigPath $backendConfig
  $clusterArn = Get-PropValue $outputs "profisee_deploy_cluster_arn"
  $taskDefArn = Get-PropValue $outputs "profisee_deploy_task_definition_arn"
  $sgId = Get-PropValue $outputs "profisee_deploy_security_group_id"
  $subnetIds = Get-PropValue $outputs "private_subnet_ids"

  if (-not $clusterArn -or -not $taskDefArn -or -not $sgId -or -not $subnetIds) {
    throw "profisee_deploy outputs missing. Ensure profisee_deploy is enabled and apply completed successfully."
  }

  $subnetList = @($subnetIds | ForEach-Object { $_ })
  $sgList = @($sgId)

  $networkConfig = @{
    awsvpcConfiguration = @{
      subnets        = $subnetList
      securityGroups = $sgList
      assignPublicIp = "DISABLED"
    }
  } | ConvertTo-Json -Depth 5 -Compress

  $networkConfigFile = New-TemporaryFile
  try {
    # Write without BOM; AWS CLI chokes on BOM for JSON inputs
    [System.IO.File]::WriteAllText($networkConfigFile, $networkConfig, (New-Object System.Text.UTF8Encoding($false)))
    $networkConfigUri = Get-FileUri $networkConfigFile
  } catch {
    Remove-Item -LiteralPath $networkConfigFile -ErrorAction SilentlyContinue
    throw "Failed to create network configuration file for profisee_deploy task."
  }

  Write-Host "Starting profisee_deploy Fargate task..."
  $taskArn = aws ecs run-task `
    --cluster $clusterArn `
    --launch-type FARGATE `
    --task-definition $taskDefArn `
    --network-configuration $networkConfigUri `
    --region $region `
    --query "tasks[0].taskArn" --output text
  Remove-Item -LiteralPath $networkConfigFile -ErrorAction SilentlyContinue

  if ($LASTEXITCODE -ne 0 -or -not $taskArn -or $taskArn -eq "None") {
    throw "Failed to start profisee_deploy task."
  }

  Write-Host ("profisee_deploy task started: {0}" -f $taskArn)

  $maxWaitMinutes = 20
  $elapsed = 0
  $sleepSeconds = 10
  while ($true) {
    $desc = aws ecs describe-tasks --cluster $clusterArn --tasks $taskArn --region $region | ConvertFrom-Json
    $task = $desc.tasks | Select-Object -First 1
    if ($task -and $task.lastStatus -eq "STOPPED") {
      $exitCode = $task.containers[0].exitCode
      if ($exitCode -ne 0) {
        throw "profisee_deploy task failed (exit code $exitCode). Check CloudWatch logs: /aws/ecs/$($cfg.eks.cluster_name)-profisee-deploy"
      }
      Write-Host "profisee_deploy task completed."
      $profiseeDeployTaskSucceeded = $true
      break
    }

    Start-Sleep -Seconds $sleepSeconds
    $elapsed += $sleepSeconds
    if ($elapsed -ge ($maxWaitMinutes * 60)) {
      Write-Host "profisee_deploy task still running. Check status in ECS console."
      break
    }
  }
} else {
  # Keep legacy safety: if task is disabled, allow edge wiring to continue.
  $profiseeDeployTaskSucceeded = $true
}

# ---------------------------------------------------------------------------
# Auto-wire CloudFront origin (NGINX OSS ingress NLB) and apply edge resources
# ---------------------------------------------------------------------------
$cloudfrontCfg = Get-PropValue $cfg "cloudfront"
$cloudfrontEnabled = Get-PropValue $cloudfrontCfg "enabled"
if ($cloudfrontEnabled -eq $true) {
  if (-not $profiseeDeployTaskSucceeded) {
    Write-Host "CloudFront wiring skipped (profisee_deploy task did not complete successfully yet)."
    return
  }
  $settingsBucketCfg = Get-PropValue $cfg "settings_bucket"
  $settingsBucketName = Get-PropValue $settingsBucketCfg "name"
  $clusterCfg = Get-PropValue $cfg "eks"
  $clusterName = Get-PropValue $clusterCfg "cluster_name"
  $regionForPlatformOut = Get-PropValue $cfg "region"
  if (-not $regionForPlatformOut -or $regionForPlatformOut -eq "") { $regionForPlatformOut = "us-east-1" }
  $platformOut = $null

  $localPlatformOutPath = Join-Path $deploymentPath "outputs\platform.json"
  $platformOut = Read-JsonFileOrNull $localPlatformOutPath

  if (-not $platformOut -and $settingsBucketName -and $clusterName) {
    $platformKey = "outputs/$clusterName/platform.json"
    $tmpPlatformPath = New-TemporaryFile
    try {
      & aws s3 cp ("s3://{0}/{1}" -f $settingsBucketName, $platformKey) $tmpPlatformPath --region $regionForPlatformOut | Out-Null
      if ($LASTEXITCODE -eq 0) {
        $platformOut = Read-JsonFileOrNull $tmpPlatformPath
      }
    } finally {
      Remove-Item -LiteralPath $tmpPlatformPath -ErrorAction SilentlyContinue
    }
  }

  $nlbDns = Get-PropValue $platformOut "nginx_oss_nlb_dns"
  if (-not $nlbDns -or $nlbDns -eq "") {
    Write-Host "CloudFront wiring skipped (NGINX OSS ingress NLB DNS not found yet)."
  } else {
    $edgeConfigChanged = $false
    $currentOrigin = Get-PropValue $cloudfrontCfg "origin_domain_name"
    if (-not $currentOrigin -or $currentOrigin -eq "" -or $currentOrigin -ne $nlbDns) {
      $cfg.cloudfront.origin_domain_name = $nlbDns
      $edgeConfigChanged = $true
      Write-Host ("CloudFront origin set to NGINX OSS ingress NLB: {0}" -f $nlbDns)
    }

    $aliasesValue = Get-PropValue $cloudfrontCfg "aliases"
    $currentAliases = Normalize-CloudFrontAliases $aliasesValue
    $route53Cfg = Get-PropValue $cfg "route53"
    $recordName = Get-PropValue $route53Cfg "record_name"
    $fallbackAliases = Normalize-CloudFrontAliases @($recordName)
    if ($currentAliases.Count -eq 0 -and $fallbackAliases.Count -gt 0) {
      $currentAliases = $fallbackAliases
      Write-Host ("CloudFront aliases defaulted to Route53 record: {0}" -f ($fallbackAliases -join ", "))
    }

    $existingAliasesForCompare = @($aliasesValue | ForEach-Object { $_.ToString().Trim().ToLower().Trim(".") } | Where-Object { $_ -ne "" })
    if (($currentAliases -join ",") -ne ($existingAliasesForCompare -join ",")) {
      $cfg.cloudfront.aliases = $currentAliases
      $edgeConfigChanged = $true
      Write-Host ("CloudFront aliases normalized: {0}" -f ($currentAliases -join ", "))
    }

    if ($edgeConfigChanged) {
      [System.IO.File]::WriteAllText($varFile, ($cfg | ConvertTo-Json -Depth 10), (New-Object System.Text.UTF8Encoding($false)))
      Write-Host ("Updated CloudFront config in {0}" -f $varFile)

      Push-Location $infraRoot
      try {
        tofu init "-backend-config=$backendConfig"

        $edgeApplyArgs = @("apply", "-var-file=$varFile")
        if ($ExtraVarFile) {
          $edgeApplyArgs += "-var-file=$ExtraVarFile"
        }
        if ($AutoApprove) {
          $edgeApplyArgs += "-auto-approve"
        }

        Write-Host "Applying CloudFront/Route53 changes..."
        tofu @edgeApplyArgs
        if ($LASTEXITCODE -ne 0) {
          throw "OpenTofu edge apply failed (exit code $LASTEXITCODE)."
        }
      } finally {
        Pop-Location
      }
    } else {
      Write-Host "CloudFront already wired; skipping edge apply."
    }
  }
} else {
  Write-Host "CloudFront disabled in config; skipping edge wiring/apply."
}

