param(
  [Parameter(Mandatory = $true)]
  [string]$DeploymentName,

  [string]$RepoRoot,
  [string]$Region,
  [string]$Prefix,
  [string]$Profile,
  [switch]$UpdateConfig,
  [string]$LogPath,
  [switch]$VerboseLog
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Get-Command aws -ErrorAction SilentlyContinue)) {
  throw "AWS CLI (aws) is not on PATH. Install AWS CLI and try again."
}

$script:LogPath = $null
$script:VerboseLog = $false
$script:LastAwsExitCode = $null

function Write-LogFile([string]$Message) {
  if (-not $script:LogPath) { return }
  $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
  $line = ("{0} {1}" -f $ts, $Message)
  try {
    [System.IO.File]::AppendAllText($script:LogPath, $line + [System.Environment]::NewLine)
  } catch {
    Write-Host ("Log write failed: {0}" -f $_.Exception.Message)
  }
}

function Write-LogVerbose([string]$Message) {
  if ($script:VerboseLog) { Write-LogFile $Message }
}

function Format-AwsArgsForLog([string[]]$CliArgs) {
  $redactNext = $false
  $out = @()
  foreach ($a in $CliArgs) {
    if ($redactNext) {
      $out += "<REDACTED>"
      $redactNext = $false
      continue
    }
    if ($a -in @("--secret-string","--secret-binary","--cli-input-json","--password","--secret-access-key")) {
      $out += $a
      $redactNext = $true
      continue
    }
    $out += $a
  }
  return ($out -join " ")
}

function Join-AwsArgsForProcess([string[]]$CliArgs) {
  $quoted = foreach ($a in $CliArgs) {
    if ($null -eq $a) { "" }
    elseif ($a -match '[\s"]') { '"' + ($a -replace '"', '\"') + '"' }
    else { $a }
  }
  return ($quoted -join " ")
}

function Normalize-AwsArgs([object[]]$CliArgs) {
  $flat = @()
  foreach ($a in $CliArgs) {
    if ($null -eq $a) { continue }
    if ($a -is [System.Array]) { $flat += $a }
    else { $flat += $a }
  }
  return $flat
}

function Invoke-AwsCliProcessCapture([string[]]$CliArgs) {
  $outFile = New-TemporaryFile
  $errFile = New-TemporaryFile
  $flatArgs = Normalize-AwsArgs ($CliArgs + $script:AwsProfileArgs)
  $argString = Join-AwsArgsForProcess $flatArgs
  if ([string]::IsNullOrWhiteSpace($argString)) {
    Remove-Item -LiteralPath $outFile, $errFile -ErrorAction SilentlyContinue
    return @{
      Exit = 1
      Out  = ""
      Err  = "Argument list empty"
      Args = $argString
    }
  }
  try {
    $proc = Start-Process -FilePath "aws" -ArgumentList $argString -NoNewWindow -PassThru -Wait `
      -RedirectStandardOutput $outFile -RedirectStandardError $errFile
  } catch {
    Remove-Item -LiteralPath $outFile, $errFile -ErrorAction SilentlyContinue
    return @{
      Exit = 1
      Out  = ""
      Err  = $_.Exception.Message
      Args = $argString
    }
  }
  $out = ""
  $err = ""
  try { $out = Get-Content -Raw -Path $outFile } catch {}
  try { $err = Get-Content -Raw -Path $errFile } catch {}
  Remove-Item -LiteralPath $outFile, $errFile -ErrorAction SilentlyContinue
  return @{
    Exit = $proc.ExitCode
    Out  = ($out | Out-String).Trim()
    Err  = ($err | Out-String).Trim()
    Args = $argString
  }
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

function Ensure-ObjectProperty($obj, [string]$Name, $DefaultValue) {
  $prop = $obj.PSObject.Properties[$Name]
  if ($null -eq $prop) {
    $obj | Add-Member -Force -NotePropertyName $Name -NotePropertyValue $DefaultValue
    return $obj.PSObject.Properties[$Name].Value
  }
  $val = $prop.Value
  $isObject = ($val -is [pscustomobject]) -or ($val -is [System.Collections.IDictionary])
  if ($null -eq $val -or -not $isObject) {
    $obj | Add-Member -Force -NotePropertyName $Name -NotePropertyValue $DefaultValue
    return $obj.PSObject.Properties[$Name].Value
  }
  return $val
}

function Set-ObjectProperty($obj, [string]$Name, $Value) {
  if ($obj -is [System.Collections.IDictionary]) {
    $obj[$Name] = $Value
    return
  }
  $prop = $obj.PSObject.Properties[$Name]
  if ($null -eq $prop) {
    $obj | Add-Member -Force -NotePropertyName $Name -NotePropertyValue $Value
  } else {
    $prop.Value = $Value
  }
}

function Get-FileUri([string]$Path) {
  $full = [System.IO.Path]::GetFullPath($Path)
  if ($full -match '^[A-Za-z]:\\') {
    $normalized = $full -replace '\\','/'
    return "file://$normalized"
  }
  return "file://$full"
}

function Invoke-AwsCliNoThrow([string[]]$CliArgs) {
  if ($null -eq $CliArgs) {
    Write-LogFile "Invoke-AwsCliNoThrow: Args is null"
  } else {
    $count = ($CliArgs | Measure-Object).Count
    Write-LogVerbose ("Invoke-AwsCliNoThrow: ArgsCount={0}; Args={1}" -f $count, ($CliArgs -join "|"))
  }
  try {
    $result = Invoke-AwsCliProcessCapture $CliArgs
    $script:LastAwsExitCode = $result.Exit
    Write-LogFile ("aws {0} (exit {1})" -f (Format-AwsArgsForLog $CliArgs), $result.Exit)
    if ($result.Exit -ne 0 -or $script:VerboseLog) {
      $text = $result.Out
      if ($text -eq "") { $text = $result.Err }
      if ($text -eq "") { $text = "<empty>" }
      Write-LogFile $text
      if ($result.Args -ne "") { Write-LogVerbose ("aws args: {0}" -f $result.Args) }
    }
    if ($result.Out -ne "") { return $result.Out }
    if ($result.Err -ne "") { return $result.Err }
    return $null
  } catch {
    $script:LastAwsExitCode = $LASTEXITCODE
    return $null
  }
}

function Invoke-AwsCliCapture([string[]]$CliArgs) {
  if ($null -eq $CliArgs) {
    Write-LogFile "Invoke-AwsCliCapture: Args is null"
  } else {
    $count = ($CliArgs | Measure-Object).Count
    Write-LogVerbose ("Invoke-AwsCliCapture: ArgsCount={0}; Args={1}" -f $count, ($CliArgs -join "|"))
  }
  try {
    $result = Invoke-AwsCliProcessCapture $CliArgs
    $script:LastAwsExitCode = $result.Exit
    Write-LogFile ("aws {0} (exit {1})" -f (Format-AwsArgsForLog $CliArgs), $result.Exit)
    if ($result.Exit -ne 0 -or $script:VerboseLog) {
      $text = $result.Out
      if ($text -eq "") { $text = $result.Err }
      if ($text -eq "") { $text = "<empty>" }
      Write-LogFile $text
      if ($result.Args -ne "") { Write-LogVerbose ("aws args: {0}" -f $result.Args) }
    }
    $combined = @()
    if ($result.Out -ne "") { $combined += $result.Out }
    if ($result.Err -ne "") { $combined += $result.Err }
    return ($combined -join [System.Environment]::NewLine).Trim()
  } catch {
    $script:LastAwsExitCode = $LASTEXITCODE
    return $_.Exception.Message
  }
}

function Get-SecretArn([string]$SecretName, [string]$Region) {
  $arn = Invoke-AwsCliNoThrow @(
    "secretsmanager","describe-secret",
    "--secret-id",$SecretName,
    "--query","ARN","--output","text",
    "--no-cli-pager",
    "--region",$Region
  )
  if ($script:LastAwsExitCode -eq 0 -and $arn) { return $arn }
  return $null
}

function Put-Secret([string]$SecretName, [string]$SecretValue, [string]$Region) {
  $tempFile = New-TemporaryFile
  try {
    [System.IO.File]::WriteAllText($tempFile, $SecretValue, (New-Object System.Text.UTF8Encoding($false)))
    $fileUri = Get-FileUri $tempFile
  } catch {
    Remove-Item -LiteralPath $tempFile -ErrorAction SilentlyContinue
    throw "Failed to create temp secret file for $SecretName"
  }

  try {
    $createOut = Invoke-AwsCliCapture @("secretsmanager","create-secret","--name",$SecretName,"--secret-string",$fileUri,"--region",$Region,"--query","ARN","--output","text","--no-cli-pager")
    $createExit = $script:LastAwsExitCode
    if ($createExit -eq 0) {
      if ($createOut) { return $createOut }
      $arn = Get-SecretArn $SecretName $Region
      if ($arn) { return $arn }
    }

    $putOut = Invoke-AwsCliCapture @("secretsmanager","put-secret-value","--secret-id",$SecretName,"--secret-string",$fileUri,"--region",$Region,"--no-cli-pager")
    $putExit = $script:LastAwsExitCode
    if ($putExit -eq 0) {
      $arn = Get-SecretArn $SecretName $Region
      if ($arn) { return $arn }
      return $SecretName
    }

    $msgCreate = if ($createOut) { $createOut } else { "AWS CLI create-secret failed without output (exit $createExit)." }
    $msgPut = if ($putOut) { $putOut } else { "AWS CLI put-secret-value failed without output (exit $putExit)." }
    throw "Failed to create/update secret: $SecretName. Create output: $msgCreate; Put output: $msgPut"
  } finally {
    Remove-Item -LiteralPath $tempFile -ErrorAction SilentlyContinue
  }
}

$resolvedRepoRoot = if ($RepoRoot) { Resolve-Path $RepoRoot } else { Resolve-Path (Join-Path $PSScriptRoot "..") }
$deploymentPath = Join-Path $resolvedRepoRoot "customer-deployments\$DeploymentName"
$configPath = Join-Path $deploymentPath "config.auto.tfvars.json"
$seedPath = Join-Path $deploymentPath "secrets\\seed-secrets.json"

if (-not (Test-Path -LiteralPath $deploymentPath)) {
  throw "Deployment folder not found: $deploymentPath"
}

$logPathResolved = $LogPath
if (-not $logPathResolved -or $logPathResolved -eq "") {
  $logDir = Join-Path $deploymentPath "logs"
  if (-not (Test-Path -LiteralPath $logDir)) {
    New-Item -ItemType Directory -Path $logDir | Out-Null
  }
  $logPathResolved = Join-Path $logDir "seed-secrets.log"
} else {
  $logDir = Split-Path -Parent $logPathResolved
  if ($logDir -and -not (Test-Path -LiteralPath $logDir)) {
    New-Item -ItemType Directory -Path $logDir | Out-Null
  }
}
$script:LogPath = $logPathResolved
if ($VerboseLog.IsPresent) { $script:VerboseLog = $true }
try {
  # Overwrite log each run
  Set-Content -Path $script:LogPath -Value "" -Encoding UTF8
} catch {
  Write-Host ("Log init failed: {0}" -f $_.Exception.Message)
}
Write-Host ("Logging to: {0}" -f $script:LogPath)
Write-LogFile "---- seed-secrets start ----"
Write-LogFile ("Log path resolved: {0}" -f $script:LogPath)
Write-LogVerbose ("PWD: {0}" -f (Get-Location))
Write-LogVerbose ("Env AWS_PROFILE: {0}" -f $env:AWS_PROFILE)
Write-LogVerbose ("Env AWS_DEFAULT_PROFILE: {0}" -f $env:AWS_DEFAULT_PROFILE)
Write-LogVerbose ("Env AWS_SDK_LOAD_CONFIG: {0}" -f $env:AWS_SDK_LOAD_CONFIG)
Write-LogVerbose ("Env AWS_CONFIG_FILE: {0}" -f $env:AWS_CONFIG_FILE)
Write-LogVerbose ("Env AWS_SHARED_CREDENTIALS_FILE: {0}" -f $env:AWS_SHARED_CREDENTIALS_FILE)
try {
  $awsCmd = Get-Command aws -ErrorAction Stop
  Write-LogVerbose ("aws path: {0}" -f $awsCmd.Source)
} catch {
  Write-LogVerbose ("aws path: <not found>")
}
try {
  $ver = & aws --version 2>&1
  Write-LogVerbose ("aws --version: {0}" -f ($ver | Out-String).Trim())
} catch {
  Write-LogVerbose ("aws --version failed: {0}" -f $_.Exception.Message)
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
Write-LogFile ("Region: {0}; Prefix: {1}" -f $Region, $Prefix)

$script:AwsProfileArgs = @()
if (-not $Profile -or $Profile -eq "") {
  if ($env:AWS_PROFILE) { $Profile = $env:AWS_PROFILE }
  elseif ($env:AWS_DEFAULT_PROFILE) { $Profile = $env:AWS_DEFAULT_PROFILE }
}
if ($Profile -and $Profile -ne "") {
  $script:AwsProfileArgs = @("--profile", $Profile)
  Write-Host ("Using AWS CLI profile: {0}" -f $Profile)
  Write-LogFile ("Using AWS CLI profile: {0}" -f $Profile)
}

$identity = Invoke-AwsCliCapture @("sts","get-caller-identity","--no-cli-pager","--region",$Region)
Write-LogFile ("sts get-caller-identity output: {0}" -f $identity)
Write-LogFile ("sts get-caller-identity exit: {0}; output length: {1}" -f $script:LastAwsExitCode, ($identity | Measure-Object -Character).Characters)
if ($script:LastAwsExitCode -ne 0) {
  $profileNote = if ($Profile) { " (profile: $Profile)" } else { "" }
  Write-Host ("AWS CLI auth failed. See log: {0}" -f $script:LogPath)
  throw "AWS CLI authentication failed$profileNote. Output: $identity"
}

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

# TLS cert/key (manual) - driven by seed file, no extra prompt
$certPath = if ($seed -and $seed.tls.cert_path) { $seed.tls.cert_path } else { $null }
$keyPath = if ($seed -and $seed.tls.key_path) { $seed.tls.key_path } else { $null }
if ($certPath -and $keyPath) {
  if ((Test-Path -LiteralPath $certPath) -and (Test-Path -LiteralPath $keyPath)) {
    $tlsPayload = @{
      cert = Get-Content -Raw -Path $certPath
      key  = Get-Content -Raw -Path $keyPath
    } | ConvertTo-Json -Depth 4
    $secretName = "$Prefix/tls"
    $secretArns.tls = Put-Secret $secretName $tlsPayload $Region
  } else {
    Write-Host "TLS cert/key not found at provided paths; skipping TLS secret."
  }
}

# App SQL credentials (required for DB init when enabled)
$dbInitEnabled = $false
if ($cfg -and $cfg.db_init) {
  $dbInitEnabled = [bool]$cfg.db_init.enabled
}

if ($dbInitEnabled) {
  $sqlUser = if ($seed -and $seed.sql.username) { $seed.sql.username } else { Read-Value "App SQL username" "" }
  $sqlPass = if ($seed -and $seed.sql.password) { $seed.sql.password } else { Read-SecretValue "App SQL password" }
  if (-not $sqlUser -or -not $sqlPass) {
    throw "App SQL username/password are required when db_init.enabled is true."
  }
  $sqlPayload = @{ username = $sqlUser; password = $sqlPass } | ConvertTo-Json -Depth 4
  $secretName = "$Prefix/sql"
  $secretArns.sql = Put-Secret $secretName $sqlPayload $Region
} else {
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
}

if ($UpdateConfig -and $cfg) {
  $platform = Ensure-ObjectProperty $cfg "platform_deployer" ([pscustomobject]@{})
  Set-ObjectProperty $platform "secret_arns" $secretArns
  $dbInitCfg = Ensure-ObjectProperty $cfg "db_init" ([pscustomobject]@{})
  Set-ObjectProperty $dbInitCfg "secret_arns" $secretArns
  $jsonOut = $cfg | ConvertTo-Json -Depth 10
  [System.IO.File]::WriteAllText($configPath, $jsonOut, (New-Object System.Text.UTF8Encoding($false)))
  Write-Host ("Updated config with secret ARNs: {0}" -f $configPath)
}

Write-Host "Secrets seeded."
