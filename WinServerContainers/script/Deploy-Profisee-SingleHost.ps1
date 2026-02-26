# Deploy-Profisee-SingleHost.ps1
#requires -RunAsAdministrator
[CmdletBinding()]
param(
  # Base name. Script auto-allocates next available suffix: <base>-0, <base>-1, ...
  [string]$ContainerName = "profisee",
  [ValidateSet("hyperv")] [string]$Isolation = "hyperv",
  [string]$DockerNamespace = "profisee",

  # Container port assumption: Profisee serves HTTP on 80 in-container.
  [int]$HostAppPort = 18080,

  [string]$NginxRoot = "C:\nginx",
  [string]$WorkDir = "C:\ProfiseeDeploy",

  [string]$NginxConfUrl = "https://raw.githubusercontent.com/Profiseeadmin/kubernetes/refs/heads/master/WinServerContainers/nginx-config/nginx.conf",
  [string]$ForensicsScriptUrl = "https://raw.githubusercontent.com/Profisee/kubernetes/refs/heads/master/Azure-ARM/forensics_log_pull.ps1"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$script:CustomerInputStatePath = $null
$script:LastContainerCliOutputText = ""
$script:DeployScriptVersion = "2026-02-26.09"

function Ensure-Dir([string]$p){ if(-not(Test-Path $p)){ New-Item -ItemType Directory -Path $p | Out-Null } }
function SecureToPlain([Security.SecureString]$s){
  $b=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)
  try{[Runtime.InteropServices.Marshal]::PtrToStringAuto($b)} finally{[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b)}
}
function New-CustomerInputState {
  return [pscustomobject]@{
    Inputs = @{}
    Secrets = @{}
  }
}
function Load-CustomerInputState([string]$path){
  if(-not(Test-Path $path)){ return New-CustomerInputState }
  try {
    $loaded = Import-Clixml -Path $path
    if($null -eq $loaded){ return New-CustomerInputState }

    $state = New-CustomerInputState
    if($loaded.PSObject.Properties.Name -contains "Inputs" -and $loaded.Inputs){
      if($loaded.Inputs -is [hashtable]){
        foreach($k in $loaded.Inputs.Keys){ $state.Inputs[$k] = [string]$loaded.Inputs[$k] }
      } else {
        foreach($p in $loaded.Inputs.PSObject.Properties){ $state.Inputs[$p.Name] = [string]$p.Value }
      }
    }
    if($loaded.PSObject.Properties.Name -contains "Secrets" -and $loaded.Secrets){
      if($loaded.Secrets -is [hashtable]){
        foreach($k in $loaded.Secrets.Keys){ $state.Secrets[$k] = $loaded.Secrets[$k] }
      } else {
        foreach($p in $loaded.Secrets.PSObject.Properties){ $state.Secrets[$p.Name] = $p.Value }
      }
    }
    return $state
  } catch {
    Write-Warning "Could not load prior customer input state from $path. Starting fresh. Error: $($_.Exception.Message)"
    return New-CustomerInputState
  }
}
function Save-CustomerInputState([object]$state,[string]$path){
  Ensure-Dir (Split-Path $path -Parent)
  Export-Clixml -InputObject $state -Path $path -Force
}
function Persist-CustomerInputState([object]$state){
  if([string]::IsNullOrWhiteSpace($script:CustomerInputStatePath)){ return }
  try {
    Save-CustomerInputState -state $state -path $script:CustomerInputStatePath
  } catch {
    Write-Warning "Could not persist customer input state to $script:CustomerInputStatePath. Error: $($_.Exception.Message)"
  }
}
function Get-StateInput([object]$state,[string]$key){
  if($state -and $state.Inputs -and $state.Inputs.ContainsKey($key)){ return [string]$state.Inputs[$key] }
  return $null
}
function Get-StateSecret([object]$state,[string]$key){
  if(-not($state -and $state.Secrets -and $state.Secrets.ContainsKey($key))){ return $null }
  $v = $state.Secrets[$key]
  if($null -eq $v){ return $null }
  if($v -is [Security.SecureString]){ return SecureToPlain $v }
  return [string]$v
}
function Set-StateInput([object]$state,[string]$key,[string]$value){
  $state.Inputs[$key] = $value
}
function Set-StateSecret([object]$state,[string]$key,[string]$value){
  if([string]::IsNullOrWhiteSpace($value)){
    if($state.Secrets.ContainsKey($key)){ $state.Secrets.Remove($key) | Out-Null }
    return
  }
  $state.Secrets[$key] = ConvertTo-SecureString $value -AsPlainText -Force
}
function Mask-SecretPreview([string]$value){
  if([string]::IsNullOrWhiteSpace($value)){ return "" }
  $prefixLen = [Math]::Min(3,$value.Length)
  $prefix = $value.Substring(0,$prefixLen)
  $maskLen = [Math]::Max(0,$value.Length - $prefixLen)
  return ($prefix + ("*" * $maskLen))
}
function Read-PromptWithGreenDefault([string]$label,[string]$defaultText){
  if(-not [string]::IsNullOrWhiteSpace($defaultText)){
    Write-Host ("{0} [" -f $label) -NoNewline
    Write-Host $defaultText -NoNewline -ForegroundColor Green
    Write-Host "]:" -NoNewline
    return Read-Host
  }
  return Read-Host ("{0}:" -f $label)
}
function Read-SecretPromptWithGreenDefault([string]$label,[string]$defaultText){
  if(-not [string]::IsNullOrWhiteSpace($defaultText)){
    Write-Host ("{0} [" -f $label) -NoNewline
    Write-Host $defaultText -NoNewline -ForegroundColor Green
    Write-Host "]:" -NoNewline
  } else {
    Write-Host ("{0}:" -f $label) -NoNewline
  }
  return SecureToPlain (Read-Host -AsSecureString)
}
function Read-WithHistory(
  [object]$state,
  [string]$key,
  [string]$prompt,
  [string]$defaultValue = "",
  [switch]$Required,
  [switch]$SensitiveDisplay
){
  $previous = Get-StateInput $state $key

  $effectiveDefault = $defaultValue
  if(-not [string]::IsNullOrWhiteSpace($previous)){ $effectiveDefault = $previous }

  while($true){
    $defaultForDisplay = if($SensitiveDisplay){ Mask-SecretPreview $effectiveDefault } else { $effectiveDefault }
    $entered = Read-PromptWithGreenDefault -label $prompt -defaultText $defaultForDisplay

    if([string]::IsNullOrWhiteSpace($entered)){ $value = $effectiveDefault } else { $value = $entered }
    if($Required -and [string]::IsNullOrWhiteSpace($value)){ continue }

    Set-StateInput -state $state -key $key -value $value
    Persist-CustomerInputState -state $state
    return $value
  }
}
function Read-SecretWithHistory(
  [object]$state,
  [string]$key,
  [string]$prompt,
  [switch]$Required
){
  $previous = Get-StateSecret $state $key

  while($true){
    $entered = Read-SecretPromptWithGreenDefault -label $prompt -defaultText (Mask-SecretPreview $previous)

    if([string]::IsNullOrWhiteSpace($entered)){ $value = $previous } else { $value = $entered }
    if($Required -and [string]::IsNullOrWhiteSpace($value)){ continue }

    Set-StateSecret -state $state -key $key -value $value
    Persist-CustomerInputState -state $state
    return $value
  }
}
function Parse-SemVer([string]$value){
  if([string]::IsNullOrWhiteSpace($value)){ return $null }
  $m = [regex]::Match($value,'(\d+\.\d+\.\d+)')
  if(-not $m.Success){ return $null }
  try { return [version]$m.Groups[1].Value } catch { return $null }
}
function Is-SameOrNewer([string]$installed,[string]$latest){
  $installedVer = Parse-SemVer $installed
  $latestVer = Parse-SemVer $latest
  if($null -eq $installedVer -or $null -eq $latestVer){ return $false }
  return $installedVer -ge $latestVer
}
function Ensure-PathContains([string[]]$entries){
  $mp = [Environment]::GetEnvironmentVariable("Path","Machine")
  foreach($p in $entries){
    if($mp -notlike "*$p*"){ $mp = "$mp;$p" }
  }
  [Environment]::SetEnvironmentVariable("Path",$mp,"Machine")
  $env:Path = [Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [Environment]::GetEnvironmentVariable("Path","User")
}
function Install-ContainersFeature {
  Import-Module ServerManager -ErrorAction SilentlyContinue | Out-Null
  $feat = Get-WindowsFeature -Name Containers -ErrorAction SilentlyContinue
  if(-not $feat){
    throw "Unable to query Windows feature state for 'Containers'."
  }
  if(-not $feat.Installed){
    throw "Install Windows feature: Containers (Install-WindowsFeature Containers) and rerun."
  }
}
function Ensure-HyperVRole {
  Import-Module ServerManager -ErrorAction SilentlyContinue | Out-Null
  $hyperV = Get-WindowsFeature -Name Hyper-V -ErrorAction SilentlyContinue
  if(-not $hyperV){
    throw "Unable to query Hyper-V feature state on this server."
  }
  if(-not $hyperV.Installed){
    throw "Install Windows feature: Hyper-V (Install-WindowsFeature Hyper-V -IncludeManagementTools) and rerun."
  }
  Write-Host "Hyper-V role is installed."
}
function Ensure-DockerService([switch]$ForceRestart){
  $dockerdExe = "$env:ProgramFiles\Docker\dockerd.exe"
  if(-not(Test-Path $dockerdExe)){
    try {
      $cmd = Get-Command dockerd -ErrorAction SilentlyContinue
      if($cmd){ $dockerdExe = $cmd.Source }
    } catch {}
  }
  if(-not(Test-Path $dockerdExe)){ throw "dockerd.exe not found at $dockerdExe" }

  $svc = Get-Service -Name "docker" -ErrorAction SilentlyContinue
  if(-not $svc){
    & $dockerdExe --register-service | Out-Null
    $svc = Get-Service -Name "docker" -ErrorAction SilentlyContinue
  }
  if(-not $svc){ throw "docker service could not be registered." }

  try { Set-Service -Name docker -StartupType Automatic } catch {}
  if($ForceRestart){
    if($svc.Status -eq "Running"){
      Restart-Service docker -Force
    } else {
      Start-Service docker
    }
    return
  }
  if($svc.Status -ne "Running"){ Start-Service docker }
}
function Install-DockerEngineLatest {
  Ensure-Dir $WorkDir
  $installScriptUrl = "https://raw.githubusercontent.com/microsoft/Windows-Containers/Main/helpful_tools/Install-DockerCE/install-docker-ce.ps1"
  $installScriptPath = Join-Path $WorkDir "install-docker-ce.ps1"
  $windowsPowerShell = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"

  Write-Host "Installing/updating Docker using Microsoft Windows-Containers installer script."
  Invoke-WebRequest -UseBasicParsing -Uri $installScriptUrl -OutFile $installScriptPath
  if(-not (Test-Path -LiteralPath $installScriptPath)){
    throw "Failed to download Docker install script from $installScriptUrl"
  }
  try { Unblock-File -LiteralPath $installScriptPath -ErrorAction SilentlyContinue } catch {}

  if(Test-Path -LiteralPath $windowsPowerShell){
    & $windowsPowerShell -NoProfile -ExecutionPolicy Bypass -File $installScriptPath
    if($LASTEXITCODE -ne 0){
      throw "Microsoft install-docker-ce.ps1 failed with exit code $LASTEXITCODE."
    }
  } else {
    & $installScriptPath
    if($LASTEXITCODE -ne 0){
      throw "Microsoft install-docker-ce.ps1 failed with exit code $LASTEXITCODE."
    }
  }

  Ensure-PathContains @("$env:ProgramFiles\Docker")
  Ensure-DockerService
}

function Download-NginxConfTemplate {
  Ensure-Dir $WorkDir
  Ensure-Dir "$NginxRoot\conf"
  Ensure-Dir "$NginxRoot\logs"

  $dst = Join-Path $NginxRoot "conf\nginx.conf"
  Invoke-WebRequest -Uri $NginxConfUrl -OutFile $dst
  if(-not (Test-Path -LiteralPath $dst)){ throw "Downloaded nginx.conf not found at: $dst" }
  $conf = Get-Content -Raw -Path $dst
  if([string]::IsNullOrWhiteSpace($conf)){ throw "Downloaded nginx.conf is empty from: $NginxConfUrl" }
  Write-Host "Downloaded nginx.conf to $dst from $NginxConfUrl"
}

function Get-NginxStableVersion {
  $dl = Invoke-WebRequest -Uri "https://nginx.org/en/download.html" -UseBasicParsing
  $html = $dl.Content
  if($html -match 'Stable version.*?nginx/Windows-(\d+\.\d+\.\d+)'){ return $Matches[1] }
  # fallback: first Windows version on page
  if($html -match 'nginx/Windows-(\d+\.\d+\.\d+)'){ return $Matches[1] }
  throw "Could not parse nginx stable version from nginx.org."
}
function Get-NginxLocalVersion {
  $exe = "$NginxRoot\nginx.exe"
  if(-not(Test-Path $exe)){ return $null }
  try{
    $txt = (& $exe -v 2>&1 | Out-String)
    $m = [regex]::Match($txt,'nginx/(\d+\.\d+\.\d+)')
    if($m.Success){ return $m.Groups[1].Value }
  } catch {}
  return $null
}

function Install-NginxStable {
  $latestVer = Get-NginxStableVersion
  $localVer = Get-NginxLocalVersion
  if(Is-SameOrNewer $localVer $latestVer){
    Write-Host "nginx local version $localVer is current (latest $latestVer). Skipping install."
    Ensure-Dir "$NginxRoot\conf\certs"
    Ensure-Dir "$NginxRoot\logs"
    return
  }

  Write-Host "Updating nginx from '$localVer' to '$latestVer'"
  $zip = Join-Path $WorkDir "nginx-$latestVer.zip"
  Invoke-WebRequest -Uri "https://nginx.org/download/nginx-$latestVer.zip" -OutFile $zip

  try { & "$NginxRoot\nginx.exe" -s stop 2>$null | Out-Null } catch {}
  if(Test-Path $NginxRoot){ Remove-Item $NginxRoot -Recurse -Force }
  Expand-Archive -Path $zip -DestinationPath (Split-Path $NginxRoot -Parent) -Force
  Move-Item -Path (Join-Path (Split-Path $NginxRoot -Parent) "nginx-$latestVer") -Destination $NginxRoot -Force
  Ensure-Dir "$NginxRoot\conf\certs"
  Ensure-Dir "$NginxRoot\logs"
}

function Assert-PemFile([string]$path,[string]$kind){
  if([string]::IsNullOrWhiteSpace($path)){ throw "$kind PEM path is required. Refusing to proceed." }
  if(-not(Test-Path $path)){ throw "$kind PEM not found at: $path" }
  $txt = (Get-Content -Raw -Path $path).Trim()
  if($kind -eq "Certificate"){
    if($txt -notmatch "BEGIN CERTIFICATE"){ throw "Certificate file does not look like PEM (missing BEGIN CERTIFICATE): $path" }
  } else {
    if($txt -notmatch "BEGIN .*PRIVATE KEY"){ throw "Key file does not look like PEM (missing BEGIN *PRIVATE KEY): $path" }
  }
}

function Start-Nginx {
  $exe = "$NginxRoot\nginx.exe"
  if(-not(Test-Path $exe)){ throw "nginx executable not found at: $exe" }

  $prefix = "$NginxRoot\"
  $confPath = Join-Path $NginxRoot "conf\nginx.conf"
  if(-not(Test-Path $confPath)){ throw "nginx config file not found at: $confPath" }
  Ensure-Dir "$NginxRoot\logs"

  & $exe -t -p $prefix -c "conf/nginx.conf" | Out-Null
  if($LASTEXITCODE -ne 0){ throw "nginx configuration test failed (prefix: $prefix, config: conf/nginx.conf)." }

  try {
    if(-not(Get-NetFirewallRule -DisplayName "NGINX HTTP" -ErrorAction SilentlyContinue)){
      New-NetFirewallRule -DisplayName "NGINX HTTP" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 80 | Out-Null
    }
    if(-not(Get-NetFirewallRule -DisplayName "NGINX HTTPS" -ErrorAction SilentlyContinue)){
      New-NetFirewallRule -DisplayName "NGINX HTTPS" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 443 | Out-Null
    }
  } catch {}

  $running = @(Get-Process -Name "nginx" -ErrorAction SilentlyContinue).Count -gt 0
  if($running){
    Write-Host "nginx is already running. Reloading configuration."
    & $exe -s reload -p $prefix 2>&1 | Out-Null
    if($LASTEXITCODE -ne 0){
      Write-Warning "nginx reload failed. Attempting restart."
      & $exe -s stop -p $prefix 2>$null | Out-Null
      Start-Process -FilePath $exe -WorkingDirectory $NginxRoot -ArgumentList @("-p",$prefix,"-c","conf/nginx.conf") | Out-Null
    }
  } else {
    Write-Host "nginx is not running. Starting nginx."
    Start-Process -FilePath $exe -WorkingDirectory $NginxRoot -ArgumentList @("-p",$prefix,"-c","conf/nginx.conf") | Out-Null
  }
}

function DockerCli([string[]]$commandArgs){
  $script:LastContainerCliOutputText = ""
  $dockerLines = @()
  & docker @commandArgs 2>&1 | Tee-Object -Variable dockerLines | Out-Host
  if($dockerLines){
    $script:LastContainerCliOutputText = (($dockerLines | ForEach-Object { [string]$_ }) -join "`n")
  }
  if($LASTEXITCODE -ne 0){
    $subcommand = if($commandArgs.Count -gt 0){ $commandArgs[0] } else { "<unknown>" }
    throw "docker command failed (subcommand: $subcommand, exit code: $LASTEXITCODE)."
  }
}
function Login-Acr([string]$registry,[string]$user,[string]$password){
  $tmpPass = Join-Path $WorkDir "acrpass.txt"
  try {
    Set-Content -Path $tmpPass -Value $password -Encoding ascii -Force
    Get-Content $tmpPass | & docker login $registry -u $user --password-stdin
    if($LASTEXITCODE -ne 0){ throw "docker login failed for $registry (exit code $LASTEXITCODE)." }
  } finally {
    if(Test-Path $tmpPass){ Remove-Item $tmpPass -Force }
  }
}
function Normalize-MemoryLimit([string]$value){
  if([string]::IsNullOrWhiteSpace($value)){ return $value }
  $trimmed = $value.Trim()
  if($trimmed -match '^\d+$'){
    Write-Warning "Memory limit '$trimmed' has no unit; interpreting as '${trimmed}G'."
    return "$trimmed`G"
  }
  return $trimmed
}
function Is-ContainerCliNotImplemented([string]$text){
  if([string]::IsNullOrWhiteSpace($text)){ return $false }
  return ($text -match '(?i)\bnot implemented\b')
}
function Is-ContainerCliRecoverableNetworkBug([string]$text){
  if([string]::IsNullOrWhiteSpace($text)){ return $false }
  if($text -match '(?i)panic:\s*runtime error:\s*index out of range'){ return $true }
  if($text -match '(?i)verifyNetworkTypes'){ return $true }
  if($text -match '(?i)netutil_windows\.go'){ return $true }
  return $false
}
function Get-EntraTenantIdFromAuthority([string]$value){
  if([string]::IsNullOrWhiteSpace($value)){ return "" }
  $trimmed = $value.Trim()

  try {
    $uri = [Uri]$trimmed
    if($uri.Host -ieq "login.microsoftonline.com"){
      $segments = $uri.AbsolutePath.Trim('/').Split('/')
      if($segments.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($segments[0])){
        return $segments[0]
      }
    }
  } catch {}

  if($trimmed -match '^(?i)https?://login\.microsoftonline\.com/([^/?#]+)'){ return $matches[1] }
  if($trimmed -match '^(?i)login\.microsoftonline\.com/([^/?#]+)'){ return $matches[1] }
  if($trimmed -notmatch '^(?i)https?://'){ return $trimmed.TrimEnd('/') }
  return ""
}
function Get-MaskedEntraAuthorityPreview([string]$value){
  if([string]::IsNullOrWhiteSpace($value)){ return "" }
  $tenantId = Get-EntraTenantIdFromAuthority $value
  if([string]::IsNullOrWhiteSpace($tenantId)){ return $value }
  return "https://login.microsoftonline.com/" + (Mask-SecretPreview $tenantId)
}
function Test-Base64String([string]$value){
  if([string]::IsNullOrWhiteSpace($value)){ return $false }
  try {
    [Convert]::FromBase64String($value) | Out-Null
    return $true
  } catch {
    return $false
  }
}
function Stage-RootCaCertificateForContainer([string]$sourcePath,[string]$destinationPath){
  if([string]::IsNullOrWhiteSpace($sourcePath)){ throw "Root CA cert source path is required." }
  if(-not (Test-Path -LiteralPath $sourcePath)){ throw "Root CA cert file not found: $sourcePath" }
  if([string]::IsNullOrWhiteSpace($destinationPath)){ throw "Root CA cert destination path is required." }
  Ensure-Dir (Split-Path -Path $destinationPath -Parent)

  $raw = ""
  try {
    $raw = Get-Content -Raw -LiteralPath $sourcePath -ErrorAction Stop
  } catch {
    $raw = ""
  }

  if(-not [string]::IsNullOrWhiteSpace($raw) -and $raw -match "BEGIN CERTIFICATE"){
    $pemMatch = [regex]::Match(
      $raw,
      "-----BEGIN CERTIFICATE-----(?<body>.*?)-----END CERTIFICATE-----",
      [System.Text.RegularExpressions.RegexOptions]::Singleline
    )
    if($pemMatch.Success){
      try {
        $b64 = ($pemMatch.Groups["body"].Value -replace "\s","")
        $bytes = [Convert]::FromBase64String($b64)
        [IO.File]::WriteAllBytes($destinationPath,$bytes)
        return
      } catch {}
    }
  }

  Copy-Item -LiteralPath $sourcePath -Destination $destinationPath -Force
}
function Get-DockerImageStartupTokens([string]$image){
  if([string]::IsNullOrWhiteSpace($image)){ throw "Image is required to resolve startup command." }
  $inspectLines = @()
  & docker image inspect $image 2>&1 | Tee-Object -Variable inspectLines | Out-Null
  $inspectText = (($inspectLines | ForEach-Object { [string]$_ }) -join "`n")
  if($LASTEXITCODE -ne 0){
    if([string]::IsNullOrWhiteSpace($inspectText)){ $inspectText = "docker image inspect failed for '$image'." }
    throw $inspectText
  }
  if([string]::IsNullOrWhiteSpace($inspectText)){
    throw "docker image inspect returned empty output for '$image'."
  }

  try {
    $inspectObj = $inspectText | ConvertFrom-Json -ErrorAction Stop
  } catch {
    throw "Failed to parse docker image inspect output for '$image'. Error: $($_.Exception.Message)"
  }

  $item = if($inspectObj -is [array]){
    if($inspectObj.Count -gt 0){ $inspectObj[0] } else { $null }
  } else {
    $inspectObj
  }
  if($null -eq $item){ throw "docker image inspect returned no records for '$image'." }

  $tokens = @()
  if($item.PSObject.Properties.Name -contains "Config" -and $item.Config){
    $config = $item.Config
    if($config.PSObject.Properties.Name -contains "Entrypoint" -and $config.Entrypoint){
      foreach($t in @($config.Entrypoint)){
        if($null -ne $t -and -not [string]::IsNullOrWhiteSpace([string]$t)){ $tokens += [string]$t }
      }
    }
    if($config.PSObject.Properties.Name -contains "Cmd" -and $config.Cmd){
      foreach($t in @($config.Cmd)){
        if($null -ne $t -and -not [string]::IsNullOrWhiteSpace([string]$t)){ $tokens += [string]$t }
      }
    }
  }
  return ,$tokens
}
function Get-ContainerBootstrapCommand([string]$startupCommandBase64,[string]$rootCaContainerPath){
  if([string]::IsNullOrWhiteSpace($startupCommandBase64)){ return "" }
  $safeStartupB64 = $startupCommandBase64.Replace("'","''")
  $safeRootPath = if([string]::IsNullOrWhiteSpace($rootCaContainerPath)){ "" } else { $rootCaContainerPath.Replace("'","''") }

  return @"
`$ErrorActionPreference = 'Stop'
`$certPath = '$safeRootPath'
if(-not [string]::IsNullOrWhiteSpace(`$certPath) -and (Test-Path -LiteralPath `$certPath)){
  Import-Certificate -FilePath `$certPath -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
  Write-Host "Imported Root CA cert into LocalMachine\Root from `$certPath."
}
`$startupJson = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('$safeStartupB64'))
`$startupTokens = ConvertFrom-Json -InputObject `$startupJson
if(`$startupTokens -isnot [System.Array]){ `$startupTokens = @(`$startupTokens) }
if(`$startupTokens.Count -lt 1){ throw 'No startup command resolved from image metadata.' }
`$exe = [string]`$startupTokens[0]
`$startupArgs = @()
if(`$startupTokens.Count -gt 1){
  for(`$i = 1; `$i -lt `$startupTokens.Count; `$i++){ `$startupArgs += [string]`$startupTokens[`$i] }
}
& `$exe @startupArgs
"@
}
function Resolve-RepositoryMountSource([string]$repoLocation){
  if([string]::IsNullOrWhiteSpace($repoLocation)){
    throw "ProfiseeAttachmentRepositoryLocation is required."
  }
  $path = $repoLocation.Trim()
  $isUnc = $path.StartsWith("\\")
  $isDrivePath = $path -match '^[A-Za-z]:\\'
  if(-not $isUnc -and -not $isDrivePath){
    throw "ProfiseeAttachmentRepositoryLocation must be an absolute UNC path (\\server\share) or local path (C:\path)."
  }

  if($isDrivePath){
    if(-not (Test-Path -LiteralPath $path)){
      Ensure-Dir $path
    }
  }

  if(-not (Test-Path -LiteralPath $path)){
    throw "Attachment repository host path is not accessible: $path"
  }
  try {
    return (Resolve-Path -LiteralPath $path).Path
  } catch {
    return $path
  }
}
function Download-ForensicsScriptToRepository([string]$repoMountSource){
  if([string]::IsNullOrWhiteSpace($repoMountSource)){
    throw "Repository mount source path is required for forensics script download."
  }
  Ensure-Dir $WorkDir
  $tmp = Join-Path $WorkDir "forensics_log_pull.ps1.download"
  $dst = Join-Path $repoMountSource "forensics_log_pull.ps1"

  Invoke-WebRequest -Uri $ForensicsScriptUrl -OutFile $tmp
  if(-not (Test-Path -LiteralPath $tmp)){
    throw "Failed to download forensics script from $ForensicsScriptUrl"
  }
  Copy-Item -LiteralPath $tmp -Destination $dst -Force
  try { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue } catch {}
  Write-Host "Downloaded forensics_log_pull.ps1 to: $dst"
}
function Build-ContainerRunArgs(
  [string]$name,
  [string]$isolation,
  [string]$dockerNamespace,
  [string]$networkName,
  [int]$hostPort,
  [string]$hostDataDir,
  [string]$repoMountSource,
  [string]$cpuLimit,
  [string]$memoryLimit,
  [hashtable]$envMap,
  [string]$image,
  [string]$startupCommandBase64,
  [string]$rootCaContainerPath,
  [switch]$IncludeResourceLimits,
  [switch]$IncludeIsolation,
  [switch]$IncludeNetwork,
  [switch]$IncludePortMapping,
  [switch]$IncludeBindMount
){
  $args = @(
    "run","-d",
    "--name",$name,
    "--hostname",$name
  )
  if(-not [string]::IsNullOrWhiteSpace($dockerNamespace)){
    $args += @("--label","profisee.namespace=$dockerNamespace")
  }

  if($IncludeIsolation -and -not [string]::IsNullOrWhiteSpace($isolation)){
    $args += @("--isolation",$isolation)
  }
  if($IncludeNetwork -and -not [string]::IsNullOrWhiteSpace($networkName)){
    $args += @("--network",$networkName)
  }
  if($IncludePortMapping){
    $args += @("-p","$hostPort`:80")
  }
  if($IncludeBindMount){
    $args += @("--mount","type=bind,source=$hostDataDir,destination=c:\data")
    $args += @("--mount","type=bind,source=$repoMountSource,destination=c:\fileshare")
  }

  if($IncludeResourceLimits){
    if(-not [string]::IsNullOrWhiteSpace($cpuLimit)){ $args += @("--cpus",$cpuLimit) }
    if(-not [string]::IsNullOrWhiteSpace($memoryLimit)){ $args += @("--memory",$memoryLimit) }
  }

  foreach($k in $envMap.Keys){
    $v = $envMap[$k]; if($null -eq $v){ $v="" }
    $args += @("-e","$k=$v")
  }

  if(-not [string]::IsNullOrWhiteSpace($startupCommandBase64)){
    $bootstrapCommand = Get-ContainerBootstrapCommand -startupCommandBase64 $startupCommandBase64 -rootCaContainerPath $rootCaContainerPath
    $args += @("--entrypoint","powershell.exe",$image,"-NoProfile","-ExecutionPolicy","Bypass","-Command",$bootstrapCommand)
  } else {
    $args += @($image)
  }
  return ,$args
}
function Remove-ContainerIfExists([string]$name){
  & docker container inspect $name *> $null
  if($LASTEXITCODE -eq 0){
    DockerCli @("rm","-f",$name)
  }
}
function Resolve-NextContainerName([string]$baseName){
  if([string]::IsNullOrWhiteSpace($baseName)){ $baseName = "profisee" }
  $trimmed = $baseName.Trim()
  if($trimmed -match '-\d+$'){
    return $trimmed
  }

  $names = @()
  try {
    $names = (& docker ps -a --format "{{.Names}}" 2>$null | ForEach-Object { [string]$_ })
  } catch {
    $names = @()
  }

  $pattern = "^{0}-(\d+)$" -f [regex]::Escape($trimmed)
  $maxIndex = -1
  foreach($n in $names){
    if([string]::IsNullOrWhiteSpace($n)){ continue }
    $m = [regex]::Match($n,$pattern)
    if($m.Success){
      try {
        $i = [int]$m.Groups[1].Value
        if($i -gt $maxIndex){ $maxIndex = $i }
      } catch {}
    }
  }
  return "$trimmed-$($maxIndex + 1)"
}
function Ensure-DockerNamespaceNetwork([string]$namespaceName){
  if([string]::IsNullOrWhiteSpace($namespaceName)){ return "" }
  $networkName = $namespaceName.Trim().ToLowerInvariant()

  & docker network inspect $networkName *> $null
  if($LASTEXITCODE -eq 0){
    Write-Host "Using docker namespace network '$networkName'."
    return $networkName
  }

  Write-Host "Creating docker namespace network '$networkName' (driver nat)."
  $createLines = @()
  & docker network create --driver nat $networkName 2>&1 | Tee-Object -Variable createLines | Out-Host
  $createText = (($createLines | ForEach-Object { [string]$_ }) -join "`n")
  if($LASTEXITCODE -eq 0 -or $createText -match "(?i)already exists"){
    return $networkName
  }

  Write-Warning "Network create with driver 'nat' failed. Retrying without explicit driver."
  $createLines2 = @()
  & docker network create $networkName 2>&1 | Tee-Object -Variable createLines2 | Out-Host
  $createText2 = (($createLines2 | ForEach-Object { [string]$_ }) -join "`n")
  if($LASTEXITCODE -eq 0 -or $createText2 -match "(?i)already exists"){
    return $networkName
  }

  Write-Warning "Failed to create docker namespace network '$networkName'. Falling back to default docker network."
  return ""
}
function Get-ContainerIPv4([string]$name){
  if([string]::IsNullOrWhiteSpace($name)){ return "" }
  $inspectLines = @()
  & docker inspect $name 2>&1 | Tee-Object -Variable inspectLines | Out-Null
  if($LASTEXITCODE -ne 0){ return "" }
  $jsonText = (($inspectLines | ForEach-Object { [string]$_ }) -join "`n")
  if([string]::IsNullOrWhiteSpace($jsonText)){ return "" }

  try {
    $obj = $jsonText | ConvertFrom-Json -ErrorAction Stop
  } catch {
    return ""
  }
  $item = if($obj -is [array]){ if($obj.Count -gt 0){ $obj[0] } else { $null } } else { $obj }
  if($null -eq $item){ return "" }

  if($item.PSObject.Properties.Name -contains "NetworkSettings"){
    $ns = $item.NetworkSettings
    if($ns -and $ns.PSObject.Properties.Name -contains "IPAddress" -and -not [string]::IsNullOrWhiteSpace($ns.IPAddress)){
      return [string]$ns.IPAddress
    }
    if($ns -and $ns.PSObject.Properties.Name -contains "Networks" -and $ns.Networks){
      foreach($p in $ns.Networks.PSObject.Properties){
        $net = $p.Value
        if($net -and $net.PSObject.Properties.Name -contains "IPAddress" -and -not [string]::IsNullOrWhiteSpace($net.IPAddress)){
          return [string]$net.IPAddress
        }
      }
    }
  }
  return ""
}
function Remove-LocalPortProxy([int]$listenPort){
  & netsh interface portproxy delete v4tov4 listenport=$listenPort listenaddress=127.0.0.1 *> $null
}
function Ensure-LocalPortProxy([int]$listenPort,[string]$connectAddress,[int]$connectPort){
  if([string]::IsNullOrWhiteSpace($connectAddress)){
    throw "connectAddress is required for local portproxy."
  }
  try { Set-Service -Name iphlpsvc -StartupType Automatic -ErrorAction SilentlyContinue } catch {}
  $iphlp = Get-Service -Name iphlpsvc -ErrorAction SilentlyContinue
  if($iphlp -and $iphlp.Status -ne "Running"){
    Start-Service -Name iphlpsvc
  }

  Remove-LocalPortProxy -listenPort $listenPort
  & netsh interface portproxy add v4tov4 listenport=$listenPort listenaddress=127.0.0.1 connectport=$connectPort connectaddress=$connectAddress protocol=tcp | Out-Null
  if($LASTEXITCODE -ne 0){
    throw "Failed to configure local portproxy 127.0.0.1:${listenPort} -> ${connectAddress}:${connectPort}."
  }
}

# ---------------- MAIN ----------------
Ensure-Dir $WorkDir
$customerInputStatePath = Join-Path $WorkDir "customer-input-state.clixml"
$script:CustomerInputStatePath = $customerInputStatePath
$customerInputState = Load-CustomerInputState $customerInputStatePath
$scriptPathDisplay = if([string]::IsNullOrWhiteSpace($PSCommandPath)){ "<interactive>" } else { $PSCommandPath }
Write-Host "Deploy script: $scriptPathDisplay"
Write-Host "Deploy script version: $($script:DeployScriptVersion)"
if($Isolation -ne "hyperv"){
  throw "This deployment requires Hyper-V isolation for Windows Server 2022 images on Windows Server 2025. Use -Isolation hyperv."
}

Install-ContainersFeature
Ensure-HyperVRole
Install-DockerEngineLatest
Install-NginxStable

# ---- Ask image (no static) ----
Write-Host ""
Write-Host "Profisee image selection"
$acrRegistry = Read-WithHistory -state $customerInputState -key "AcrRegistry" -prompt "ACR registry" -defaultValue "profisee.azurecr.io" -Required
$acrRepo     = Read-WithHistory -state $customerInputState -key "AcrRepository" -prompt "Repository" -defaultValue "profiseeplatform" -Required
$acrTag      = Read-WithHistory -state $customerInputState -key "AcrTag" -prompt "Image tag (e.g. 2025r4.0-153319-win22)" -defaultValue "2025r4.0-153319-win22" -Required

$image = "$acrRegistry/$acrRepo`:$acrTag"

# ---- REQUIRED PEMs (refuse to run without) ----
Write-Host ""
$pemCert = Read-WithHistory -state $customerInputState -key "TlsCertPath" -prompt "Path to TLS CERT file for nginx (.crt or .pem; PEM-encoded)" -Required
$pemKey  = Read-WithHistory -state $customerInputState -key "TlsKeyPath" -prompt "Path to TLS KEY file for nginx (.key or .pem; PEM-encoded)" -Required
Assert-PemFile $pemCert "Certificate"
Assert-PemFile $pemKey  "PrivateKey"

$caCertType = ""
while([string]::IsNullOrWhiteSpace($caCertType)){
  $enteredCaType = Read-WithHistory -state $customerInputState -key "ContainerCaCertType" -prompt "Certificate trust type for container HTTPS hostname/URL (Internal/Public)" -defaultValue "Internal" -Required
  $normalizedCaType = $enteredCaType.Trim().ToLowerInvariant()
  if($normalizedCaType -eq "internal"){
    $caCertType = "Internal"
  } elseif($normalizedCaType -eq "public"){
    $caCertType = "Public"
  } else {
    Write-Warning "Please enter either 'Internal' or 'Public'."
    continue
  }
  Set-StateInput -state $customerInputState -key "ContainerCaCertType" -value $caCertType
  Persist-CustomerInputState -state $customerInputState
}

$rootCaCertSourcePath = ""
if($caCertType -eq "Internal"){
  $rootCaCertSourcePath = Read-WithHistory -state $customerInputState -key "ContainerRootCaCertPath" -prompt "Path to Root CA cert for internal hostname/URL chain (.cer/.crt/.pem)" -Required
  if(-not (Test-Path -LiteralPath $rootCaCertSourcePath)){
    throw "Root CA cert file not found: $rootCaCertSourcePath"
  }
} else {
  Set-StateInput -state $customerInputState -key "ContainerRootCaCertPath" -value ""
  Persist-CustomerInputState -state $customerInputState
}

$nginxCertFile = "site.crt"
$nginxKeyFile  = "site.key"

Copy-Item $pemCert "$NginxRoot\conf\certs\$nginxCertFile" -Force
Copy-Item $pemKey  "$NginxRoot\conf\certs\$nginxKeyFile" -Force

# ---- Prompts for EXACT Profisee env vars you provided ----
Write-Host ""
$sqlServer = Read-WithHistory -state $customerInputState -key "ProfiseeSqlServer" -prompt "ProfiseeSqlServer (e.g. xxx.database.windows.net)" -Required
$sqlDb     = Read-WithHistory -state $customerInputState -key "ProfiseeSqlDatabase" -prompt "ProfiseeSqlDatabase" -Required
$sqlUser   = Read-WithHistory -state $customerInputState -key "ProfiseeSqlUserName" -prompt "ProfiseeSqlUserName" -Required
$sqlPass   = Read-SecretWithHistory -state $customerInputState -key "ProfiseeSqlPassword" -prompt "ProfiseeSqlPassword" -Required

Write-Host ""
$repoLocation = Read-WithHistory -state $customerInputState -key "ProfiseeAttachmentRepositoryLocation" -prompt "ProfiseeAttachmentRepositoryLocation (host path to mount, UNC or local, e.g. \\server\share or C:\localfolder)" -Required
$repoUser     = Read-WithHistory -state $customerInputState -key "ProfiseeAttachmentRepositoryUserName" -prompt "ProfiseeAttachmentRepositoryUserName" -Required
$repoPass     = Read-SecretWithHistory -state $customerInputState -key "ProfiseeAttachmentRepositoryUserPassword" -prompt "ProfiseeAttachmentRepositoryUserPassword" -Required
$repoLogon    = Read-WithHistory -state $customerInputState -key "ProfiseeAttachmentRepositoryLogonType" -prompt "ProfiseeAttachmentRepositoryLogonType" -defaultValue "NewCredentials" -Required

Write-Host ""
$adminAccount = Read-WithHistory -state $customerInputState -key "ProfiseeAdminAccount" -prompt "ProfiseeAdminAccount (email/username)" -Required
$externalUrl  = Read-WithHistory -state $customerInputState -key "ProfiseeExternalDNSUrl" -prompt "ProfiseeExternalDNSUrl (e.g. https://something.com)" -Required
$webAppName = Read-WithHistory -state $customerInputState -key "ProfiseeWebAppName" -prompt "ProfiseeWebAppName (used in URL path: https://FQDN/<ProfiseeWebAppName>)" -Required

Download-NginxConfTemplate
Start-Nginx

Write-Host ""
$oidcProvider  = Read-WithHistory -state $customerInputState -key "ProfiseeOidcName" -prompt "ProfiseeOidcName (Entra/Okta)" -defaultValue "Entra" -Required
if($oidcProvider.ToLower() -eq "entra"){
  $priorTenantId = Get-StateSecret $customerInputState "ProfiseeOidcTenantId"
  if([string]::IsNullOrWhiteSpace($priorTenantId)){
    $priorTenantId = Get-StateInput $customerInputState "ProfiseeOidcTenantId"
  }
  if([string]::IsNullOrWhiteSpace($priorTenantId)){
    $priorTenantId = Get-EntraTenantIdFromAuthority (Get-StateInput $customerInputState "ProfiseeOidcAuthority")
  }
  if(-not [string]::IsNullOrWhiteSpace($priorTenantId)){
    Set-StateSecret -state $customerInputState -key "ProfiseeOidcTenantId" -value $priorTenantId
    if($customerInputState.Inputs.ContainsKey("ProfiseeOidcTenantId")){
      $customerInputState.Inputs.Remove("ProfiseeOidcTenantId") | Out-Null
    }
    Persist-CustomerInputState -state $customerInputState
  }

  $oidcTenantIdInput = Read-SecretWithHistory -state $customerInputState -key "ProfiseeOidcTenantId" -prompt "ProfiseeOidcTenantId (used for https://login.microsoftonline.com/<tenantId>)" -Required
  $oidcTenantId = Get-EntraTenantIdFromAuthority $oidcTenantIdInput
  if([string]::IsNullOrWhiteSpace($oidcTenantId)){ $oidcTenantId = $oidcTenantIdInput.Trim() }
  $oidcAuthority = "https://login.microsoftonline.com/$oidcTenantId"
  Set-StateSecret -state $customerInputState -key "ProfiseeOidcTenantId" -value $oidcTenantId
  Set-StateInput -state $customerInputState -key "ProfiseeOidcAuthority" -value $oidcAuthority
  Persist-CustomerInputState -state $customerInputState
  Write-Host ("ProfiseeOidcAuthority resolved to: {0}" -f (Get-MaskedEntraAuthorityPreview $oidcAuthority))
} else {
  $oidcAuthority = Read-WithHistory -state $customerInputState -key "ProfiseeOidcAuthority" -prompt "ProfiseeOidcAuthority (full authority URL)" -Required
}
$oidcClientId  = Read-WithHistory -state $customerInputState -key "ProfiseeOidcClientId" -prompt "ProfiseeOidcClientId" -Required -SensitiveDisplay
$oidcSecret    = Read-SecretWithHistory -state $customerInputState -key "ProfiseeOidcClientSecret" -prompt "ProfiseeOidcClientSecret" -Required

Write-Host ""
$purviewTenantId = Read-WithHistory -state $customerInputState -key "ProfiseePurviewTenantId" -prompt "ProfiseePurviewTenantId (optional)" -SensitiveDisplay
$purviewClientId = Read-WithHistory -state $customerInputState -key "ProfiseePurviewClientId" -prompt "ProfiseePurviewClientId (optional)" -SensitiveDisplay
$purviewClientSecret = Read-SecretWithHistory -state $customerInputState -key "ProfiseePurviewClientSecret" -prompt "ProfiseePurviewClientSecret (optional)"
$purviewUrl = Read-WithHistory -state $customerInputState -key "ProfiseePurviewUrl" -prompt "ProfiseePurviewUrl (optional)"
$priorPurviewCollectionId = Get-StateInput $customerInputState "ProfiseePurviewCollectionId"
if(-not [string]::IsNullOrWhiteSpace($priorPurviewCollectionId) -and [string]::IsNullOrWhiteSpace((Get-StateSecret $customerInputState "ProfiseePurviewCollectionId"))){
  Set-StateSecret -state $customerInputState -key "ProfiseePurviewCollectionId" -value $priorPurviewCollectionId
  if($customerInputState.Inputs.ContainsKey("ProfiseePurviewCollectionId")){
    $customerInputState.Inputs.Remove("ProfiseePurviewCollectionId") | Out-Null
  }
  Persist-CustomerInputState -state $customerInputState
}
$purviewCollectionId = Read-SecretWithHistory -state $customerInputState -key "ProfiseePurviewCollectionId" -prompt "ProfiseePurviewCollectionId (optional)"

if($oidcProvider.ToLower() -eq "entra"){
  $oidcUsernameClaim = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
  $oidcUserIdClaim   = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"
  $oidcFirstName     = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"
  $oidcLastName      = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"
  $oidcEmailClaim    = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
  $oidcGroupsClaim   = "groups"
} else {
  $oidcUsernameClaim = "preferred_username"
  $oidcUserIdClaim   = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"
  $oidcFirstName     = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"
  $oidcLastName      = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"
  $oidcEmailClaim    = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
  $oidcGroupsClaim   = "groups"
}

Write-Host ""
$cpuLimit = Read-WithHistory -state $customerInputState -key "ContainerCpuLimit" -prompt "CPU limit for container (--cpus), e.g. 2" -defaultValue "2" -Required
$memLimit = Read-WithHistory -state $customerInputState -key "ContainerMemoryLimit" -prompt "Memory limit for container (--memory), e.g. 8G" -defaultValue "8G" -Required
$memLimit = Normalize-MemoryLimit $memLimit
Set-StateInput -state $customerInputState -key "ContainerMemoryLimit" -value $memLimit
Persist-CustomerInputState -state $customerInputState

Write-Host ""
Write-Host "ACR login (auth is computed automatically when needed)"
$acrUser = Read-WithHistory -state $customerInputState -key "AcrUserName" -prompt "ACR username" -Required
$acrPw   = Read-SecretWithHistory -state $customerInputState -key "AcrPassword" -prompt "ACR password" -Required
# Computed auth for ACR login flow.
$acrAuth = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("$acrUser`:$acrPw"))

Write-Host ""
$oidcJsonSource = Read-WithHistory -state $customerInputState -key "OidcJsonSourcePath" -prompt "Path to local OIDC JSON file for c:\data\oidc.json (blank = create {})"
Save-CustomerInputState -state $customerInputState -path $customerInputStatePath

$hostDataDir = Join-Path $WorkDir "data"
Ensure-Dir $hostDataDir
$hostOidcJson = Join-Path $hostDataDir "oidc.json"
if([string]::IsNullOrWhiteSpace($oidcJsonSource)){
  "{}" | Set-Content -Path $hostOidcJson -Encoding utf8 -Force
} else {
  if(-not(Test-Path $oidcJsonSource)){ throw "OIDC JSON file not found: $oidcJsonSource" }
  Copy-Item $oidcJsonSource $hostOidcJson -Force
}

$containerRootCaPath = ""
if(-not [string]::IsNullOrWhiteSpace($rootCaCertSourcePath)){
  $containerRootCaPath = "c:\data\root-ca.cer"
  $hostRootCaPath = Join-Path $hostDataDir "root-ca.cer"
  Stage-RootCaCertificateForContainer -sourcePath $rootCaCertSourcePath -destinationPath $hostRootCaPath
  Write-Host "Root CA cert staged for container trust: $hostRootCaPath -> $containerRootCaPath"
}

$containerLicenseFile = "c:\data\profisee.plic"
$hostLicenseFile = Join-Path $hostDataDir "profisee.plic"
$licenseString = ""
$licenseMode = ""
while([string]::IsNullOrWhiteSpace($licenseMode)){
  Write-Host ""
  $licenseFileSource = Read-WithHistory -state $customerInputState -key "ProfiseeLicenseSourcePath" -prompt "Path to local Profisee .plic file (optional; leave blank to use base64)"
  if(-not [string]::IsNullOrWhiteSpace($licenseFileSource)){
    if(-not(Test-Path $licenseFileSource)){
      Write-Warning "License file not found: $licenseFileSource"
      continue
    }
    Copy-Item $licenseFileSource $hostLicenseFile -Force
    Set-StateSecret -state $customerInputState -key "ProfiseeLicenseString" -value ""
    Persist-CustomerInputState -state $customerInputState
    $licenseMode = "file"
    break
  }

  $licenseString = Read-SecretWithHistory -state $customerInputState -key "ProfiseeLicenseString" -prompt "ProfiseeLicenseString (base64; optional if .plic path provided)"
  if(-not [string]::IsNullOrWhiteSpace($licenseString)){
    if(-not (Test-Base64String $licenseString)){
      Write-Warning "ProfiseeLicenseString is not valid base64. Please re-enter."
      continue
    }
    $licenseMode = "base64"
    break
  }

  Write-Warning "A license is required. Provide either a .plic path or a base64 ProfiseeLicenseString."
}

# ---- docker login/pull/run ----
Login-Acr -registry $acrRegistry -user $acrUser -password $acrPw

$imagePulled = $false
while(-not $imagePulled){
  try {
    DockerCli @("pull", $image)
    $imagePulled = $true
  } catch {
    $pullErr = $script:LastContainerCliOutputText
    if([string]::IsNullOrWhiteSpace($pullErr)){ $pullErr = $_.Exception.Message }
    if($pullErr -match "(404|not found)"){
      Write-Warning "Image not found in ACR: $image"
      Write-Host "Update image coordinates and retry pull."
      $acrRegistry = Read-WithHistory -state $customerInputState -key "AcrRegistry" -prompt "ACR registry" -defaultValue "profisee.azurecr.io" -Required
      $acrRepo     = Read-WithHistory -state $customerInputState -key "AcrRepository" -prompt "Repository" -defaultValue "profiseeplatform" -Required
      $acrTag      = Read-WithHistory -state $customerInputState -key "AcrTag" -prompt "Image tag (e.g. 2025r4.0-153319-win22)" -defaultValue "2025r4.0-153319-win22" -Required
      $image       = "$acrRegistry/$acrRepo`:$acrTag"
      Login-Acr -registry $acrRegistry -user $acrUser -password $acrPw
      continue
    }
    throw
  }
}

$startupCommandBase64 = ""
if(-not [string]::IsNullOrWhiteSpace($containerRootCaPath)){
  $startupTokens = Get-DockerImageStartupTokens -image $image
  if($startupTokens.Count -lt 1){
    throw "Image '$image' does not define an entrypoint/cmd to execute after Root CA injection."
  }
  $startupJson = ConvertTo-Json -InputObject $startupTokens -Compress
  $startupCommandBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($startupJson))
  Write-Host "Container startup bootstrap enabled: Root CA import runs before app startup."
}

$resolvedContainerName = Resolve-NextContainerName -baseName $ContainerName
Write-Host "Container name selected: $resolvedContainerName"
$containerAttachmentPath = "c:\fileshare"
$repoMountSource = Resolve-RepositoryMountSource -repoLocation $repoLocation
Write-Host "Attachment repository mount: host '$repoMountSource' -> container '$containerAttachmentPath'"
Download-ForensicsScriptToRepository -repoMountSource $repoMountSource
$containerNetwork = ""
if($Isolation -eq "hyperv"){
  if(-not [string]::IsNullOrWhiteSpace($DockerNamespace)){
    Write-Host "Docker namespace label: '$DockerNamespace'."
  }
  Write-Warning "Hyper-V isolation selected. Using default docker network (custom --network is skipped)."
} else {
  $containerNetwork = Ensure-DockerNamespaceNetwork -namespaceName $DockerNamespace
  if([string]::IsNullOrWhiteSpace($containerNetwork)){
    Write-Warning "Docker namespace network unavailable. Container will use default docker network."
  } else {
    Write-Host "Docker namespace: '$DockerNamespace' (network '$containerNetwork')."
  }
}

$envMap = @{
  "ProfiseeAdditionalOpenIdConnectProvidersFile" = "c:\data\oidc.json"
  "ProfiseeAdminAccount"                        = $adminAccount

  "ProfiseeLicenseFile"                         = $containerLicenseFile

  "ProfiseeAttachmentRepositoryLocation"        = $containerAttachmentPath
  "ProfiseeAttachmentRepositoryLogonType"       = $repoLogon
  "ProfiseeAttachmentRepositoryUserName"        = $repoUser
  "ProfiseeAttachmentRepositoryUserPassword"    = $repoPass

  "ProfiseeExternalDNSUrl"                      = $externalUrl

  "ProfiseeOidcAuthority"                       = $oidcAuthority
  "ProfiseeOidcClientId"                        = $oidcClientId
  "ProfiseeOidcClientSecret"                    = $oidcSecret
  "ProfiseeOidcEmailClaim"                      = $oidcEmailClaim
  "ProfiseeOidcFirstNameClaim"                  = $oidcFirstName
  "ProfiseeOidcGroupsClaim"                     = $oidcGroupsClaim
  "ProfiseeOidcLastNameClaim"                   = $oidcLastName
  "ProfiseeOidcName"                            = $oidcProvider
  "ProfiseeOidcUserIdClaim"                     = $oidcUserIdClaim
  "ProfiseeOidcUsernameClaim"                   = $oidcUsernameClaim

  "ProfiseePurviewTenantId"                     = $purviewTenantId
  "ProfiseePurviewClientId"                     = $purviewClientId
  "ProfiseePurviewClientSecret"                 = $purviewClientSecret
  "ProfiseePurviewUrl"                          = $purviewUrl
  "ProfiseePurviewCollectionId"                 = $purviewCollectionId

  "ProfiseeSqlDatabase"                         = $sqlDb
  "ProfiseeSqlPassword"                         = $sqlPass
  "ProfiseeSqlServer"                           = $sqlServer
  "ProfiseeSqlUserName"                         = $sqlUser

  "ProfiseeUseWindowsAuthentication"            = "false"
  "ProfiseeWebAppName"                          = $webAppName
}
if($licenseMode -eq "base64"){
  $envMap["ProfiseeLicenseString"] = $licenseString
}

$envListPath = Join-Path $WorkDir "container-env-vars.txt"
$envMap.Keys | Sort-Object | Set-Content -Path $envListPath -Encoding ascii -Force

$runAttempts = @(
  [pscustomobject]@{
    Name = "hyperv-standard"
    Message = ""
    AttemptIsolation = "hyperv"
    IncludeResourceLimits = $true
    IncludeIsolation = $true
    IncludeNetwork = $true
    IncludePortMapping = $true
    IncludeBindMount = $true
  },
  [pscustomobject]@{
    Name = "hyperv-no-limits"
    Message = "docker run returned 'not implemented'. Retrying with Hyper-V isolation and without --cpus/--memory."
    AttemptIsolation = "hyperv"
    IncludeResourceLimits = $false
    IncludeIsolation = $true
    IncludeNetwork = $true
    IncludePortMapping = $true
    IncludeBindMount = $true
  }
)

$runSucceeded = $false
$runSucceededMode = ""
$runUsedPortMapping = $true
$lastRunErrorText = ""
$containerIpViaPortProxy = ""

for($i = 0; $i -lt $runAttempts.Count; $i++){
  $attempt = $runAttempts[$i]
  if($i -gt 0 -and -not [string]::IsNullOrWhiteSpace($attempt.Message)){
    Write-Warning $attempt.Message
  }

  $attemptArgs = Build-ContainerRunArgs -name $resolvedContainerName -isolation $attempt.AttemptIsolation -dockerNamespace $DockerNamespace -networkName $containerNetwork -hostPort $HostAppPort -hostDataDir $hostDataDir -repoMountSource $repoMountSource -cpuLimit $cpuLimit -memoryLimit $memLimit -envMap $envMap -image $image -startupCommandBase64 $startupCommandBase64 -rootCaContainerPath $containerRootCaPath -IncludeResourceLimits:$attempt.IncludeResourceLimits -IncludeIsolation:$attempt.IncludeIsolation -IncludeNetwork:$attempt.IncludeNetwork -IncludePortMapping:$attempt.IncludePortMapping -IncludeBindMount:$attempt.IncludeBindMount

  try {
    DockerCli $attemptArgs
    $runSucceeded = $true
    $runSucceededMode = $attempt.Name
    $runUsedPortMapping = [bool]$attempt.IncludePortMapping
    break
  } catch {
    $runErr = $script:LastContainerCliOutputText
    if([string]::IsNullOrWhiteSpace($runErr)){ $runErr = $_.Exception.Message }
    $lastRunErrorText = $runErr
    if((Is-ContainerCliNotImplemented $runErr) -or (Is-ContainerCliRecoverableNetworkBug $runErr)){
      Remove-ContainerIfExists $resolvedContainerName
      continue
    }
    throw
  }
}

if(-not $runSucceeded){
  throw "docker run failed while enforcing Hyper-V isolation. This host likely does not support one or more required Windows container features (Hyper-V isolation, port mapping, and/or bind mounts)."
}
if($runSucceededMode -ne "hyperv-standard"){
  Write-Warning "Container started in compatibility mode '$runSucceededMode'."
}
if($runUsedPortMapping){
  Remove-LocalPortProxy -listenPort $HostAppPort
} else {
  $containerIpViaPortProxy = Get-ContainerIPv4 -name $resolvedContainerName
  if([string]::IsNullOrWhiteSpace($containerIpViaPortProxy)){
    throw "Container started without native port mapping, but container IP could not be determined for local portproxy setup."
  }
  Ensure-LocalPortProxy -listenPort $HostAppPort -connectAddress $containerIpViaPortProxy -connectPort 80
  Write-Warning "Native port mapping is unavailable on this host. Using local portproxy 127.0.0.1:$HostAppPort -> ${containerIpViaPortProxy}:80."
}

Write-Host ""
Write-Host "DONE."
Write-Host "Access: https://<FQDN>/$webAppName (nginx 443 terminates TLS and proxies to container HTTP)"
Write-Host "nginx redirects: http://<FQDN> -> https://<FQDN>"
if($runUsedPortMapping){
  Write-Host "Container '$resolvedContainerName' is mapped host 127.0.0.1:$HostAppPort -> container :80 (internal only)"
} else {
  Write-Host "Container '$resolvedContainerName' port path uses local portproxy 127.0.0.1:$HostAppPort -> ${containerIpViaPortProxy}:80 (internal only)"
}
Write-Host "oidc.json injected at: c:\data\oidc.json"
if(-not [string]::IsNullOrWhiteSpace($containerRootCaPath)){
  Write-Host "Root CA cert injected at container startup from: $containerRootCaPath (store: Cert:\LocalMachine\Root)"
}
Write-Host "Container env var key list written to: $envListPath"
Write-Host "Customer input state saved to: $customerInputStatePath"
Write-Host ""

try {
  $dockerSvc = Get-Service -Name "docker" -ErrorAction Stop
  Write-Host "Docker service status: $($dockerSvc.Status)"
} catch {
  Write-Warning "Could not read Docker service status. Error: $($_.Exception.Message)"
}

Write-Host ""
Write-Host "docker ps -a"
& docker ps -a 2>&1 | Out-Host

$traceContainer = "profisee-0"
& docker container inspect $traceContainer *> $null
if($LASTEXITCODE -ne 0){
  $traceContainer = $resolvedContainerName
}

Write-Host ""
Write-Host "Streaming logs (Ctrl+C to stop): docker logs -f $traceContainer"
& docker logs -f $traceContainer 2>&1 | Out-Host
