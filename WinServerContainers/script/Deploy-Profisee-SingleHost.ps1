# Deploy-Profisee-SingleHost.ps1
#requires -RunAsAdministrator
[CmdletBinding()]
param(
  [string]$ContainerName = "profisee",
  [ValidateSet("process","hyperv")] [string]$Isolation = "process",

  # Container port assumption: Profisee serves HTTP on 80 in-container.
  [int]$HostAppPort = 18080,

  [string]$NginxRoot = "C:\nginx",
  [string]$WorkDir = "C:\ProfiseeDeploy",

  # For parity/reference as you requested
  [string]$SettingsYamlUrl = "https://raw.githubusercontent.com/Profiseeadmin/kubernetes/refs/heads/master/Azure-ARM/Settings.yaml",
  [string]$NginxConfUrl = "https://raw.githubusercontent.com/Profiseeadmin/kubernetes/refs/heads/master/WinServerContainers/nginx-config/nginx.conf"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$script:CustomerInputStatePath = $null
$script:LastContainerCliOutputText = ""
$script:DeployScriptVersion = "2026-02-25.6"

function Ensure-Dir([string]$p){ if(-not(Test-Path $p)){ New-Item -ItemType Directory -Path $p | Out-Null } }
function SecureToPlain([Security.SecureString]$s){
  $b=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)
  try{[Runtime.InteropServices.Marshal]::PtrToStringAuto($b)} finally{[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b)}
}
function Read-Required([string]$prompt){
  do { $v = Read-Host $prompt } while([string]::IsNullOrWhiteSpace($v))
  return $v
}
function Read-RequiredSecret([string]$prompt){
  do { $v = SecureToPlain (Read-Host $prompt -AsSecureString) } while([string]::IsNullOrWhiteSpace($v))
  return $v
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
function Get-ContainerdLocalVersion {
  $exe = "$env:ProgramFiles\containerd\containerd.exe"
  if(-not(Test-Path $exe)){ return $null }
  try{
    $txt = (& $exe --version 2>&1 | Out-String)
    $m = [regex]::Match($txt,'v(\d+\.\d+\.\d+)')
    if($m.Success){ return $m.Groups[1].Value }
  } catch {}
  return $null
}
function Get-NerdctlLocalVersion {
  $exe = "$env:ProgramFiles\nerdctl\nerdctl.exe"
  if(-not(Test-Path $exe)){ return $null }
  try{
    $txt = (& $exe --version 2>&1 | Out-String)
    $m = [regex]::Match($txt,'(\d+\.\d+\.\d+)')
    if($m.Success){ return $m.Groups[1].Value }
  } catch {}
  return $null
}
function Get-WindowsCniLocalVersion {
  $marker = "$env:ProgramFiles\containerd\cni\bin\wcni.version"
  if(Test-Path $marker){
    $v = (Get-Content -Raw -Path $marker).Trim()
    if(-not [string]::IsNullOrWhiteSpace($v)){ return $v }
  }

  $natExe = "$env:ProgramFiles\containerd\cni\bin\nat.exe"
  if(Test-Path $natExe){
    $fv = (Get-Item $natExe).VersionInfo.FileVersion
    $m = [regex]::Match($fv,'(\d+\.\d+\.\d+)')
    if($m.Success){ return $m.Groups[1].Value }
  }
  return $null
}
function Get-LatestGitHubRelease([string]$owner,[string]$repo,[string]$fallback){
  try{
    $r = Invoke-RestMethod -Headers @{ "User-Agent"="ProfiseeDeploy" } -Uri "https://api.github.com/repos/$owner/$repo/releases/latest"
    return ($r.tag_name -replace '^v','')
  } catch { return $fallback }
}
function Stop-ServiceIfExists([string]$name){
  $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
  if($svc -and $svc.Status -ne "Stopped"){ Stop-Service -Name $name -Force }
}
function Ensure-ContainerdService([switch]$ForceRestart){
  $containerdExe = "$env:ProgramFiles\containerd\containerd.exe"
  if(-not(Test-Path $containerdExe)){ throw "containerd.exe not found at $containerdExe" }

  $cfgPath = "$env:ProgramFiles\containerd\config.toml"
  if(-not(Test-Path $cfgPath)){
    & $containerdExe config default | Out-File $cfgPath -Encoding ascii
  }

  $svc = Get-Service -Name "containerd" -ErrorAction SilentlyContinue
  if(-not $svc){
    & $containerdExe --register-service | Out-Null
    $svc = Get-Service -Name "containerd" -ErrorAction SilentlyContinue
  }
  if(-not $svc){ throw "containerd service could not be registered." }

  if($ForceRestart){
    if($svc.Status -eq "Running"){
      Restart-Service containerd -Force
    } else {
      Start-Service containerd
    }
    return
  }
  if($svc.Status -ne "Running"){ Start-Service containerd }
}
function Install-ContainersFeature {
  Import-Module ServerManager -ErrorAction SilentlyContinue | Out-Null
  $feat = Get-WindowsFeature -Name Containers -ErrorAction SilentlyContinue
  if($feat -and -not $feat.Installed){
    Install-WindowsFeature -Name Containers | Out-Null
    Write-Warning "Containers feature installed. A reboot may be required."
  }
}
function Get-DockerLocalVersion {
  $dockerExe = $null
  try {
    $cmd = Get-Command docker -ErrorAction SilentlyContinue
    if($cmd){ $dockerExe = $cmd.Source }
  } catch {}
  if([string]::IsNullOrWhiteSpace($dockerExe)){
    $fallback = "$env:ProgramFiles\Docker\docker.exe"
    if(Test-Path $fallback){ $dockerExe = $fallback }
  }
  if([string]::IsNullOrWhiteSpace($dockerExe)){ return $null }
  try{
    $txt = (& $dockerExe --version 2>&1 | Out-String)
    $m = [regex]::Match($txt,'(\d+\.\d+\.\d+)')
    if($m.Success){ return $m.Groups[1].Value }
  } catch {}
  return $null
}
function Get-LatestDockerStableVersion {
  try{
    $listing = (Invoke-WebRequest -Uri "https://download.docker.com/win/static/stable/x86_64/" -UseBasicParsing).Content
    $matches = [regex]::Matches($listing,'docker-(\d+\.\d+\.\d+)\.zip')
    $unique = @{}
    foreach($m in $matches){ $unique[$m.Groups[1].Value] = $true }
    if($unique.Keys.Count -gt 0){
      return ($unique.Keys | Sort-Object { [version]$_ } -Descending | Select-Object -First 1)
    }
  } catch {}
  return $null
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
  Ensure-Dir "$env:ProgramFiles\Docker"

  $latestDocker = Get-LatestDockerStableVersion
  $localDocker = Get-DockerLocalVersion
  $dockerUpdated = $false

  if([string]::IsNullOrWhiteSpace($latestDocker)){
    if(-not [string]::IsNullOrWhiteSpace($localDocker)){
      Write-Warning "Could not determine latest Docker version online. Keeping local version $localDocker."
      Ensure-PathContains @("$env:ProgramFiles\Docker")
      Ensure-DockerService
      return
    }
    throw "Could not determine latest Docker version online and Docker is not installed."
  }

  if(Is-SameOrNewer $localDocker $latestDocker){
    Write-Host "docker local version $localDocker is current (latest $latestDocker). Skipping install."
  } else {
    Write-Host "Updating docker from '$localDocker' to '$latestDocker'"
    Stop-ServiceIfExists "docker"
    $dockerZip = Join-Path $WorkDir "docker-$latestDocker.zip"
    $dockerExtract = Join-Path $WorkDir "docker-extract"
    if(Test-Path $dockerExtract){ Remove-Item $dockerExtract -Recurse -Force }
    Ensure-Dir $dockerExtract
    Invoke-WebRequest -Uri "https://download.docker.com/win/static/stable/x86_64/docker-$latestDocker.zip" -OutFile $dockerZip
    Expand-Archive -Path $dockerZip -DestinationPath $dockerExtract -Force
    Copy-Item -Path (Join-Path $dockerExtract "docker\*") -Destination "$env:ProgramFiles\Docker" -Recurse -Force
    Remove-Item $dockerExtract -Recurse -Force
    $dockerUpdated = $true
  }

  Ensure-PathContains @("$env:ProgramFiles\Docker")
  Ensure-DockerService -ForceRestart:$dockerUpdated
}

function Install-ContainerdAndNerdctl {
  Ensure-Dir $WorkDir
  Ensure-Dir "$env:ProgramFiles\containerd"
  Ensure-Dir "$env:ProgramFiles\nerdctl"

  $containerdVer = Get-LatestGitHubRelease "containerd" "containerd" "2.2.1"
  $nerdctlVer    = Get-LatestGitHubRelease "containerd" "nerdctl"    "2.2.1"
  $localContainerdVer = Get-ContainerdLocalVersion
  $localNerdctlVer = Get-NerdctlLocalVersion
  $arch = "amd64"
  $containerdUpdated = $false

  if(Is-SameOrNewer $localContainerdVer $containerdVer){
    Write-Host "containerd local version $localContainerdVer is current (latest $containerdVer). Skipping install."
  } else {
    Write-Host "Updating containerd from '$localContainerdVer' to '$containerdVer'"
    Stop-ServiceIfExists "containerd"
    $cTgz = Join-Path $WorkDir "containerd-$containerdVer-windows-$arch.tar.gz"
    $cExtract = Join-Path $WorkDir "containerd-extract"
    if(Test-Path $cExtract){ Remove-Item $cExtract -Recurse -Force }
    Ensure-Dir $cExtract
    Invoke-WebRequest -Uri "https://github.com/containerd/containerd/releases/download/v$containerdVer/containerd-$containerdVer-windows-$arch.tar.gz" -OutFile $cTgz
    tar.exe -xvf $cTgz -C $cExtract | Out-Null
    Copy-Item -Path (Join-Path $cExtract "bin\*") -Destination "$env:ProgramFiles\containerd" -Recurse -Force
    Remove-Item $cExtract -Recurse -Force
    $containerdUpdated = $true
  }

  if(Is-SameOrNewer $localNerdctlVer $nerdctlVer){
    Write-Host "nerdctl local version $localNerdctlVer is current (latest $nerdctlVer). Skipping install."
  } else {
    Write-Host "Updating nerdctl from '$localNerdctlVer' to '$nerdctlVer'"
    $nTgz = Join-Path $WorkDir "nerdctl-$nerdctlVer-windows-$arch.tar.gz"
    $nExtract = Join-Path $WorkDir "nerdctl-extract"
    if(Test-Path $nExtract){ Remove-Item $nExtract -Recurse -Force }
    Ensure-Dir $nExtract
    Invoke-WebRequest -Uri "https://github.com/containerd/nerdctl/releases/download/v$nerdctlVer/nerdctl-$nerdctlVer-windows-$arch.tar.gz" -OutFile $nTgz
    tar.exe -xvf $nTgz -C $nExtract | Out-Null
    Copy-Item -Path (Join-Path $nExtract "nerdctl.exe") -Destination "$env:ProgramFiles\nerdctl\nerdctl.exe" -Force
    Remove-Item $nExtract -Recurse -Force
  }

  Ensure-PathContains @("$env:ProgramFiles\containerd","$env:ProgramFiles\nerdctl")
  Ensure-ContainerdService -ForceRestart:$containerdUpdated
}

function Ensure-HnsModule {
  if(-not(Get-Command New-HnsNetwork -ErrorAction SilentlyContinue)){
    $hns = Join-Path $WorkDir "hns.psm1"
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/microsoft/SDN/master/Kubernetes/windows/hns.psm1" -OutFile $hns
    Import-Module $hns -Force
  }
}
function Write-ContainerdNatCniConfig([string]$adapterName){
  if([string]::IsNullOrWhiteSpace($adapterName)){ $adapterName = "Ethernet" }
@"
{
  "cniVersion": "1.0.0",
  "name": "nat",
  "type": "nat",
  "master": "$adapterName",
  "ipam": {
    "subnet": "10.88.0.0/16",
    "ranges": [
      [
        { "subnet": "10.88.0.0/16", "gateway": "10.88.0.1" }
      ]
    ],
    "routes": [ { "dst": "0.0.0.0/0", "gw": "10.88.0.1" } ]
  },
  "capabilities": { "portMappings": true, "dns": true }
}
"@ | Set-Content -Path "$env:ProgramFiles\containerd\cni\conf\0-containerd-nat.conf" -Encoding ascii -Force
}

function Install-WindowsNatCni_Latest {
  # Install latest windows-container-networking CNI zip (contains nat.exe, etc.)
  Ensure-Dir "$env:ProgramFiles\containerd\cni\bin"
  Ensure-Dir "$env:ProgramFiles\containerd\cni\conf"

  $wcniVer = Get-LatestGitHubRelease "microsoft" "windows-container-networking" "0.3.2"
  $localWcniVer = Get-WindowsCniLocalVersion
  $zipName = "windows-container-networking-cni-amd64-v$wcniVer.zip"
  $zipUrl  = "https://github.com/microsoft/windows-container-networking/releases/download/v$wcniVer/$zipName"
  $zipPath = Join-Path $WorkDir $zipName

  if(Is-SameOrNewer $localWcniVer $wcniVer){
    Write-Host "Windows CNI local version $localWcniVer is current (latest $wcniVer). Skipping install."
  } else {
    Write-Host "Updating Windows CNI from '$localWcniVer' to '$wcniVer'"
    Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath
    Expand-Archive -Path $zipPath -DestinationPath "$env:ProgramFiles\containerd\cni\bin" -Force
    Set-Content -Path "$env:ProgramFiles\containerd\cni\bin\wcni.version" -Value $wcniVer -Encoding ascii -Force
  }

  Ensure-HnsModule
  $adapter = (Get-NetAdapter | Where-Object Status -eq "Up" | Select-Object -First 1 -ExpandProperty Name)
  if(-not $adapter){ $adapter = "Ethernet" }
  $existing = Get-HnsNetwork | Where-Object Name -eq "nat" -ErrorAction SilentlyContinue
  if(-not $existing){
    New-HnsNetwork -Type Nat -AddressPrefix "10.88.0.0/16" -Gateway "10.88.0.1" -Name "nat" | Out-Null
  }
  # Always refresh CNI config so nerdctl sees stable IPAM schema.
  Write-ContainerdNatCniConfig -adapterName $adapter
}

function Download-SettingsYamlTemplate {
  Ensure-Dir $WorkDir
  $dst = Join-Path $WorkDir "Settings.yaml"
  Invoke-WebRequest -Uri $SettingsYamlUrl -OutFile $dst
  Write-Host "Downloaded Settings.yaml template to $dst"
}
function Download-NginxConfTemplate([int]$upstreamPort,[string]$webAppName,[string]$certFileName,[string]$keyFileName){
  Ensure-Dir $WorkDir
  Ensure-Dir "$NginxRoot\conf"
  Ensure-Dir "$NginxRoot\logs"

  $tmp = Join-Path $WorkDir "nginx.conf.downloaded"
  $dst = Join-Path $NginxRoot "conf\nginx.conf"

  Invoke-WebRequest -Uri $NginxConfUrl -OutFile $tmp
  $conf = Get-Content -Raw -Path $tmp
  if([string]::IsNullOrWhiteSpace($conf)){ throw "Downloaded nginx.conf is empty from: $NginxConfUrl" }

  # Keep repo as source of truth while applying run-time values.
  $conf = [regex]::Replace($conf,'server\s+127\.0\.0\.1:\d+;',"server 127.0.0.1:$upstreamPort;",1)
  $conf = [regex]::Replace($conf,'ssl_certificate\s+[^;]+;',"ssl_certificate     c:/nginx/conf/certs/$certFileName;",1)
  $conf = [regex]::Replace($conf,'ssl_certificate_key\s+[^;]+;',"ssl_certificate_key c:/nginx/conf/certs/$keyFileName;",1)
  if($conf -notmatch '(?m)^\s*server_tokens\s+off;'){
    $conf = [regex]::Replace($conf,'default_type\s+application/octet-stream;',"default_type  application/octet-stream;`r`n`r`n    server_tokens off;",1)
  }
  if($conf -notmatch 'location\s*=\s*/\s*\{'){
    $needle = "        location = /healthz {"
    if($conf.Contains($needle)){
      $conf = $conf.Replace($needle, "        location = / { return 302 /$webAppName/; }`r`n`r`n$needle")
    }
  }

  Set-Content -Path $dst -Value $conf -Encoding ascii -Force
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

function Write-NginxConf([int]$upstreamPort,[string]$webAppName,[string]$certFileName,[string]$keyFileName){
@"
worker_processes auto;

events {
    worker_connections 50000;
    multi_accept on;
}

http {
    include       mime.types;
    default_type  application/octet-stream;
    server_tokens off;

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;

    keepalive_timeout 60;
    types_hash_max_size 2048;

    client_max_body_size 250M;
    client_body_buffer_size 512k;
    client_body_timeout 300s;
    reset_timedout_connection on;

    log_not_found off;

    log_format main '`$remote_addr - `$remote_user [`$time_local] "`$request" '
                    '`$status `$body_bytes_sent "`$http_referer" '
                    '"`$http_user_agent" "`$http_x_forwarded_for"';

    access_log logs/access.log main;
    error_log  logs/error.log notice;

    gzip on;
    gzip_disable msie6;
    gzip_vary on;
    gzip_comp_level 3;
    gzip_min_length 256;
    gzip_buffers 16 8k;
    gzip_proxied any;
    gzip_types
        text/css
        text/plain
        text/javascript
        application/javascript
        application/json
        application/xml
        application/xml+rss
        application/xhtml+xml
        application/ld+json
        image/svg+xml
        image/x-icon
        font/opentype;

    map `$http_upgrade `$connection_upgrade { default upgrade; "" close; }

    upstream profisee_upstream { server 127.0.0.1:$upstreamPort; keepalive 32; }

    server { listen 80; server_name _; return 301 https://`$host`$request_uri; }

    server {
        listen 443 ssl;
        server_name _;

        ssl_certificate     c:/nginx/conf/certs/$certFileName;
        ssl_certificate_key c:/nginx/conf/certs/$keyFileName;

        # convenience: / -> /<webAppName>/
        location = / { return 302 /$webAppName/; }

        location = /healthz { return 200 "ok`n"; add_header Content-Type text/plain; }

        location / {
            proxy_http_version 1.1;
            proxy_set_header Host                `$host;
            proxy_set_header X-Real-IP           `$remote_addr;
            proxy_set_header X-Forwarded-For     `$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto   https;
            proxy_set_header X-Forwarded-Host    `$host;
            proxy_set_header X-Forwarded-Port    443;
            proxy_set_header Upgrade             `$http_upgrade;
            proxy_set_header Connection          `$connection_upgrade;

            proxy_connect_timeout 60s;
            proxy_send_timeout    600s;
            proxy_read_timeout    600s;

            proxy_buffering off;
            proxy_request_buffering off;

            # DO NOT rewrite the URI; Profisee expects /<webAppName>/... to reach the app
            proxy_pass http://profisee_upstream;
        }
    }
}
"@ | Set-Content -Path "$NginxRoot\conf\nginx.conf" -Encoding ascii -Force
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

  & $exe -s stop -p $prefix 2>$null | Out-Null
  Start-Process -FilePath $exe -WorkingDirectory $NginxRoot -ArgumentList @("-p",$prefix,"-c","conf/nginx.conf") | Out-Null
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
function Build-ContainerRunArgs(
  [string]$name,
  [string]$isolation,
  [string]$networkName,
  [int]$hostPort,
  [string]$hostDataDir,
  [string]$cpuLimit,
  [string]$memoryLimit,
  [hashtable]$envMap,
  [string]$image,
  [switch]$IncludeResourceLimits,
  [switch]$IncludeIsolation,
  [switch]$IncludeNetwork,
  [switch]$IncludePortMapping,
  [switch]$IncludeBindMount
){
  $args = @(
    "run","-d",
    "--name",$name
  )

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
  }

  if($IncludeResourceLimits){
    if(-not [string]::IsNullOrWhiteSpace($cpuLimit)){ $args += @("--cpus",$cpuLimit) }
    if(-not [string]::IsNullOrWhiteSpace($memoryLimit)){ $args += @("--memory",$memoryLimit) }
  }

  foreach($k in $envMap.Keys){
    $v = $envMap[$k]; if($null -eq $v){ $v="" }
    $args += @("-e","$k=$v")
  }

  $args += @($image)
  return ,$args
}
function Remove-ContainerIfExists([string]$name){
  & docker container inspect $name *> $null
  if($LASTEXITCODE -eq 0){
    DockerCli @("rm","-f",$name)
  }
}
function Ensure-NerdctlNatNetwork([string]$networkName){
  if([string]::IsNullOrWhiteSpace($networkName)){ return "" }

  $nerdctlExe = "$env:ProgramFiles\nerdctl\nerdctl.exe"
  & $nerdctlExe network inspect $networkName *> $null
  if($LASTEXITCODE -eq 0){
    Write-Host "Using nerdctl network '$networkName'."
    return $networkName
  }

  Write-Host "Creating nerdctl network '$networkName' (driver nat)."
  $createLines = @()
  & $nerdctlExe network create --driver nat $networkName 2>&1 | Tee-Object -Variable createLines | Out-Host
  $createText = (($createLines | ForEach-Object { [string]$_ }) -join "`n")
  if($LASTEXITCODE -eq 0 -or $createText -match "(?i)already exists"){
    return $networkName
  }

  Write-Warning "Network create with driver 'nat' failed. Retrying without explicit driver."
  $createLines2 = @()
  & $nerdctlExe network create $networkName 2>&1 | Tee-Object -Variable createLines2 | Out-Host
  $createText2 = (($createLines2 | ForEach-Object { [string]$_ }) -join "`n")
  if($LASTEXITCODE -eq 0 -or $createText2 -match "(?i)already exists"){
    return $networkName
  }

  Write-Warning "Failed to create nerdctl network '$networkName'. Falling back to default CNI network selection."
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

Install-ContainersFeature
Install-DockerEngineLatest
Install-NginxStable
Download-SettingsYamlTemplate

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

$certExt = [IO.Path]::GetExtension($pemCert)
if([string]::IsNullOrWhiteSpace($certExt)){ $certExt = ".pem" }
$keyExt = [IO.Path]::GetExtension($pemKey)
if([string]::IsNullOrWhiteSpace($keyExt)){ $keyExt = ".key" }

$nginxCertFile = "site-cert$certExt"
$nginxKeyFile  = "site-key$keyExt"

if($nginxCertFile -ieq $nginxKeyFile){
  throw "TLS cert/key destination filenames resolved to the same file ($nginxCertFile). Refusing to continue."
}

Copy-Item $pemCert "$NginxRoot\conf\certs\$nginxCertFile" -Force
Copy-Item $pemKey  "$NginxRoot\conf\certs\$nginxKeyFile" -Force

# ---- Prompts for EXACT Profisee env vars you provided ----
Write-Host ""
$webAppName = Read-WithHistory -state $customerInputState -key "ProfiseeWebAppName" -prompt "ProfiseeWebAppName (used in URL path: https://FQDN/<ProfiseeWebAppName>)" -Required

try {
  Download-NginxConfTemplate -upstreamPort $HostAppPort -webAppName $webAppName -certFileName $nginxCertFile -keyFileName $nginxKeyFile
} catch {
  Write-Warning "Failed to download nginx.conf from $NginxConfUrl. Falling back to built-in template. Error: $($_.Exception.Message)"
  Write-NginxConf -upstreamPort $HostAppPort -webAppName $webAppName -certFileName $nginxCertFile -keyFileName $nginxKeyFile
}
Start-Nginx

Write-Host ""
$sqlServer = Read-WithHistory -state $customerInputState -key "ProfiseeSqlServer" -prompt "ProfiseeSqlServer (e.g. xxx.database.windows.net)" -Required
$sqlDb     = Read-WithHistory -state $customerInputState -key "ProfiseeSqlDatabase" -prompt "ProfiseeSqlDatabase" -Required
$sqlUser   = Read-WithHistory -state $customerInputState -key "ProfiseeSqlUserName" -prompt "ProfiseeSqlUserName" -Required
$sqlPass   = Read-SecretWithHistory -state $customerInputState -key "ProfiseeSqlPassword" -prompt "ProfiseeSqlPassword" -Required

Write-Host ""
$repoLocation = Read-WithHistory -state $customerInputState -key "ProfiseeAttachmentRepositoryLocation" -prompt "ProfiseeAttachmentRepositoryLocation (UNC path, e.g. \\server\share)" -Required
$repoUser     = Read-WithHistory -state $customerInputState -key "ProfiseeAttachmentRepositoryUserName" -prompt "ProfiseeAttachmentRepositoryUserName" -Required
$repoPass     = Read-SecretWithHistory -state $customerInputState -key "ProfiseeAttachmentRepositoryUserPassword" -prompt "ProfiseeAttachmentRepositoryUserPassword" -Required
$repoLogon    = Read-WithHistory -state $customerInputState -key "ProfiseeAttachmentRepositoryLogonType" -prompt "ProfiseeAttachmentRepositoryLogonType" -defaultValue "NewCredentials" -Required

Write-Host ""
$adminAccount = Read-WithHistory -state $customerInputState -key "ProfiseeAdminAccount" -prompt "ProfiseeAdminAccount (email/username)" -Required
$externalUrl  = Read-WithHistory -state $customerInputState -key "ProfiseeExternalDNSUrl" -prompt "ProfiseeExternalDNSUrl (e.g. https://something.com)" -Required

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
# Computed for Settings.yaml parity/reference (docker login uses --password-stdin).
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

Remove-ContainerIfExists $ContainerName
$containerNetwork = ""

$envMap = @{
  "ProfiseeAdditionalOpenIdConnectProvidersFile" = "c:\data\oidc.json"
  "ProfiseeAdminAccount"                        = $adminAccount

  "ProfiseeLicenseFile"                         = $containerLicenseFile

  "ProfiseeAttachmentRepositoryLocation"        = $repoLocation
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

$envMapNoMount = @{}
foreach($k in $envMap.Keys){ $envMapNoMount[$k] = $envMap[$k] }
$envMapNoMount.Remove("ProfiseeAdditionalOpenIdConnectProvidersFile") | Out-Null
if($licenseMode -eq "file" -and (Test-Path $hostLicenseFile)){
  $licBytes = [IO.File]::ReadAllBytes($hostLicenseFile)
  $envMapNoMount["ProfiseeLicenseString"] = [Convert]::ToBase64String($licBytes)
} elseif($licenseMode -eq "base64"){
  $envMapNoMount["ProfiseeLicenseString"] = $licenseString
}

$runAttempts = @(
  [pscustomobject]@{
    Name = "standard"
    Message = ""
    AttemptIsolation = $Isolation
    UseNoMountEnv = $false
    IncludeResourceLimits = $true
    IncludeIsolation = $true
    IncludeNetwork = $false
    IncludePortMapping = $true
    IncludeBindMount = $true
  },
  [pscustomobject]@{
    Name = "no-resource-limits"
    Message = "docker run returned 'not implemented'. Retrying without --cpus/--memory."
    AttemptIsolation = $Isolation
    UseNoMountEnv = $false
    IncludeResourceLimits = $false
    IncludeIsolation = $true
    IncludeNetwork = $false
    IncludePortMapping = $true
    IncludeBindMount = $true
  },
  [pscustomobject]@{
    Name = "no-explicit-isolation"
    Message = "Retrying without explicit isolation."
    AttemptIsolation = $Isolation
    UseNoMountEnv = $false
    IncludeResourceLimits = $false
    IncludeIsolation = $false
    IncludeNetwork = $false
    IncludePortMapping = $true
    IncludeBindMount = $true
  },
  [pscustomobject]@{
    Name = "no-port-mapping"
    Message = "Retrying without port mapping (-p)."
    AttemptIsolation = $Isolation
    UseNoMountEnv = $false
    IncludeResourceLimits = $false
    IncludeIsolation = $false
    IncludeNetwork = $false
    IncludePortMapping = $false
    IncludeBindMount = $true
  },
  [pscustomobject]@{
    Name = "hyperv-no-port-mapping"
    Message = "Retrying with hyperv isolation and without port mapping."
    AttemptIsolation = "hyperv"
    UseNoMountEnv = $false
    IncludeResourceLimits = $false
    IncludeIsolation = $true
    IncludeNetwork = $false
    IncludePortMapping = $false
    IncludeBindMount = $true
  },
  [pscustomobject]@{
    Name = "hyperv-no-limits"
    Message = "Retrying with hyperv isolation."
    AttemptIsolation = "hyperv"
    UseNoMountEnv = $false
    IncludeResourceLimits = $false
    IncludeIsolation = $true
    IncludeNetwork = $false
    IncludePortMapping = $true
    IncludeBindMount = $true
  },
  [pscustomobject]@{
    Name = "no-port-and-no-bind-mount"
    Message = "Retrying without port mapping and without bind mount."
    AttemptIsolation = $Isolation
    UseNoMountEnv = $true
    IncludeResourceLimits = $false
    IncludeIsolation = $false
    IncludeNetwork = $false
    IncludePortMapping = $false
    IncludeBindMount = $false
  },
  [pscustomobject]@{
    Name = "no-bind-mount"
    Message = "Retrying without bind mount."
    AttemptIsolation = $Isolation
    UseNoMountEnv = $true
    IncludeResourceLimits = $false
    IncludeIsolation = $false
    IncludeNetwork = $false
    IncludePortMapping = $false
    IncludeBindMount = $false
  },
  [pscustomobject]@{
    Name = "hyperv-no-bind-mount"
    Message = "Retrying with hyperv isolation and no bind mount."
    AttemptIsolation = "hyperv"
    UseNoMountEnv = $true
    IncludeResourceLimits = $false
    IncludeIsolation = $true
    IncludeNetwork = $false
    IncludePortMapping = $false
    IncludeBindMount = $false
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

  $attemptEnvMap = if($attempt.UseNoMountEnv){ $envMapNoMount } else { $envMap }
  $attemptArgs = Build-ContainerRunArgs -name $ContainerName -isolation $attempt.AttemptIsolation -networkName $containerNetwork -hostPort $HostAppPort -hostDataDir $hostDataDir -cpuLimit $cpuLimit -memoryLimit $memLimit -envMap $attemptEnvMap -image $image -IncludeResourceLimits:$attempt.IncludeResourceLimits -IncludeIsolation:$attempt.IncludeIsolation -IncludeNetwork:$attempt.IncludeNetwork -IncludePortMapping:$attempt.IncludePortMapping -IncludeBindMount:$attempt.IncludeBindMount

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
      Remove-ContainerIfExists $ContainerName
      continue
    }
    throw
  }
}

if(-not $runSucceeded){
  throw "docker run failed across all compatibility retries. This host likely does not support one or more required Windows container features (port mapping and/or bind mounts)."
}
if($runSucceededMode -ne "standard"){
  Write-Warning "Container started in compatibility mode '$runSucceededMode'."
}
if($runUsedPortMapping){
  Remove-LocalPortProxy -listenPort $HostAppPort
} else {
  $containerIpViaPortProxy = Get-ContainerIPv4 -name $ContainerName
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
  Write-Host "Container is mapped host 127.0.0.1:$HostAppPort -> container :80 (internal only)"
} else {
  Write-Host "Container port path uses local portproxy 127.0.0.1:$HostAppPort -> ${containerIpViaPortProxy}:80 (internal only)"
}
Write-Host "Settings.yaml downloaded to: $(Join-Path $WorkDir 'Settings.yaml')"
Write-Host "oidc.json injected at: c:\data\oidc.json"
Write-Host "Container env var key list written to: $envListPath"
Write-Host "Customer input state saved to: $customerInputStatePath"
