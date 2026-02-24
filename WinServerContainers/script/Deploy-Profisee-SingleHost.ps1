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
  $existing = Get-HnsNetwork | Where-Object Name -eq "nat" -ErrorAction SilentlyContinue
  if(-not $existing){
    $adapter = (Get-NetAdapter | Where-Object Status -eq "Up" | Select-Object -First 1 -ExpandProperty Name)
    if(-not $adapter){ $adapter = "Ethernet" }

    New-HnsNetwork -Type Nat -AddressPrefix "10.88.0.0/16" -Gateway "10.88.0.1" -Name "nat" | Out-Null

    # cniVersion here is the CNI *spec* version of the config.
    # windows-container-networking releases note support for CNI config 1.0.0, so we use 1.0.0.
@"
{
  "cniVersion": "1.0.0",
  "name": "nat",
  "type": "nat",
  "master": "$adapter",
  "ipam": {
    "subnet": "10.88.0.0/16",
    "routes": [ { "dst": "0.0.0.0/0", "gw": "10.88.0.1" } ]
  },
  "capabilities": { "portMappings": true, "dns": true }
}
"@ | Set-Content -Path "$env:ProgramFiles\containerd\cni\conf\0-containerd-nat.conf" -Encoding ascii -Force
  }
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

function Nerdctl([string[]]$args){
  & "$env:ProgramFiles\nerdctl\nerdctl.exe" @args
  if($LASTEXITCODE -ne 0){ throw "nerdctl failed: $($args -join ' ')" }
}

# ---------------- MAIN ----------------
Ensure-Dir $WorkDir
Install-ContainersFeature
Install-ContainerdAndNerdctl
Install-WindowsNatCni_Latest
Install-NginxStable
Download-SettingsYamlTemplate

# ---- Ask image (no static) ----
Write-Host ""
Write-Host "Profisee image selection"
$acrRegistry = Read-Host "ACR registry [profisee.azurecr.io]"
if([string]::IsNullOrWhiteSpace($acrRegistry)){ $acrRegistry = "profisee.azurecr.io" }

$acrRepo = Read-Host "Repository [profiseeplatform]"
if([string]::IsNullOrWhiteSpace($acrRepo)){ $acrRepo = "profiseeplatform" }

do { $acrTag = Read-Host "Image tag (e.g. 2025r4.0-153319-win22) [REQUIRED]" } while([string]::IsNullOrWhiteSpace($acrTag))

$image = "$acrRegistry/$acrRepo`:$acrTag"

# ---- REQUIRED PEMs (refuse to run without) ----
Write-Host ""
$pemCert = Read-Host "Path to TLS CERT file for nginx (.crt or .pem; PEM-encoded) [REQUIRED]"
$pemKey  = Read-Host "Path to TLS KEY file for nginx (.key or .pem; PEM-encoded) [REQUIRED]"
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
$webAppName = Read-Required "ProfiseeWebAppName (used in URL path: https://FQDN/<ProfiseeWebAppName>)"

try {
  Download-NginxConfTemplate -upstreamPort $HostAppPort -webAppName $webAppName -certFileName $nginxCertFile -keyFileName $nginxKeyFile
} catch {
  Write-Warning "Failed to download nginx.conf from $NginxConfUrl. Falling back to built-in template. Error: $($_.Exception.Message)"
  Write-NginxConf -upstreamPort $HostAppPort -webAppName $webAppName -certFileName $nginxCertFile -keyFileName $nginxKeyFile
}
Start-Nginx

Write-Host ""
$sqlServer = Read-Required "ProfiseeSqlServer (e.g. xxx.database.windows.net)"
$sqlDb     = Read-Required "ProfiseeSqlDatabase"
$sqlUser   = Read-Required "ProfiseeSqlUserName"
$sqlPass   = Read-RequiredSecret "ProfiseeSqlPassword"

Write-Host ""
$repoLocation = Read-Required "ProfiseeAttachmentRepositoryLocation (UNC path, e.g. \\server\share)"
$repoUser     = Read-Required "ProfiseeAttachmentRepositoryUserName"
$repoPass     = Read-RequiredSecret "ProfiseeAttachmentRepositoryUserPassword"
$repoLogon    = Read-Host "ProfiseeAttachmentRepositoryLogonType [NewCredentials]"
if([string]::IsNullOrWhiteSpace($repoLogon)){ $repoLogon = "NewCredentials" }

Write-Host ""
$adminAccount = Read-Required "ProfiseeAdminAccount (email/username)"
$externalUrl  = Read-Required "ProfiseeExternalDNSUrl (e.g. https://something.com)"

Write-Host ""
$oidcProvider = Read-Host "ProfiseeOidcName (Entra/Okta) [Entra]"
if([string]::IsNullOrWhiteSpace($oidcProvider)){ $oidcProvider="Entra" }
$oidcAuthority = Read-Required "ProfiseeOidcAuthority"
$oidcClientId  = Read-Required "ProfiseeOidcClientId"
$oidcSecret    = Read-RequiredSecret "ProfiseeOidcClientSecret"

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
do { $cpuLimit = Read-Host "CPU limit for container (--cpus), e.g. 2 [REQUIRED]" } while([string]::IsNullOrWhiteSpace($cpuLimit))
do { $memLimit = Read-Host "Memory limit for container (--memory), e.g. 8G [REQUIRED]" } while([string]::IsNullOrWhiteSpace($memLimit))

Write-Host ""
Write-Host "ACR login (auth is computed automatically when needed)"
$acrUser = Read-Required "ACR username"
$acrPw   = Read-RequiredSecret "ACR password"
# Computed for Settings.yaml parity/reference (nerdctl login uses --password-stdin).
$acrAuth = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("$acrUser`:$acrPw"))

Write-Host ""
$oidcJsonSource = Read-Host "Path to local OIDC JSON file for c:\data\oidc.json (blank = create {})"

$hostDataDir = Join-Path $WorkDir "data"
Ensure-Dir $hostDataDir
$hostOidcJson = Join-Path $hostDataDir "oidc.json"
if([string]::IsNullOrWhiteSpace($oidcJsonSource)){
  "{}" | Set-Content -Path $hostOidcJson -Encoding utf8 -Force
} else {
  if(-not(Test-Path $oidcJsonSource)){ throw "OIDC JSON file not found: $oidcJsonSource" }
  Copy-Item $oidcJsonSource $hostOidcJson -Force
}

# ---- nerdctl login/pull/run ----
$tmpPass = Join-Path $WorkDir "acrpass.txt"
Set-Content -Path $tmpPass -Value $acrPw -Encoding ascii -Force
Get-Content $tmpPass | & "$env:ProgramFiles\nerdctl\nerdctl.exe" login $acrRegistry -u $acrUser --password-stdin
Remove-Item $tmpPass -Force

Nerdctl @("pull", $image)
try { Nerdctl @("rm","-f",$ContainerName) } catch {}

$envMap = @{
  "ProfiseeAdditionalOpenIdConnectProvidersFile" = "c:\data\oidc.json"
  "ProfiseeAdminAccount"                        = $adminAccount

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

  "ProfiseeSqlDatabase"                         = $sqlDb
  "ProfiseeSqlPassword"                         = $sqlPass
  "ProfiseeSqlServer"                           = $sqlServer
  "ProfiseeSqlUserName"                         = $sqlUser

  "ProfiseeUseWindowsAuthentication"            = "false"
  "ProfiseeWebAppName"                          = $webAppName
}

$envListPath = Join-Path $WorkDir "container-env-vars.txt"
$envMap.Keys | Sort-Object | Set-Content -Path $envListPath -Encoding ascii -Force

$args = @(
  "run","-d",
  "--name",$ContainerName,
  "--isolation",$Isolation,
  "-p","$HostAppPort`:80",
  "--cpus",$cpuLimit,
  "--memory",$memLimit,
  "--mount","type=bind,source=$hostDataDir,destination=c:\data"
)

foreach($k in $envMap.Keys){
  $v = $envMap[$k]; if($null -eq $v){ $v="" }
  $args += @("-e","$k=$v")
}

$args += @($image)
Nerdctl $args

Write-Host ""
Write-Host "DONE."
Write-Host "Access: https://<FQDN>/$webAppName (nginx 443 terminates TLS and proxies to container HTTP)"
Write-Host "nginx redirects: http://<FQDN> -> https://<FQDN>"
Write-Host "Container is mapped host 127.0.0.1:$HostAppPort -> container :80 (internal only)"
Write-Host "Settings.yaml downloaded to: $(Join-Path $WorkDir 'Settings.yaml')"
Write-Host "oidc.json injected at: c:\data\oidc.json"
Write-Host "Container env var key list written to: $envListPath"
