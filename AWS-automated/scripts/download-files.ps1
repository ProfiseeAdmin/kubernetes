param(
  [string]$RepoOwner,
  [string]$RepoName,
  [string]$RepoPath,
  [string]$Branch,
  [string]$OutputDir = ".",
  [switch]$IncludeOptional
)

if ([string]::IsNullOrWhiteSpace($RepoOwner)) { throw "RepoOwner is required." }
if ([string]::IsNullOrWhiteSpace($RepoName)) { throw "RepoName is required." }
if ([string]::IsNullOrWhiteSpace($RepoPath)) { throw "RepoPath is required." }
if ([string]::IsNullOrWhiteSpace($Branch)) { throw "Branch is required." }

$baseRaw = "https://raw.githubusercontent.com/$RepoOwner/$RepoName/$Branch/$RepoPath"

$coreFiles = @(
  "FullyPrivateEKS.yaml",
  "deployprofisee-aws.ps1",
  "deployprofisee-aws-stack.ps1",
  "Settings-aws.yaml",
  "traefik-values.yaml",
  "traefik-values-public.yaml"
)

$optionalFiles = @(
  "smb-csi-values.yaml",
  "smb-secret.yaml",
  "smb-storageclass.yaml",
  "smb-pvc.yaml",
  "profisee-ingress.yaml",
  "cert-manager-route53-issuer.yaml",
  "cert-manager-certificate.yaml",
  "route53-credentials-secret.yaml",
  "secretsmanager-cert.example.json"
)

if (-not (Test-Path $OutputDir)) {
  New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

function Download-File {
  param([string]$FileName)
  $uri = "$baseRaw/$FileName"
  $dest = Join-Path $OutputDir $FileName
  Write-Host "Downloading $uri -> $dest"
  Invoke-WebRequest -Uri $uri -OutFile $dest
}

$coreFiles | ForEach-Object { Download-File $_ }

if ($IncludeOptional) {
  $optionalFiles | ForEach-Object { Download-File $_ }
}

Write-Host "Download complete."
