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
  @{ Remote = "infra/FullyPrivateEKS.yaml"; Local = "FullyPrivateEKS.yaml" },
  @{ Remote = "scripts/deployprofisee-aws.ps1"; Local = "deployprofisee-aws.ps1" },
  @{ Remote = "scripts/deployprofisee-aws-stack.ps1"; Local = "deployprofisee-aws-stack.ps1" },
  @{ Remote = "values/Settings-aws.yaml"; Local = "Settings-aws.yaml" },
  @{ Remote = "values/traefik-values.yaml"; Local = "traefik-values.yaml" },
  @{ Remote = "values/traefik-values-public.yaml"; Local = "traefik-values-public.yaml" }
)

$optionalFiles = @(
  @{ Remote = "values/smb-csi-values.yaml"; Local = "smb-csi-values.yaml" },
  @{ Remote = "manifests/smb-secret.yaml"; Local = "smb-secret.yaml" },
  @{ Remote = "manifests/smb-storageclass.yaml"; Local = "smb-storageclass.yaml" },
  @{ Remote = "manifests/smb-pvc.yaml"; Local = "smb-pvc.yaml" },
  @{ Remote = "manifests/profisee-ingress.yaml"; Local = "profisee-ingress.yaml" },
  @{ Remote = "manifests/cert-manager-route53-issuer.yaml"; Local = "cert-manager-route53-issuer.yaml" },
  @{ Remote = "manifests/cert-manager-certificate.yaml"; Local = "cert-manager-certificate.yaml" },
  @{ Remote = "manifests/route53-credentials-secret.yaml"; Local = "route53-credentials-secret.yaml" },
  @{ Remote = "examples/secretsmanager-cert.example.json"; Local = "secretsmanager-cert.example.json" }
)

if (-not (Test-Path $OutputDir)) {
  New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

function Download-File {
  param([string]$RemotePath, [string]$LocalName)
  $uri = "$baseRaw/$RemotePath"
  $dest = Join-Path $OutputDir $LocalName
  Write-Host "Downloading $uri -> $dest"
  Invoke-WebRequest -Uri $uri -OutFile $dest
}

$coreFiles | ForEach-Object { Download-File $_.Remote $_.Local }

if ($IncludeOptional) {
  $optionalFiles | ForEach-Object { Download-File $_.Remote $_.Local }
}

Write-Host "Download complete."
