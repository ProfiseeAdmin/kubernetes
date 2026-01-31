param(
  [Parameter(Mandatory = $false)]
  [string]$RepoRoot = "C:\GitRepoPaaS\ProfiseeAdmin\kubernetes\AWS-OpenTofu"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Ensure-Dir([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -ItemType Directory -Path $Path | Out-Null
    Write-Host "Created dir : $Path"
  } else {
    Write-Host "Exists dir  : $Path"
  }
}

function Ensure-File([string]$Path, [string]$Content = "") {
  if (-not (Test-Path -LiteralPath $Path)) {
    $parent = Split-Path -Parent $Path
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
      Ensure-Dir $parent
    }
    New-Item -ItemType File -Path $Path | Out-Null
    if ($Content -ne $null -and $Content.Length -gt 0) {
      Set-Content -Path $Path -Value $Content -Encoding UTF8
    }
    Write-Host "Created file: $Path"
  } else {
    Write-Host "Exists file : $Path"
  }
}

Write-Host ""
Write-Host "Initializing repo structure at:"
Write-Host "  $RepoRoot"
Write-Host ""

Ensure-Dir $RepoRoot

# -----------------------
# Directories
# -----------------------
$dirs = @(
  "docs",
  "bootstrap",
  "bootstrap\templates",

  "infra",
  "infra\modules",
  "infra\modules\vpc",
  "infra\modules\eks",
  "infra\modules\rds_sqlserver",
  "infra\modules\kms",
  "infra\modules\secrets",
  "infra\modules\acm_use1",
  "infra\modules\cloudfront",
  "infra\modules\route53",
  "infra\modules\outputs_contract",
  "infra\root",

  "platform",
  "platform\helm",
  "platform\helm\addons",
  "platform\helm\traefik",
  "platform\helm\app",
  "platform\helm\app\templates",
  "platform\manifests",

  "scripts",

  "deployments",
  "deployments\_template",
  "deployments\example-minimal",

  ".github",
  ".github\workflows-disabled"
)

foreach ($d in $dirs) {
  Ensure-Dir (Join-Path $RepoRoot $d)
}

# -----------------------
# Root files
# -----------------------
$gitignore = @"
# OpenTofu / Terraform dirs
**/.terraform/**
**/.tofu/**

# State files
*.tfstate
*.tfstate.*
crash.log

# Customer deployment folders (customer-specific + secrets)
customer-deployments/**
**/secrets/**
*.lic

# kube / helm
kubeconfig
"@

Ensure-File (Join-Path $RepoRoot "README.md") @"
# AWS-OpenTofu

Customer-run installer repo (OpenTofu + Helm) for deploying the product into a customer's AWS account.

See docs/02-quickstart-local.md for the end-to-end flow.
"@

Ensure-File (Join-Path $RepoRoot "CHANGELOG.md") "# Changelog`r`n"
Ensure-File (Join-Path $RepoRoot "LICENSE") "TODO: Add license text here.`r`n"
Ensure-File (Join-Path $RepoRoot ".gitignore") $gitignore

# -----------------------
# docs/*
# -----------------------
$docFiles = @(
  "docs\00-overview.md",
  "docs\01-prereqs.md",
  "docs\02-quickstart-local.md",
  "docs\03-quickstart-github-actions.md",
  "docs\04-configuration-reference.md",
  "docs\05-security-notes.md",
  "docs\06-operations-upgrade-rollback.md",
  "docs\07-uninstall.md"
)

foreach ($f in $docFiles) {
  Ensure-File (Join-Path $RepoRoot $f) "# TODO`r`n"
}

# -----------------------
# bootstrap/*
# -----------------------
Ensure-File (Join-Path $RepoRoot "bootstrap\main.tf") "// TODO: bootstrap resources (KMS, S3 state bucket, DynamoDB lock, optional IAM role)`r`n"
Ensure-File (Join-Path $RepoRoot "bootstrap\variables.tf") "// TODO: bootstrap variables`r`n"
Ensure-File (Join-Path $RepoRoot "bootstrap\outputs.tf") "// TODO: bootstrap outputs (backend config values, key ARNs, etc.)`r`n"
Ensure-File (Join-Path $RepoRoot "bootstrap\versions.tf") "// TODO: required_version + provider pins`r`n"
Ensure-File (Join-Path $RepoRoot "bootstrap\templates\backend.hcl.tmpl") @"
bucket         = "<STATE_BUCKET>"
key            = "<STATE_KEY>"
region         = "<REGION>"
dynamodb_table = "<LOCK_TABLE>"
encrypt        = true
"@

# -----------------------
# infra/modules/* (placeholder files)
# -----------------------
$moduleNames = @(
  "vpc","eks","rds_sqlserver","kms","secrets","acm_use1","cloudfront","route53","outputs_contract"
)

foreach ($m in $moduleNames) {
  Ensure-File (Join-Path $RepoRoot "infra\modules\$m\main.tf") "// TODO: module $m`r`n"
  Ensure-File (Join-Path $RepoRoot "infra\modules\$m\variables.tf") "// TODO: variables for $m`r`n"
  Ensure-File (Join-Path $RepoRoot "infra\modules\$m\outputs.tf") "// TODO: outputs for $m`r`n"
  Ensure-File (Join-Path $RepoRoot "infra\modules\$m\versions.tf") "// TODO: provider pins for $m`r`n"
}

# -----------------------
# infra/root/*
# -----------------------
Ensure-File (Join-Path $RepoRoot "infra\root\main.tf") "// TODO: wire modules together`r`n"
Ensure-File (Join-Path $RepoRoot "infra\root\providers.tf") "// TODO: aws provider + aws.use1 provider`r`n"
Ensure-File (Join-Path $RepoRoot "infra\root\variables.tf") "// TODO: root inputs`r`n"
Ensure-File (Join-Path $RepoRoot "infra\root\outputs.tf") "// TODO: root outputs (cluster name, distro domain, secret names, etc.)`r`n"
Ensure-File (Join-Path $RepoRoot "infra\root\versions.tf") "// TODO: required_version + provider pins`r`n"

# -----------------------
# platform/*
# -----------------------
Ensure-File (Join-Path $RepoRoot "platform\helm\addons\aws-load-balancer-controller.values.yaml") "# TODO`r`n"
Ensure-File (Join-Path $RepoRoot "platform\helm\addons\cert-manager.values.yaml") "# TODO`r`n"
Ensure-File (Join-Path $RepoRoot "platform\helm\addons\secrets-store-csi.values.yaml") "# TODO`r`n"
Ensure-File (Join-Path $RepoRoot "platform\helm\addons\external-secrets.values.yaml") "# TODO`r`n"

Ensure-File (Join-Path $RepoRoot "platform\helm\traefik\values.yaml") "# TODO`r`n"
Ensure-File (Join-Path $RepoRoot "platform\helm\traefik\values-cloudfront.yaml") "# TODO: NLB public + CloudFront lock-down annotations`r`n"

Ensure-File (Join-Path $RepoRoot "platform\helm\app\Chart.yaml") @"
apiVersion: v2
name: app
version: 0.1.0
"@
Ensure-File (Join-Path $RepoRoot "platform\helm\app\values.yaml") "# TODO`r`n"

Ensure-File (Join-Path $RepoRoot "platform\manifests\traefik-origin-guard.yaml") "# TODO: Traefik routing rule requiring X-Origin-Verify header`r`n"

# -----------------------
# scripts/*
# -----------------------
$scriptFiles = @(
  "scripts\new-deployment.ps1",
  "scripts\bootstrap.ps1",
  "scripts\tofu-plan.ps1",
  "scripts\tofu-apply.ps1",
  "scripts\tofu-destroy.ps1",
  "scripts\seed-secrets.ps1",
  "scripts\kubeconfig.ps1",
  "scripts\deploy-platform.ps1",
  "scripts\verify.ps1"
)
foreach ($sf in $scriptFiles) {
  Ensure-File (Join-Path $RepoRoot $sf) "# TODO`r`n"
}

# -----------------------
# deployments/*
# -----------------------
Ensure-File (Join-Path $RepoRoot "deployments\_template\backend.hcl.example") "# TODO`r`n"
Ensure-File (Join-Path $RepoRoot "deployments\_template\config.auto.tfvars.json.example") "{`r`n  // TODO`r`n}`r`n"
Ensure-File (Join-Path $RepoRoot "deployments\_template\README.md") "# Template deployment folder`r`n"

Ensure-File (Join-Path $RepoRoot "deployments\example-minimal\backend.hcl.example") "# TODO`r`n"
Ensure-File (Join-Path $RepoRoot "deployments\example-minimal\config.auto.tfvars.json.example") "{`r`n  // TODO`r`n}`r`n"
Ensure-File (Join-Path $RepoRoot "deployments\example-minimal\README.md") "# Example minimal (non-secret) config`r`n"

# -----------------------
# .github/workflows-disabled/*
# -----------------------
Ensure-File (Join-Path $RepoRoot ".github\workflows-disabled\plan.yml.example") "# TODO`r`n"
Ensure-File (Join-Path $RepoRoot ".github\workflows-disabled\apply.yml.example") "# TODO`r`n"
Ensure-File (Join-Path $RepoRoot ".github\workflows-disabled\deploy.yml.example") "# TODO`r`n"

Write-Host ""
Write-Host "Done. Repo skeleton created (no secrets)."
Write-Host ""
Write-Host "Next: we can build the first real files starting with bootstrap/ and infra/root/."
