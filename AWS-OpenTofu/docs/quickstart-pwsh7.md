# Quickstart (PowerShell 7)

## 1) Install tools (Git + AWS CLI + OpenTofu)

```powershell
winget install --id Git.Git -e
winget install --id Amazon.AWSCLI -e
winget install --id OpenTofu.Tofu -e
```

## 2) Create backend + deploy role

Use your AWS account ID in trusted principal ARN.

```powershell
.\scripts\bootstrap.ps1 `
  -Region us-east-1 `
  -StateBucketName <globally-unique-state-bucket> `
  -CreateDeployRole `
  -DeployRoleName profisee-opentofu-deploy `
  -DeployRoleTrustedPrincipalArns arn:aws:iam::<ACCOUNT_ID>:root `
  -DeployRolePolicyArns arn:aws:iam::aws:policy/AdministratorAccess `
  -BackendOutPath .\customer-deployments\acme-prod\backend.hcl `
  -AutoApprove
```

## 3) Set AWS role/profile for deployment

```powershell
aws configure set profile.profisee-deploy.role_arn arn:aws:iam::<ACCOUNT_ID>:role/profisee-opentofu-deploy
aws configure set profile.profisee-deploy.source_profile default
$env:AWS_PROFILE = "profisee-deploy"
```

## 4) Collect deployment info + seed secrets

```powershell
.\scripts\new-deployment.ps1 -DeploymentName acme-prod
```

## 5) Deploy / update

```powershell
.\scripts\tofu-apply.ps1 -DeploymentName acme-prod -AutoApprove
```

When `cloudfront.enabled` is `true`, this apply flow auto-wires CloudFront origin to the NGINX OSS ingress NLB DNS and runs the edge apply in the same command.

## 6) Destroy

```powershell
.\scripts\tofu-destroy.ps1 -DeploymentName acme-prod -AutoApprove
```
