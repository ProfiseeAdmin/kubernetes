# Quickstart (Local)

This guide walks a customer through a staged, local deployment from a fresh AWS
account. It keeps secrets out of Git and out of OpenTofu state.

## Where to run each step

- **AWS CloudShell**: create the deploy role (one‑liner) and capture its ARN.
- **Customer Windows workstation**: run OpenTofu (bootstrap + infra).
- **Jumpbox (optional)**: run kubectl/Helm if the EKS API is private‑only.

## Prereqs

- AWS account with permissions to create VPC, EKS, RDS, ACM, CloudFront, Route53
- A public Route53 hosted zone (or delegated subdomain) for your hostname
- OpenTofu, AWS CLI, kubectl, and Helm installed

## Stage A - Bootstrap state backend

### Step 1 - Create the deploy role (CloudShell)

Create a dedicated IAM role in the customer account (example name:
`opentofu-deploy`) and attach the permissions needed for bootstrap and infra.

For initial proof/testing, attach `AdministratorAccess`. Later, replace it with
least‑privilege policies.

Suggested steps in IAM:
1. IAM → Roles → Create role
2. Trusted entity: AWS account (this account)
3. Add a trust relationship for your IAM user or SSO role that will run OpenTofu
4. Attach `AdministratorAccess` (for proof/testing)
5. Name the role `opentofu-deploy`

CloudShell one‑liner (admin user/role):

```bash
ROLE_NAME=opentofu-deploy; ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text); aws iam get-role --role-name $ROLE_NAME >/dev/null 2>&1 || aws iam create-role --role-name $ROLE_NAME --assume-role-policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::${ACCOUNT_ID}:root\"},\"Action\":\"sts:AssumeRole\"}]}"; aws iam attach-role-policy --role-name $ROLE_NAME --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

For production, replace the root principal with the specific IAM user/role that
will run OpenTofu.

Get the role ARN:

```bash
aws iam get-role --role-name opentofu-deploy --query Role.Arn --output text
```

Then configure your CLI to assume the role:

```ini
# ~/.aws/config
[profile opentofu-deploy]
role_arn = arn:aws:iam::<ACCOUNT_ID>:role/opentofu-deploy
source_profile = default
region = us-east-1
```

Run subsequent commands with:

```powershell
$env:AWS_PROFILE = "opentofu-deploy"
```

### Step 1a - Assume the role (Windows CMD)

Option A (recommended): configure a profile and set `AWS_PROFILE`.

```cmd
aws configure set role_arn arn:aws:iam::<ACCOUNT_ID>:role/opentofu-deploy --profile opentofu-deploy
aws configure set source_profile default --profile opentofu-deploy
aws configure set region us-east-1 --profile opentofu-deploy
set AWS_PROFILE=opentofu-deploy
```

Option B: assume role and export temporary credentials (CMD).

```cmd
for /f "tokens=1,2,3" %a in ('aws sts assume-role --role-arn arn:aws:iam::<ACCOUNT_ID>:role/opentofu-deploy --role-session-name opentofu-cli --query "Credentials.[AccessKeyId,SecretAccessKey,SessionToken]" --output text') do (set AWS_ACCESS_KEY_ID=%a & set AWS_SECRET_ACCESS_KEY=%b & set AWS_SESSION_TOKEN=%c)
```

Note: in a `.bat` file, double the percent signs (`%%a`, `%%b`, `%%c`).

### Shell shortcuts

- If you are using **CMD**, click here: [Assume role (CMD)](#assume-role-cmd).
- If you are using **PowerShell**, click here: [Assume role (PowerShell)](#assume-role-powershell).
- If you are using **Git Bash**, click here: [Assume role (Git Bash)](#assume-role-git-bash).

### Assume role (CMD)

Profile + `AWS_PROFILE` (recommended):

```cmd
aws configure set role_arn arn:aws:iam::<ACCOUNT_ID>:role/opentofu-deploy --profile opentofu-deploy
aws configure set source_profile default --profile opentofu-deploy
aws configure set region us-east-1 --profile opentofu-deploy
set AWS_PROFILE=opentofu-deploy
```

Temporary creds (one‑liner):

```cmd
for /f "tokens=1,2,3" %a in ('aws sts assume-role --role-arn arn:aws:iam::<ACCOUNT_ID>:role/opentofu-deploy --role-session-name opentofu-cli --query "Credentials.[AccessKeyId,SecretAccessKey,SessionToken]" --output text') do (set AWS_ACCESS_KEY_ID=%a & set AWS_SECRET_ACCESS_KEY=%b & set AWS_SESSION_TOKEN=%c)
```

### Assume role (PowerShell)

Profile + `AWS_PROFILE` (recommended):

```powershell
aws configure set role_arn arn:aws:iam::<ACCOUNT_ID>:role/opentofu-deploy --profile opentofu-deploy
aws configure set source_profile default --profile opentofu-deploy
aws configure set region us-east-1 --profile opentofu-deploy
$env:AWS_PROFILE = "opentofu-deploy"
```

Temporary creds:

```powershell
$creds = aws sts assume-role --role-arn arn:aws:iam::<ACCOUNT_ID>:role/opentofu-deploy --role-session-name opentofu-cli --query "Credentials.[AccessKeyId,SecretAccessKey,SessionToken]" --output text
$parts = $creds -split "\s+"
$env:AWS_ACCESS_KEY_ID = $parts[0]
$env:AWS_SECRET_ACCESS_KEY = $parts[1]
$env:AWS_SESSION_TOKEN = $parts[2]
```

### Assume role (Git Bash)

Profile + `AWS_PROFILE` (recommended):

```bash
aws configure set role_arn arn:aws:iam::<ACCOUNT_ID>:role/opentofu-deploy --profile opentofu-deploy
aws configure set source_profile default --profile opentofu-deploy
aws configure set region us-east-1 --profile opentofu-deploy
export AWS_PROFILE=opentofu-deploy
```

Temporary creds (one‑liner):

```bash
read AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN < <(aws sts assume-role --role-arn arn:aws:iam::<ACCOUNT_ID>:role/opentofu-deploy --role-session-name opentofu-cli --query "Credentials.[AccessKeyId,SecretAccessKey,SessionToken]" --output text)
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
```

Note: `scripts/bootstrap.ps1` can optionally create a deploy role if you pass
`-CreateDeployRole` and related inputs, but you still need initial credentials
with permissions to create IAM roles.

From repo root:

```powershell
cd <path-to-repo>
```

Edit or provide values for:
- `region`
- `state_bucket_name` (globally unique)
- `state_lock_table_name` (optional override)

Then (recommended):

```powershell
.\scripts\bootstrap.ps1 `
  -Region us-east-1 `
  -StateBucketName my-unique-state-bucket `
  -BackendOutPath .\customer-deployments\acme-prod\backend.hcl `
  -AutoApprove
```

Or run OpenTofu directly:

```powershell
tofu -chdir=bootstrap init
tofu -chdir=bootstrap apply
```

Copy the `backend_hcl` output into your deployment folder later.

## Stage B - Create a deployment folder

Copy the template folder locally (do not commit):

```powershell
New-Item -ItemType Directory -Path .\customer-deployments\acme-prod
Copy-Item -Recurse -Force .\deployments\_template\* .\customer-deployments\acme-prod\
```

Create `backend.hcl` from the bootstrap outputs (example):

```hcl
bucket         = "my-state-bucket"
key            = "infra/acme-prod.tfstate"
region         = "us-east-1"
dynamodb_table = "opentofu-state-locks"
encrypt        = true
kms_key_id     = "arn:aws:kms:us-east-1:123456789012:key/..."
```

Edit `customer-deployments/acme-prod/config.auto.tfvars.json` using
`deployments/_template/config.auto.tfvars.json.example` as a baseline.

## Stage C - Core infra (VPC + EKS + RDS + ACM)

Disable CloudFront and Route53 for this stage:

```json
"cloudfront": { "enabled": false },
"route53": { "enabled": false }
```

Then:

```powershell
.\scripts\tofu-plan.ps1 -DeploymentName acme-prod
.\scripts\tofu-apply.ps1 -DeploymentName acme-prod -DeployRoleName opentofu-deploy
```

## Stage C.1 - Jumpbox (optional, GUI access)

If you want a Windows jumpbox for GUI management (SSMS, kubectl, Helm), enable
it before or during Stage C and re-apply infra.

Example config:

```json
"jumpbox": {
  "enabled": true,
  "instance_type": "m6i.large",
  "associate_public_ip": false,
  "enable_rdp_ingress": false,
  "allowed_rdp_cidrs": [],
  "assume_role_arn": "arn:aws:iam::<ACCOUNT_ID>:role/opentofu-deploy"
}
```

Apply (if not already):

```powershell
.\scripts\tofu-apply.ps1 -DeploymentName acme-prod -DeployRoleName opentofu-deploy
```

Auto‑add the jumpbox role to the deploy role trust policy (runs automatically
after `tofu-apply.ps1` if the jumpbox is enabled):

```powershell
.\scripts\tofu-apply.ps1 -DeploymentName acme-prod -DeployRoleName opentofu-deploy
```

## Stage D - Platform (Kubernetes)

Deploy the Kubernetes layer (Traefik/NLB, addons, app). This creates the public
NLB DNS name that CloudFront needs as an origin.

If the EKS API endpoint is private‑only (recommended), run kubectl/Helm from
inside the VPC (jumpbox/bastion) or through a VPN/Direct Connect connection.

Optional: enable a Windows jumpbox (GUI) for management tasks. Example:

```json
"jumpbox": {
  "enabled": true,
  "instance_type": "m6i.large",
  "associate_public_ip": false,
  "enable_rdp_ingress": false,
  "allowed_rdp_cidrs": [],
  "assume_role_arn": "arn:aws:iam::<ACCOUNT_ID>:role/opentofu-deploy"
}
```

For private access, connect via SSM port forwarding (no inbound 3389). You can
also use Fleet Manager Remote Desktop if enabled in your account.
See docs/ssm-rdp.md for step-by-step instructions.

Example (replace with your scripts when ready):

```powershell
.\scripts\kubeconfig.ps1 acme-prod
.\scripts\deploy-platform.ps1 acme-prod
```

Capture the NLB DNS name.

## Stage E - Edge (CloudFront + Route53)

Enable CloudFront and Route53, then set the origin domain name and alias:

```json
"cloudfront": {
  "enabled": true,
  "origin_domain_name": "nlb-abc123.us-east-1.elb.amazonaws.com",
  "aliases": ["app.example.com"],
  "origin_custom_headers": {}
},
"route53": {
  "enabled": true,
  "hosted_zone_id": "Z1234567890ABC",
  "record_name": "app.example.com"
}
```

Re-apply infra:

```powershell
.\scripts\tofu-apply.ps1 -DeploymentName acme-prod -DeployRoleName opentofu-deploy
```

## Validate

- CloudFront distribution status is Deployed.
- DNS resolves your hostname to the CloudFront distribution.
- HTTPS works on the hostname.
- WebSocket upgrade returns 101 Switching Protocols through CloudFront (use your app client).

## Important notes

- Do not put secrets (license, origin header secret, DB password) in OpenTofu
  variables or state. Use AWS Secrets Manager and mount secrets in the cluster.
- If you need an origin guard header, set it out-of-band and do not store it in
  Terraform/OpenTofu state.

