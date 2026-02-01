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

## Stage A - Create a deployment folder

Copy the template folder locally (do not commit):

```powershell
New-Item -ItemType Directory -Path .\customer-deployments\acme-prod
Copy-Item -Recurse -Force .\deployments\_template\* .\customer-deployments\acme-prod\
```

Or use the helper (prompts for key values and writes `config.auto.tfvars.json`):

```powershell
.\scripts\new-deployment.ps1 -DeploymentName acme-prod
```

To skip prompts and only copy the template:

```powershell
.\scripts\new-deployment.ps1 -DeploymentName acme-prod -NoPrompt
```

### Prompt reference (new-deployment.ps1)

Press **Enter** to accept the default value shown in brackets. Lists are
comma‑separated.

- **Primary region**: `us-east-1`
- **us-east-1 region (ACM/CloudFront)**: `us-east-1`
- **Tag: Project**: `my-product`
- **Tag: Environment**: `dev` / `test` / `prod`
- **VPC name**: `my-product`
- **VPC CIDR block**: `10.20.0.0/16`
- **VPC AZs** (comma‑separated): `us-east-1a,us-east-1b,us-east-1c`
- **Public subnet CIDRs**: `10.20.0.0/20,10.20.16.0/20,10.20.32.0/20`
- **Private subnet CIDRs**: `10.20.64.0/20,10.20.80.0/20,10.20.96.0/20`
- **EKS cluster name**: `my-product-eks`
- **EKS cluster version**: `1.29`
- **EKS public endpoint**: `n` (recommended)
- **EKS private endpoint**: `y` (recommended)
- **Linux node instance types**: `m6i.large`
- **Linux node min/max/desired**: `2 / 4 / 2`
- **Windows node instance types**: `m6i.large`
- **Windows node min/max/desired**: `1 / 2 / 1`
- **RDS identifier**: `my-product-sql`
- **RDS SQL Server engine version**: use a valid RDS engine version string (see AWS CLI in docs)
- **RDS instance class**: `db.m6i.large`
- **RDS allocated storage (GB)**: `200`
- **RDS master username**: `dbadmin`
- **RDS publicly accessible**: `n` (recommended)
- **ACM domain name**: `app.example.com`
- **ACM hosted zone ID**: `Z1234567890ABC`
- **Route53 hosted zone ID**: `Z1234567890ABC` (same as ACM)
- **Route53 record name**: `app.example.com`
- **CloudFront enabled (Stage E)**: `n` (Stage C), `y` (Stage E)
- **Route53 enabled (Stage E)**: `n` (Stage C), `y` (Stage E)
- **CloudFront aliases** (when enabled): `app.example.com`
- **CloudFront origin domain (NLB DNS)** (when enabled): `nlb-abc123.us-east-1.elb.amazonaws.com`
- **Jumpbox enabled**: `y`/`n`
- **Jumpbox instance type**: `m6i.large`
- **Jumpbox key pair name (optional, for RDP)**: `profisee-jumpbox-key`
- **Jumpbox public IP**: `n` (recommended)
- **Jumpbox inbound RDP**: `n` (recommended)
- **Jumpbox RDP CIDRs**: `203.0.113.10/32`
- **Jumpbox assume role ARN**: `arn:aws:iam::<ACCOUNT_ID>:role/opentofu-deploy`

After Stage B, `backend.hcl` will be written here. Example content:

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

## Stage B - Bootstrap state backend

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
Push-Location .\bootstrap
tofu init
tofu apply
Pop-Location
```

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

This stage creates an optional **Windows jumpbox** inside the VPC so you can
manage a **private‑only EKS API** and private RDS from a GUI (SSMS, kubectl,
Helm, etc.). It also creates a **jumpbox IAM role**, and can update your **deploy
role trust policy** so the jumpbox can assume that role when you run AWS CLI
commands from the jumpbox.

Example config:

```json
"jumpbox": {
  "enabled": true,
  "instance_type": "m6i.large",
  "key_name": "<your-ec2-keypair-name>",
  "associate_public_ip": false,
  "enable_rdp_ingress": false,
  "allowed_rdp_cidrs": [],
  "assume_role_arn": "arn:aws:iam::<ACCOUNT_ID>:role/opentofu-deploy"
}
```

Notes:
- If you **use RDP**, you must supply `key_name` and keep the **PEM file locally**
  (AWS only lets you download it once when you create the key pair).
- If you **use SSM port forwarding**, you can omit `key_name` entirely.

Create the key pair on‑the‑fly (updates your config automatically):

```powershell
.\scripts\create-jumpbox-key.ps1 -DeploymentName acme-prod
```

Create a key pair (only if you plan to use classic RDP):

```powershell
New-Item -ItemType Directory -Path C:\keys -Force | Out-Null
aws ec2 create-key-pair --region us-east-1 --key-name profisee-jumpbox-key `
  --query "KeyMaterial" --output text | Out-File -FilePath C:\keys\profisee-jumpbox-key.pem -Encoding ascii
```

Then set:

```json
"key_name": "profisee-jumpbox-key"
```

Apply (if not already):

```powershell
# IMPORTANT: Replace 'opentofu-deploy' with your actual deploy role name.
.\scripts\tofu-apply.ps1 -DeploymentName acme-prod -DeployRoleName opentofu-deploy
```

Auto‑add the jumpbox role to the deploy role trust policy (runs automatically
after `tofu-apply.ps1` if the jumpbox is enabled):

```powershell
# IMPORTANT: Replace 'opentofu-deploy' with your actual deploy role name.
.\scripts\tofu-apply.ps1 -DeploymentName acme-prod -DeployRoleName opentofu-deploy
```

If you want to run the trust update manually:

```powershell
# IMPORTANT: Replace 'opentofu-deploy' with your actual deploy role name.
.\scripts\add-jumpbox-trust.ps1 -DeploymentName acme-prod -DeployRoleName opentofu-deploy
```

## Stage D - Platform (Kubernetes)

Deploy the Kubernetes layer (Traefik/NLB, addons, app). This creates the public
NLB DNS name that CloudFront needs as an origin.

**Private access is the default** (EKS API private‑only). Run kubectl/Helm from
inside the VPC (jumpbox/bastion) or through a VPN/Direct Connect connection.
For a jumpbox with no inbound RDP, use SSM port forwarding:
[SSM RDP via port forwarding](./ssm-rdp.md).

Example (replace with your scripts when ready):

```powershell
.\scripts\kubeconfig.ps1 -DeploymentName acme-prod
.\scripts\deploy-platform.ps1 -DeploymentName acme-prod
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
