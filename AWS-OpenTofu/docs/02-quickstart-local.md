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

## Stage A - AWS credentials + bootstrap state backend

### Step 1 - Create the deploy role (CloudShell)

Create a dedicated IAM role in the customer account (example name:
`opentofu-deploy`, or your custom role name) and attach the permissions needed for bootstrap and infra.

For initial proof/testing, attach `AdministratorAccess`. Later, replace it with
least‑privilege policies.

If you use a **custom role name**, replace `opentofu-deploy` everywhere below
and pass `-DeployRoleName <your-role-name>` when running scripts.

Suggested steps in IAM:
1. IAM → Roles → Create role
2. Trusted entity: AWS account (this account)
3. Add a trust relationship for your IAM user or SSO role that will run OpenTofu
4. Attach `AdministratorAccess` (for proof/testing)
5. Name the role `opentofu-deploy` (or your custom role name)

CloudShell one‑liner (admin user/role):

```bash
# Replace ROLE_NAME if you used a custom role name.
ROLE_NAME=opentofu-deploy; ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text); aws iam get-role --role-name $ROLE_NAME >/dev/null 2>&1 || aws iam create-role --role-name $ROLE_NAME --assume-role-policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::${ACCOUNT_ID}:root\"},\"Action\":\"sts:AssumeRole\"}]}"; aws iam attach-role-policy --role-name $ROLE_NAME --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

For production, replace the root principal with the specific IAM user/role that
will run OpenTofu.

Get the role ARN:

```bash
# Replace opentofu-deploy if you used a custom role name.
aws iam get-role --role-name opentofu-deploy --query Role.Arn --output text
```

Then configure your CLI to assume the role:

```ini
# Replace opentofu-deploy if you used a custom role name.
# ~/.aws/config
[profile opentofu-deploy]
role_arn = arn:aws:iam::<ACCOUNT_ID>:role/opentofu-deploy
source_profile = default
region = us-east-1
```

Run subsequent commands with:

```powershell
# Replace opentofu-deploy if you used a custom role name.
$env:AWS_PROFILE = "opentofu-deploy"
```

### Step 1a - Assume the role (Windows CMD)

Option A (recommended): configure a profile and set `AWS_PROFILE`.

```cmd
REM Replace opentofu-deploy if you used a custom role name.
aws configure set role_arn arn:aws:iam::<ACCOUNT_ID>:role/opentofu-deploy --profile opentofu-deploy
aws configure set source_profile default --profile opentofu-deploy
aws configure set region us-east-1 --profile opentofu-deploy
set AWS_PROFILE=opentofu-deploy
```

Option B: assume role and export temporary credentials (CMD).

```cmd
REM Replace opentofu-deploy if you used a custom role name.
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
REM Replace opentofu-deploy if you used a custom role name.
aws configure set role_arn arn:aws:iam::<ACCOUNT_ID>:role/opentofu-deploy --profile opentofu-deploy
aws configure set source_profile default --profile opentofu-deploy
aws configure set region us-east-1 --profile opentofu-deploy
set AWS_PROFILE=opentofu-deploy
```

Temporary creds (one‑liner):

```cmd
REM Replace opentofu-deploy if you used a custom role name.
for /f "tokens=1,2,3" %a in ('aws sts assume-role --role-arn arn:aws:iam::<ACCOUNT_ID>:role/opentofu-deploy --role-session-name opentofu-cli --query "Credentials.[AccessKeyId,SecretAccessKey,SessionToken]" --output text') do (set AWS_ACCESS_KEY_ID=%a & set AWS_SECRET_ACCESS_KEY=%b & set AWS_SESSION_TOKEN=%c)
```

### Assume role (PowerShell)

Profile + `AWS_PROFILE` (recommended):

```powershell
# Replace opentofu-deploy if you used a custom role name.
aws configure set role_arn arn:aws:iam::<ACCOUNT_ID>:role/opentofu-deploy --profile opentofu-deploy
aws configure set source_profile default --profile opentofu-deploy
aws configure set region us-east-1 --profile opentofu-deploy
$env:AWS_PROFILE = "opentofu-deploy"
```

Temporary creds:

```powershell
# Replace opentofu-deploy if you used a custom role name.
$creds = aws sts assume-role --role-arn arn:aws:iam::<ACCOUNT_ID>:role/opentofu-deploy --role-session-name opentofu-cli --query "Credentials.[AccessKeyId,SecretAccessKey,SessionToken]" --output text
$parts = $creds -split "\s+"
$env:AWS_ACCESS_KEY_ID = $parts[0]
$env:AWS_SECRET_ACCESS_KEY = $parts[1]
$env:AWS_SESSION_TOKEN = $parts[2]
```

### Assume role (Git Bash)

Profile + `AWS_PROFILE` (recommended):

```bash
# Replace opentofu-deploy if you used a custom role name.
aws configure set role_arn arn:aws:iam::<ACCOUNT_ID>:role/opentofu-deploy --profile opentofu-deploy
aws configure set source_profile default --profile opentofu-deploy
aws configure set region us-east-1 --profile opentofu-deploy
export AWS_PROFILE=opentofu-deploy
```

Temporary creds (one‑liner):

```bash
# Replace opentofu-deploy if you used a custom role name.
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

After Stage A, `backend.hcl` will be written here. Example content:

```hcl
bucket         = "my-state-bucket"
key            = "infra/acme-prod.tfstate"
region         = "us-east-1"
dynamodb_table = "opentofu-state-locks"
encrypt        = true
kms_key_id     = "arn:aws:kms:us-east-1:123456789012:key/..."
```

## Stage B - Clone repo + create a deployment folder

Before running `new-deployment.ps1`, make sure Stage A is complete and your
AWS CLI credentials are set (admin or your deploy role). This script now
**seeds Secrets Manager** automatically.

Clone the repo locally:

```powershell
git clone <repo-url>
cd <repo-folder>
```

Copy the template folder locally (do not commit):

```powershell
New-Item -ItemType Directory -Path .\customer-deployments\acme-prod
Copy-Item -Recurse -Force .\deployments\_template\* .\customer-deployments\acme-prod\
```

Or use the helper (prompts for key values and writes `config.auto.tfvars.json`):

```powershell
.\scripts\new-deployment.ps1 -DeploymentName acme-prod
```

If you want the settings bucket to be auto‑emptied on destroy (recommended for
test runs), add:

```powershell
.\scripts\new-deployment.ps1 -DeploymentName acme-prod -ForceDestroySettingsBucket
```

`new-deployment.ps1` will **always seed Secrets Manager** at the end
(recommended) so the DB init task has the secret ARNs it needs. This requires
valid AWS CLI credentials (admin or your deploy role).

Review `customer-deployments/acme-prod/config.auto.tfvars.json` (based on
`deployments/_template/config.auto.tfvars.json.example`) before continuing.

To skip prompts and only copy the template:

```powershell
.\scripts\new-deployment.ps1 -DeploymentName acme-prod -NoPrompt
```

If you run with `-NoPrompt`, you must provide
`customer-deployments/<name>/secrets/seed-secrets.json` before seeding.

License file:
- Place your license at `customer-deployments/<name>/secrets/license.txt`.
- `new-deployment.ps1` will **not** inject it into `Settings.yaml`. It keeps
  placeholders and writes a `secrets/seed-secrets.json` file so you can seed
  Secrets Manager later.

`new-deployment.ps1` also downloads `Settings.yaml` from the Azure-ARM base and
fills **non‑secret** app settings. It keeps placeholders for secrets
(license, ACR creds, OIDC client details, TLS cert/key, app SQL creds), and
writes them to `secrets/seed-secrets.json`. After `tofu-apply`, the script will
update `Settings.yaml` with the RDS endpoint and the app EBS volume ID.

Stage B collects **two categories** of input:
- **Infra** (VPC/EKS/RDS/ACM/Route53/CloudFront/jumpbox)
- **Profisee app config** (OIDC, admin email, ACR creds, TLS choice, etc.)

### Prompt reference (new-deployment.ps1)

Press **Enter** to accept the default value shown in brackets. Lists are
comma‑separated.

- **Primary region**: `us-east-1`
- **us-east-1 region (ACM/CloudFront)**: `us-east-1`
- **Tag: Project**: `my-product`
- **Tag: Environment**: `dev` / `test` / `prod`
- **App Settings S3 bucket name**: `my-unique-settings-bucket`
- **App Settings bucket force destroy**: `y` (default). Use `-ForceDestroySettingsBucket` to force‑enable.
- **App Settings bucket KMS key ARN (optional)**: leave blank to use SSE-S3
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
- **App database name** (created by db_init; not the RDS initial DB): `Profisee`
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
- **Jumpbox assume role ARN**: `arn:aws:iam::<ACCOUNT_ID>:role/opentofu-deploy` (replace with your role name if different)

After the infra prompts, the script will also ask for **app settings**
(OIDC provider, ACR credentials, admin account, app SQL creds, etc.). These
values are written to `secrets/seed-secrets.json` and **not** injected into
`Settings.yaml`.

App settings prompts (stored in `secrets/seed-secrets.json`):
- **SQL Server endpoint** (optional, filled after apply)
- **SQL database name** (app DB created by db_init)
- **App SQL username / password** (required; not the RDS master)
- **Use Let’s Encrypt**
- **SuperAdmin email / Infra admin email**
- **Web app name (path)**
- **OIDC provider** (Entra or Okta)
- **Entra tenant ID** or **Okta authority URL**
- **OIDC client ID / client secret**
- **Cluster node count (app pods)**
- **ACR repository name / image tag / registry**
- **ACR username / password / auth / email**
- **TLS cert/key paths** (manual TLS only)

Edit `customer-deployments/acme-prod/config.auto.tfvars.json` using
`deployments/_template/config.auto.tfvars.json.example` as a baseline.

### DB init image (prebuilt tools)

The db_init task uses a prebuilt image that already includes the required tools.
Leave `db_init.image_uri` at the default:

```json
"db_init": {
  "image_uri": "profisee.azurecr.io/profiseeplatformdev:aws-ecs-tools-latest"
}
```

## Stage C - Core infra (VPC + EKS + RDS + ACM)

Disable CloudFront and Route53 for this stage (template defaults enable them):

```json
"cloudfront": { "enabled": false },
"route53": { "enabled": false }
```

Then:

```powershell
.\scripts\tofu-plan.ps1 -DeploymentName acme-prod
# Replace 'opentofu-deploy' if you used a custom deploy role name.
.\scripts\tofu-apply.ps1 -DeploymentName acme-prod -DeployRoleName opentofu-deploy
```

If you skipped seeding in Stage B, run:

```powershell
.\scripts\seed-secrets.ps1 -DeploymentName acme-prod -UpdateConfig
```

Run `seed-secrets.ps1` **before** `tofu-apply.ps1` so the DB init task
definition includes the secret ARNs.

After apply, `Settings.yaml` is updated with the RDS endpoint and (if provided)
the app EBS volume ID.

Upload `Settings.yaml` to the App Settings S3 bucket:

```powershell
.\scripts\upload-settings.ps1 -DeploymentName acme-prod
```

Notes:
- Store **app SQL** credentials (not the RDS master) when prompted — required
  because `db_init` runs automatically after apply.
- The script writes secret ARNs into `platform_deployer.secret_arns` and
  `db_init.secret_arns` so the Fargate tasks can retrieve them.
- If `secrets/seed-secrets.json` exists, the script will use it instead of
  re‑prompting.
- If you skip `seed-secrets.ps1`, `tofu-apply.ps1` will fail because `db_init`
  requires secret ARNs.

### Stage C.1 - DB init (automated via Fargate)

OpenTofu creates the **RDS instance**. The **app database** (from
`rds_sqlserver.db_name`) and the **app login/user** are created automatically
by a **one‑shot Fargate task** (`db_init`) that runs as part of
`tofu-apply.ps1` when `db_init.enabled = true` (required).

The task receives:
- `DB_ENDPOINT`, `DB_NAME`, and `SECRET_RDS_MASTER_ARN`
- `SECRET_SQL_ARN` (app SQL username/password)
- any `SECRET_<NAME>_ARN` entries from `db_init.secret_arns`

If the task fails, check CloudWatch logs:
`/aws/ecs/<cluster-name>-db-init`.

Note: the db_init task installs its dependencies at runtime, so the first run
can take a few minutes.

After db_init completes, it also writes a kubeconfig and uploads it to the
**App Settings S3 bucket** (same bucket as `Settings.yaml`), at:
`s3://<settings-bucket>/kubeconfig/<cluster-name>/kubeconfig`.

To download it later:

```powershell
aws s3 cp s3://<settings-bucket>/kubeconfig/<cluster-name>/kubeconfig .\kubeconfig
```

Note: when the jumpbox is enabled, its IAM role includes read access to the
App Settings bucket for `settings/*` and `kubeconfig/*`, so you can run the
download commands directly on the jumpbox without extra role switches.

## Stage C.2 - Jumpbox (optional, GUI access)

This stage creates an optional **Windows jumpbox** inside the VPC so you can
manage a **private‑only EKS API** and private RDS from a GUI (SSMS, kubectl,
Helm, etc.). It also creates a **jumpbox IAM role**, and can update your **deploy
role trust policy** so the jumpbox can assume that role when you run AWS CLI
commands from the jumpbox.

When enabled, the jumpbox **automatically downloads kubeconfig** from the
App Settings S3 bucket (`kubeconfig/<cluster-name>/kubeconfig`) on first boot.
It retries for up to ~60 minutes, so there is **no chicken‑and‑egg** even if the
kubeconfig is uploaded later by the db_init task.

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

If you used a custom deploy role name, update `assume_role_arn` accordingly.

Notes:
- If you **use classic RDP**, you must supply `key_name` and keep the **PEM file locally**
  (AWS only lets you download it once when you create the key pair).

Create the key pair on‑the‑fly (updates your config automatically):

```powershell
.\scripts\create-jumpbox-key.ps1 -DeploymentName acme-prod
```

Create a key pair (only if you plan to use classic RDP):

```powershell
$secretsDir = ".\\customer-deployments\\acme-prod\\secrets"
New-Item -ItemType Directory -Path $secretsDir -Force | Out-Null
aws ec2 create-key-pair --region us-east-1 --key-name profisee-jumpbox-key `
  --query "KeyMaterial" --output text | Out-File -FilePath "$secretsDir\\profisee-jumpbox-key.pem" -Encoding ascii
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

By default, this now also **ensures a jumpbox key exists** (for classic RDP).
If you want to skip key creation, pass `-EnsureJumpboxKey $false`.

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

## Stage D - Platform foundation (Kubernetes)

Deploy the Kubernetes foundation (Traefik/NLB + addons only). This creates the
public NLB DNS name that CloudFront needs as an origin, and updates Route53 to
point your chosen FQDN (for example `kickoff2026.demos.profisee.com`) at the
NLB via a **CNAME** record. **Do not deploy the app yet** — we deploy the app
in Stage E.

**Private access is the default** (EKS API private‑only). Run kubectl/Helm from
inside the VPC (jumpbox/bastion) or through a VPN/Direct Connect connection.
For a jumpbox with no inbound RDP, use **Fleet Manager Remote Desktop**
(recommended). See: [Fleet Manager Remote Desktop](./fleet-manager-rdp.md).

**Automatic (default):** The **db_init** Fargate task now runs Stage D after it
finishes DB init. It:
- Installs Traefik via Helm and waits for the NLB hostname.
- Uses the Terraform-managed `aws-ebs-csi-driver` add-on and waits for CSI controller/node readiness before app install.
- If Windows nodes exist, enables Windows IPAM on VPC CNI (`amazon-vpc-cni` ConfigMap and `aws-node` DaemonSet env) so Windows pods can receive pod IP labels.
- Logs the NLB DNS name in `/aws/ecs/<cluster-name>-db-init`.
- Writes platform outputs to the App Settings S3 bucket:
  `s3://<settings-bucket>/outputs/<cluster-name>/platform.json`.
- Updates Route53 `route53.record_name` → NLB hostname (CNAME), if provided.
After the NLB hostname is available **and** Route53 update succeeds, the task
installs the app by default (see `app_deploy`).

**Manual (optional, rerun):** From inside the VPC, you can re‑run the platform
install script:

```powershell
.\scripts\deploy-platform.ps1 -DeploymentName acme-prod
```

Note: if you plan to use CloudFront in Stage E, this CNAME is temporary and
will be updated to the CloudFront distribution later.

Note: Traefik is configured to use the **standard kubernetesIngress provider**
and the NGINX compatibility provider is disabled.

## Stage E - App + Edge (CloudFront + Route53)

Deploy the app in this stage **regardless of whether CloudFront is enabled**.
If you are not using CloudFront, you can skip the CloudFront/Route53 toggles
below and deploy the app once the NLB DNS name is available.

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

Or use the helper to wire Stage E from platform outputs:

```powershell
.\scripts\enable-edge.ps1 -DeploymentName acme-prod
```

Get the NLB DNS name from:
- CloudWatch logs: `/aws/ecs/<cluster-name>-db-init`, or
- `s3://<settings-bucket>/outputs/<cluster-name>/platform.json`

Re-apply infra:

```powershell
# Replace 'opentofu-deploy' if you used a custom deploy role name.
.\scripts\tofu-apply.ps1 -DeploymentName acme-prod -DeployRoleName opentofu-deploy
```

Deploy the Profisee app **now** (Stage E). If your platform script installs the
app, run it here instead of Stage D, using the completed `Settings.yaml`.

**App deploy via db_init task (no extra scripts):**

1) App deploy is enabled by default. To disable it:

```json
"app_deploy": {
  "enabled": false,
  "release_name": "profiseeplatform",
  "namespace": "profisee"
}
```

2) Re-apply infra (this will run db_init again and install/upgrade the app):

```powershell
.\scripts\tofu-apply.ps1 -DeploymentName acme-prod -AutoApprove
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
