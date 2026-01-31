# Quickstart (Local)

This guide walks a customer through a staged, local deployment from a fresh AWS
account. It keeps secrets out of Git and out of OpenTofu state.

## Prereqs

- AWS account with permissions to create VPC, EKS, RDS, ACM, CloudFront, Route53
- A public Route53 hosted zone (or delegated subdomain) for your hostname
- OpenTofu, AWS CLI, kubectl, and Helm installed

## Stage A - Bootstrap state backend

### Step 1 - Authenticate as a deploy role

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

Then configure your CLI to assume the role:

```ini
# ~/.aws/config
[profile opentofu-deploy]
role_arn = arn:aws:iam::<ACCOUNT_ID>:role/opentofu-deploy
source_profile = default
region = us-west-2
```

Run subsequent commands with:

```powershell
$env:AWS_PROFILE = "opentofu-deploy"
```

Note: `scripts/bootstrap.ps1` can optionally create a deploy role if you pass
`-CreateDeployRole` and related inputs, but you still need initial credentials
with permissions to create IAM roles.

From repo root:

```powershell
cd C:\GitRepoPaaS\ProfiseeAdmin\kubernetes\AWS-OpenTofu
```

Edit or provide values for:
- `region`
- `state_bucket_name` (globally unique)
- `state_lock_table_name` (optional override)

Then:

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
region         = "us-west-2"
dynamodb_table = "opentofu-state-locks"
encrypt        = true
kms_key_id     = "arn:aws:kms:us-west-2:123456789012:key/..."
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
tofu -chdir=infra/root init -backend-config=..\..\customer-deployments\acme-prod\backend.hcl
tofu -chdir=infra/root apply -var-file=..\..\customer-deployments\acme-prod\config.auto.tfvars.json
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
  "iam_policy_arns": [
    "arn:aws:iam::aws:policy/AdministratorAccess"
  ]
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
  "origin_domain_name": "nlb-abc123.us-west-2.elb.amazonaws.com",
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
tofu -chdir=infra/root apply -var-file=..\..\customer-deployments\acme-prod\config.auto.tfvars.json
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

