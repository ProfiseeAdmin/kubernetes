# Quickstart (Local)

This guide walks a customer through a staged, local deployment from a fresh AWS
account. It keeps secrets out of Git and out of OpenTofu state.

## Prereqs

- AWS account with permissions to create VPC, EKS, RDS, ACM, CloudFront, Route53
- A public Route53 hosted zone (or delegated subdomain) for your hostname
- OpenTofu, AWS CLI, kubectl, and Helm installed

## Stage A - Bootstrap state backend

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

