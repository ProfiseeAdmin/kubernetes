# Security Notes

## No secrets in state or Git

- Do **not** put license files, DB passwords, or origin header secrets in OpenTofu variables.
- License files live in `customer-deployments/<name>/secrets/license.txt` and
  are **not** injected into `Settings.yaml`. Instead, seed Secrets Manager and
  keep the entire `customer-deployments/` tree out of Git.
- `Settings.yaml` may contain sensitive values. Store it in the dedicated S3
  settings bucket with encryption enabled and restrict access to the deployer
  role only.
- `secrets/seed-secrets.json` contains sensitive values (ACR creds, OIDC client
  secret, TLS key). Keep it out of Git and delete it after seeding Secrets
  Manager.
- Use AWS Secrets Manager + CSI to mount secrets into pods.

## Private by default

- EKS API is private by default. Use a jumpbox or VPN/Direct Connect for kubectl/Helm.
- RDS is private (not publicly accessible).

## Edge security

- CloudFront is the only public edge.
- Origin is the NLB created by Traefik.
- Do not store origin secrets in Terraform/OpenTofu state.

## IAM

- Use a dedicated deploy role.
- Tighten policies after the first run using Access Analyzer or CloudTrail.

## State backend

- State bucket is encrypted with KMS and versioning enabled.
- DynamoDB locking is enabled.

