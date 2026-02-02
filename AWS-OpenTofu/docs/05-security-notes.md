# Security Notes

## No secrets in state or Git

- Do **not** put license files, DB passwords, or origin header secrets in OpenTofu variables.
- License files live in `customer-deployments/<name>/secrets/license.txt` and
  are injected into `Settings.yaml` (raw). Keep the entire
  `customer-deployments/` tree out of Git.
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

