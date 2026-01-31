# Prerequisites

This installer is designed for customer‑run deployments inside your own AWS
account. It assumes a public DNS name fronted by CloudFront.

## AWS account and permissions

- An AWS account with permissions to create:
  - VPC, subnets, Internet/NAT gateways
  - EKS and IAM roles
  - RDS SQL Server
  - ACM certificates (us-east-1 for CloudFront)
  - CloudFront distributions
  - Route53 hosted zone records
- For testing, admin permissions are simplest. For production, use a dedicated
  deploy role with least privilege.

## DNS / domain

- A public Route53 hosted zone (or delegated subdomain) for the hostname you
  will use (e.g., `app.example.com`).
- DNS validation is used for ACM certificates in us-east-1.

## Local tools

- OpenTofu (Terraform-compatible) on PATH as `tofu`
- AWS CLI authenticated to your target account
- kubectl and Helm (for the platform layer)

## Notes

- CloudFront requires certificates in `us-east-1`, even if your cluster is in a
  different region.
- CloudFront origin headers are stored in state. Do not place secrets there.

