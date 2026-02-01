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

### Recommended: Dedicated deploy role

For customer‑run installs, create a dedicated IAM role (e.g., `opentofu-deploy`)
and assume it when running the scripts. For initial proof/testing, attach
`AdministratorAccess` to that role. Later, you can replace it with a least‑privilege
policy once the required actions are finalized.

## DNS / domain

- A public Route53 hosted zone (or delegated subdomain) for the hostname you
  will use (e.g., `app.example.com`).
- DNS validation is used for ACM certificates in us-east-1.

## Local tools

- OpenTofu (Terraform-compatible) on PATH as `tofu`
- AWS CLI authenticated to your target account
- kubectl and Helm (for the platform layer)
- Session Manager plugin (optional, for SSM RDP port forwarding)

### AWS CLI (Windows)

Install the AWS CLI v2 from the official AWS documentation:
`https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html`

From **Command Prompt**:

```cmd
msiexec.exe /i https://awscli.amazonaws.com/AWSCLIV2.msi
```

Complete the installer, then reopen Command Prompt and confirm:

```cmd
aws --version
```

## Notes

- CloudFront requires certificates in `us-east-1`, even if your cluster is in a
  different region.
- CloudFront origin headers are stored in state. Do not place secrets there.
- If you set the EKS API endpoint to private‑only, you must run kubectl/Helm from
  inside the VPC (jumpbox/bastion) or through VPN/Direct Connect.
- A Windows jumpbox can be used for GUI access. You can connect via RDP over:
  - VPN/Direct Connect, or
  - SSM port forwarding (no inbound RDP required)

