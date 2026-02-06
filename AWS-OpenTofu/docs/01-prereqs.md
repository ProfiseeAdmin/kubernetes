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

For customer‑run installs, create a dedicated IAM role (e.g., `opentofu-deploy`,
or your custom role name)
and assume it when running the scripts. For initial proof/testing, attach
`AdministratorAccess` to that role. Later, you can replace it with a least‑privilege
policy once the required actions are finalized.

If you choose a **custom role name**, replace `opentofu-deploy` everywhere in
the docs/commands and pass `-DeployRoleName <your-role-name>` to scripts that
accept it.

## DNS / domain

- A public Route53 hosted zone (or delegated subdomain) for the hostname you
  will use (e.g., `app.example.com`).
- DNS validation is used for ACM certificates in us-east-1.

## App Settings S3 bucket

- Have a **globally unique S3 bucket name** ready for storing `Settings.yaml`.

## Local tools

- OpenTofu (Terraform-compatible) on PATH as `tofu`
- AWS CLI authenticated to your target account
- kubectl and Helm (for the platform layer)
- Session Manager plugin (optional, for Fleet Manager Remote Desktop)

Install these using Choco or manually using their respective pages:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
choco upgrade chocolatey kubernetes-cli eksctl kubernetes-helm awscli awscli-session-manager opentofu -y
```

Verify installs (CMD or PowerShell):

```cmd
helm version
aws --version
eksctl version
kubectl version
tofu --version
```

## Optional: EC2 key pair for jumpbox RDP

Only required if you plan to use **classic RDP**. If you use **SSM port
forwarding**, you do not need a key pair.

Create a key pair and save the PEM locally (AWS only lets you download it once):

```powershell
$secretsDir = ".\\customer-deployments\\acme-prod\\secrets"
New-Item -ItemType Directory -Path $secretsDir -Force | Out-Null
aws ec2 create-key-pair --region us-east-1 --key-name profisee-jumpbox-key `
  --query "KeyMaterial" --output text | Out-File -FilePath "$secretsDir\\profisee-jumpbox-key.pem" -Encoding ascii
```

Then set `jumpbox.key_name` to `profisee-jumpbox-key` in your config.

Optional helper (creates the key under `customer-deployments/<name>/secrets` and updates your config):

```powershell
.\scripts\create-jumpbox-key.ps1 -DeploymentName acme-prod
```

## Notes

- CloudFront requires certificates in `us-east-1`, even if your cluster is in a
  different region.
- CloudFront origin headers are stored in state. Do not place secrets there.
- If you set the EKS API endpoint to private‑only, you must run kubectl/Helm from
  inside the VPC (jumpbox/bastion) or through VPN/Direct Connect.
- A Windows jumpbox can be used for GUI access. Recommended access method:
  - Fleet Manager Remote Desktop (no inbound RDP required)

