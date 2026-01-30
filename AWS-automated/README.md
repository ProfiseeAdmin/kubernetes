# Profisee AWS EKS Deployment (CFN + Post-Deploy)

## 1) Overall steps (high level)
1. Deploy the CloudFormation stack (`infra/FullyPrivateEKS.yaml` in repo).
2. Wait for **CREATE_COMPLETE**.
3. Connect to the **SSM jumpbox** and configure `kubectl` access to the private cluster.
4. Download the required scripts/manifests and edit placeholders.
5. Create any Secrets Manager secrets not already created (license, TLS certs).
6. Run the post-deploy script (`scripts/deployprofisee-aws.ps1`) to render settings and install Traefik/Profisee (and optional CloudFront).

## 2) Repo layout (condensed)
- `infra/` CloudFormation templates.
- `scripts/` PowerShell/shell automation (post-deploy, downloads).
- `values/` Helm values files.
- `manifests/` Kubernetes YAMLs (cert-manager, ingress, storage).
- `examples/` Example JSON payloads for Secrets Manager.

## 3) Stack options (what each parameter does)
| Parameter | Default | What it controls |
|---|---|---|
| `VpcBlock` | `10.0.0.0/22` | CIDR for the VPC. |
| `PrivateEKSSubnet01Block` | `10.0.0.0/24` | CIDR for EKS private subnet 01. |
| `PrivateEKSSubnet02Block` | `10.0.1.0/24` | CIDR for EKS private subnet 02. |
| `PrivateRDSSubnet01Block` | `10.0.2.0/26` | CIDR for RDS private subnet 01. |
| `PrivateRDSSubnet02Block` | `10.0.2.64/26` | CIDR for RDS private subnet 02. |
| `PublicSubnet01Block` | `10.0.3.0/26` | CIDR for public subnet 01 (NAT/ingress). |
| `PublicSubnet02Block` | `10.0.3.64/26` | CIDR for public subnet 02 (HA NAT/ingress). |
| `NamePrefix` | `Profisee` | Prefix for Name tags. |
| `EnvType` | `dev` | Environment tag segment (dev/test/prod). |
| `JumpboxEnabled` | `true` | Create a private Windows jumpbox with SSM. |
| `JumpboxInstanceType` | `t3.small` | Jumpbox EC2 instance type. |
| `JumpboxAmiId` | Windows 2022 | AMI for the jumpbox (SSM parameter). |
| `JumpboxKeyName` | (empty) | Optional EC2 key pair. If empty, SSM-only access is used. |
| `AdditionalSecretsArn` | (empty) | Customer-supplied Secrets Manager ARN/prefix for extra secrets (TLS certs, etc.). If empty, no extra access is granted. |
| `LicenseSecretArn` | (empty) | Pre-uploaded license secret ARN (customer-created). If empty, license must be provided via `-LicenseBase64`. |
| `NatMode` | `Single` | `Single`, `HA`, or `None` NAT mode. |
| `ClusterName` | `ProfiseeEKSCluster` | EKS cluster name. |
| `EKSVersion` | (empty) | EKS version. If empty, AWS default is used. |
| `DBPort` | `1433` | SQL Server port. |
| `StorageMode` | `FSx` | `FSx` (shared SMB) or `EBS` (single-pod). |
| `DBInstanceClass` | `db.m5.large` | RDS SQL Server instance class. |
| `DBAllocatedStorage` | `50` | RDS storage in GiB. |
| `DBMasterUsername` | `sqladmin` | RDS master username. |
| `DBBackupRetentionDays` | `7` | RDS backup retention (days). |
| `DBMultiAZ` | `false` | Enable Multi-AZ RDS. |
| `DBDeletionProtection` | `true` | Prevents accidental RDS deletion. |
| `FSxDirectoryId` | (empty) | Directory Service ID for FSx (required when `StorageMode=FSx`). |
| `FSxStorageCapacity` | `5` | FSx capacity (GiB). |
| `FSxThroughputCapacity` | `16` | FSx throughput (MB/s). |
| `FSxBackupRetentionDays` | `7` | FSx backup retention. |
| `FSxEnableBackups` | `false` | Enable FSx automatic backups. |
| `FSxDailyBackupStartTime` | (empty) | FSx backup start time (HH:MM). |
| `FSxEnableWeeklyMaintenanceWindow` | `false` | Enable FSx weekly maintenance. |
| `FSxWeeklyMaintenanceStartTime` | (empty) | FSx maintenance time (d:HH:MM). |
| `EBSVolumeSize` | `5` | EBS size (GiB) for single-pod mode. |
| `EBSVolumeType` | `gp3` | EBS volume type. |
| `EBSVolumeAZ` | (empty) | AZ for EBS volume (defaults to subnet 01 AZ). |

## 4) Connect to the jumpbox via SSM
**Console**
1) AWS Console → **Systems Manager** → **Session Manager**  
2) **Start session** → select the jumpbox instance → **Start session**

**CLI**
```
aws ssm start-session --target i-xxxxxxxxxxxx
```

### Jumpbox prerequisites (AWS CLI / kubectl / helm)
The latest template **auto-installs** these tools on the jumpbox (requires NAT/outbound internet).
If you see `aws : The term 'aws' is not recognized`, the tools are not installed—use the steps below.

**A) Online install (requires NAT/outbound internet)**
```
Set-ExecutionPolicy Bypass -Scope Process -Force
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
choco upgrade chocolatey awscli kubernetes-cli kubernetes-helm -y

After the prerequisites are installed, run this:
Import-Module C:\ProgramData\chocolatey\helpers\chocolateyProfile.psm1

And then run:
refreshenv

After that you should be able to verify that aws cli has been installed by running:
aws --version
and you'll get the Chocolatey installed version
```

**B) Offline install (no NAT)**
- Download installers to S3 and install from a presigned URL.

### IAM access to the cluster
The jumpbox IAM role can call `eks:DescribeCluster` (already in CFN), but **Kubernetes API access** still requires mapping the role in EKS.
The jumpbox bootstrap **waits ~5 minutes and creates an access entry automatically** (when NAT is enabled). If that step fails or NAT is disabled, run the manual commands below.

**Option 1: EKS Access Entry (recommended)**
```
aws eks create-access-entry --cluster-name <ClusterName> --principal-arn <JumpboxRoleArn>
aws eks associate-access-policy \
  --cluster-name <ClusterName> \
  --principal-arn <JumpboxRoleArn> \
  --policy-arn arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy \
  --access-scope type=cluster
```

**Option 2: aws-auth ConfigMap**
- Add the jumpbox role to `system:masters` in the `aws-auth` ConfigMap.

Once connected and tools are installed, configure access to the private cluster:
```
aws eks update-kubeconfig --name <ClusterName> --region <region>
kubectl get nodes
```

**Tip:** Use the **jumpbox role ARN**, not the STS assumed-role ARN. The role ARN is available
as a stack output (`JumpboxRoleArn`).

If the instance doesn’t appear in Session Manager:
- Verify the jumpbox IAM role includes `AmazonSSMManagedInstanceCore`
- Ensure VPC endpoints exist: `ssm`, `ssmmessages`, `ec2messages`

## 4) Download files and edit placeholders
Set repo variables (PowerShell):
```
$RepoOwner = "<GITHUB_ORG>"
$RepoName = "<REPO_NAME>"
$RepoPath = "<PATH_IN_REPO>"
$Branch = "<BRANCH_OR_TAG>"
$BaseRaw = "https://raw.githubusercontent.com/$RepoOwner/$RepoName/$Branch/$RepoPath"
```

Download core files:
```
Invoke-WebRequest -Uri "$BaseRaw/FullyPrivateEKS.yaml" -OutFile "FullyPrivateEKS.yaml"
Invoke-WebRequest -Uri "$BaseRaw/deployprofisee-aws.ps1" -OutFile "deployprofisee-aws.ps1"
Invoke-WebRequest -Uri "$BaseRaw/deployprofisee-aws-stack.ps1" -OutFile "deployprofisee-aws-stack.ps1"
Invoke-WebRequest -Uri "$BaseRaw/Settings-aws.yaml" -OutFile "Settings-aws.yaml"
Invoke-WebRequest -Uri "$BaseRaw/traefik-values.yaml" -OutFile "traefik-values.yaml"
Invoke-WebRequest -Uri "$BaseRaw/traefik-values-public.yaml" -OutFile "traefik-values-public.yaml"
```

Optional files:
```
Invoke-WebRequest -Uri "$BaseRaw/smb-csi-values.yaml" -OutFile "smb-csi-values.yaml"
Invoke-WebRequest -Uri "$BaseRaw/smb-secret.yaml" -OutFile "smb-secret.yaml"
Invoke-WebRequest -Uri "$BaseRaw/smb-storageclass.yaml" -OutFile "smb-storageclass.yaml"
Invoke-WebRequest -Uri "$BaseRaw/smb-pvc.yaml" -OutFile "smb-pvc.yaml"
Invoke-WebRequest -Uri "$BaseRaw/profisee-ingress.yaml" -OutFile "profisee-ingress.yaml"
Invoke-WebRequest -Uri "$BaseRaw/cert-manager-route53-issuer.yaml" -OutFile "cert-manager-route53-issuer.yaml"
Invoke-WebRequest -Uri "$BaseRaw/cert-manager-certificate.yaml" -OutFile "cert-manager-certificate.yaml"
Invoke-WebRequest -Uri "$BaseRaw/route53-credentials-secret.yaml" -OutFile "route53-credentials-secret.yaml"
Invoke-WebRequest -Uri "$BaseRaw/secretsmanager-cert.example.json" -OutFile "secretsmanager-cert.example.json"
```

**Edit these files before use:**
- `smb-secret.yaml` → set AD username/password  
- `smb-storageclass.yaml` → set `\\<FSX_DNS_NAME>\share`  
- `cert-manager-route53-issuer.yaml` → set email, hosted zone, access key  
- `route53-credentials-secret.yaml` → set secret access key  
- `cert-manager-certificate.yaml` → set hostname  
- `profisee-ingress.yaml` → set hostname (if used)

## 5) Create Secrets Manager secrets (if not pre‑done)
**SQL credentials**  
CloudFormation already creates the RDS master secret. You can use its ARN from stack outputs.

**License (large string)**
```
aws secretsmanager create-secret --name profisee-license --secret-string file://license.txt
```

**TLS certs (Traefik / CloudFront import)**
```
aws secretsmanager create-secret --name profisee-tls --secret-string file://secretsmanager-cert.example.json
```

## 6) Deployment examples (common combinations)
Set shared variables:
```
$StackName = "ProfiseeStack"
$Region = "us-east-1"
$DbName = "Profisee"
$DbSecretArn = "arn:aws:secretsmanager:REGION:ACCOUNT:secret:rds-master"
$LicenseSecretArn = "arn:aws:secretsmanager:REGION:ACCOUNT:secret:profisee-license"
```

### A) CloudFront + Traefik, fully managed certs (ACMRequest + Let’s Encrypt)
```
.\deployprofisee-aws.ps1 `
  -StackName $StackName `
  -AwsRegion $Region `
  -DbName $DbName `
  -DbSecretArn $DbSecretArn `
  -LicenseSecretArn $LicenseSecretArn `
  -TraefikTlsMode "LetsEncrypt" `
  -UseLetsEncrypt "true" `
  -CloudFrontEnabled "true" `
  -CloudFrontAlias "profiseetest.profisee.com" `
  -CloudFrontCertMode "ACMRequest"
```

### B) CloudFront + Traefik, customer-managed certs (Secrets Manager)
```
.\deployprofisee-aws.ps1 `
  -StackName $StackName `
  -AwsRegion $Region `
  -DbName $DbName `
  -DbSecretArn $DbSecretArn `
  -LicenseSecretArn $LicenseSecretArn `
  -TraefikTlsMode "SecretsManager" `
  -TraefikTlsSecretArn "arn:aws:secretsmanager:REGION:ACCOUNT:secret:profisee-tls" `
  -CloudFrontEnabled "true" `
  -CloudFrontAlias "profiseetest.profisee.com" `
  -CloudFrontCertMode "ACMImport" `
  -CloudFrontCertSecretArn "arn:aws:secretsmanager:us-east-1:ACCOUNT:secret:cf-cert"
```

### C) Traefik only, fully managed cert (Let’s Encrypt)
```
.\deployprofisee-aws.ps1 `
  -StackName $StackName `
  -AwsRegion $Region `
  -DbName $DbName `
  -DbSecretArn $DbSecretArn `
  -LicenseSecretArn $LicenseSecretArn `
  -TraefikTlsMode "LetsEncrypt" `
  -UseLetsEncrypt "true" `
  -CloudFrontEnabled "false"
```

### D) Traefik only, customer-managed cert
```
.\deployprofisee-aws.ps1 `
  -StackName $StackName `
  -AwsRegion $Region `
  -DbName $DbName `
  -DbSecretArn $DbSecretArn `
  -LicenseSecretArn $LicenseSecretArn `
  -TraefikTlsMode "SecretsManager" `
  -TraefikTlsSecretArn "arn:aws:secretsmanager:REGION:ACCOUNT:secret:profisee-tls" `
  -CloudFrontEnabled "false"
```

## Notes
- CloudFront requires ACM certificates in **us-east-1**.
- For FSx SMB, install the SMB CSI driver and apply the storage class + PVC files.
- For public ingress, use `traefik-values-public.yaml`. For private, use `traefik-values.yaml`.
- NAT Gateway cost: Single NAT is cheaper but a single point of failure; HA NAT is recommended for production.
- Node AMI compatibility: this template uses **AL2023** for Linux nodegroups and **Windows Server 2022** for Windows nodegroups. If you pin an older EKS version, confirm AMI support.
