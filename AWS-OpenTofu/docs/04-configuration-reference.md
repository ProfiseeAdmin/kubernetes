# Configuration Reference

Configuration is supplied via `config.auto.tfvars.json` in a deployment folder.
See `deployments/_template/config.auto.tfvars.json.example` for a full example.

## Top‑level keys

- `region`: primary AWS region (use `us-east-1`)
- `use1_region`: `us-east-1` (ACM for CloudFront)
- `tags`: default tags applied to resources
- `settings_bucket`: S3 bucket for `Settings.yaml` and deployment artifacts
- `app_ebs`: optional EBS volume configuration for the app fileshare (created by OpenTofu)
- `platform_deployer`: optional Fargate one‑shot deployer configuration
- `db_init`: **required** Fargate one‑shot DB initializer configuration

## VPC

`vpc` includes CIDR, subnets, AZs, NAT settings, and tags.

Key fields:
- `name`, `cidr_block`, `azs`
- `public_subnet_cidrs`, `private_subnet_cidrs`
- `enable_nat_gateway`, `single_nat_gateway`

## EKS

`eks` controls the private cluster and node groups.

Key fields:
- `cluster_name`, `cluster_version`
- `endpoint_public_access` (default false)
- `endpoint_private_access` (default true)
- `linux_node_group`, `windows_node_group`

## RDS SQL Server

`rds_sqlserver` controls SQL Server in private subnets.

Key fields:
- `identifier`, `engine_version`, `instance_class`
- `allocated_storage`
- `db_name` (required; initial DB created by RDS)
- `publicly_accessible` (default false)

## KMS / Secrets (optional)

- `kms.keys`: map of KMS keys
- `secrets.secrets`: map of Secrets Manager secrets

## ACM (us‑east‑1)

`acm` controls the CloudFront certificate:
- `domain_name`, `hosted_zone_id`
- `subject_alternative_names`

## CloudFront (edge)

`cloudfront` is **stage‑gated**:
- `enabled`: false for Stage C, true for Stage E
- `origin_domain_name`: NLB DNS name (from platform)
- `aliases`: customer hostname

## Route53 (edge DNS)

`route53` is also **stage‑gated**:
- `enabled`: false for Stage C, true for Stage E
- `hosted_zone_id`, `record_name`

## Jumpbox (optional)

`jumpbox` enables a Windows GUI management box:
- `enabled`
- `key_name` (required for classic RDP)
- `assume_role_arn` (recommended)
  - `associate_public_ip` (default false)

## App EBS (fileshare)

`app_ebs` controls the dedicated EBS volume used by the app fileshare.

Key fields:
- `enabled` (default true)
- `size_gb`, `type` (default 5 GB, `gp3`)
- `availability_zone` (defaults to first VPC AZ)
- `encrypted`, `kms_key_id`

## Settings bucket (S3)

`settings_bucket` controls the S3 bucket used to store `Settings.yaml`.

Key fields:
- `name` (globally unique)
- `force_destroy` (default false)
- `kms_key_arn` (optional)

## Platform deployer (Fargate)

`platform_deployer` defines the one‑shot Fargate task used to deploy
platform components (Traefik + addons) before the app.

Key fields:
- `enabled` (default false)
- `image_uri` (container image that runs the deploy script)
- `cpu`, `memory`
- `settings_key` (S3 key for `Settings.yaml`)
- `secret_arns` (map of secrets for the container to retrieve)

## DB init (Fargate)

`db_init` defines a one‑shot Fargate task that creates the **app SQL login/user**
and grants `db_owner` on the app database.

Key fields:
- `enabled` (required; set to true)
- `image_uri` (container image with `sqlcmd` + AWS CLI/SDK)
- `cpu`, `memory`
- `secret_arns` (map of secrets for the container to retrieve)

