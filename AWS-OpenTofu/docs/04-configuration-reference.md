# Configuration Reference

Configuration is supplied via `config.auto.tfvars.json` in a deployment folder.
See `deployments/_template/config.auto.tfvars.json.example` for a full example.

## Top‑level keys

- `region`: primary AWS region (use `us-east-1`)
- `use1_region`: `us-east-1` (ACM for CloudFront)
- `tags`: default tags applied to resources

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
- `assume_role_arn` (recommended)
- `associate_public_ip` (default false)

