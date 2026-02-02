locals {
  jumpbox_enabled   = try(var.jumpbox.enabled, false)
  jumpbox_name      = coalesce(try(var.jumpbox.name, null), "jumpbox")
  jumpbox_subnet_id = coalesce(try(var.jumpbox.subnet_id, null), module.vpc.private_subnet_ids[0])
  jumpbox_tags      = merge(var.tags, try(var.jumpbox.tags, {}))
  app_ebs_enabled   = try(var.app_ebs.enabled, true)
  app_ebs_az        = coalesce(try(var.app_ebs.availability_zone, null), var.vpc.azs[0])
  app_ebs_tags      = merge(var.tags, try(var.app_ebs.tags, {}))
}

module "vpc" {
  source = "../modules/vpc"

  name                 = var.vpc.name
  cidr_block           = var.vpc.cidr_block
  azs                  = var.vpc.azs
  public_subnet_cidrs  = var.vpc.public_subnet_cidrs
  private_subnet_cidrs = var.vpc.private_subnet_cidrs
  enable_nat_gateway   = var.vpc.enable_nat_gateway
  single_nat_gateway   = var.vpc.single_nat_gateway
  enable_dns_hostnames = var.vpc.enable_dns_hostnames
  enable_dns_support   = var.vpc.enable_dns_support
  public_subnet_tags   = var.vpc.public_subnet_tags
  private_subnet_tags  = var.vpc.private_subnet_tags
  vpc_tags             = var.vpc.vpc_tags
  tags                 = var.vpc.tags
}

module "eks" {
  source = "../modules/eks"

  cluster_name            = var.eks.cluster_name
  cluster_version         = var.eks.cluster_version
  vpc_id                  = module.vpc.vpc_id
  private_subnet_ids      = module.vpc.private_subnet_ids
  public_subnet_ids       = module.vpc.public_subnet_ids
  endpoint_public_access  = var.eks.endpoint_public_access
  endpoint_private_access = var.eks.endpoint_private_access
  enabled_cluster_log_types = var.eks.enabled_cluster_log_types
  cluster_kms_key_arn        = var.eks.cluster_kms_key_arn
  linux_node_group           = var.eks.linux_node_group
  windows_node_group         = var.eks.windows_node_group
  tags                       = var.eks.tags
}

module "rds_sqlserver" {
  source = "../modules/rds_sqlserver"

  identifier                    = var.rds_sqlserver.identifier
  engine_version                = var.rds_sqlserver.engine_version
  instance_class                = var.rds_sqlserver.instance_class
  allocated_storage             = var.rds_sqlserver.allocated_storage
  max_allocated_storage         = var.rds_sqlserver.max_allocated_storage
  storage_type                  = var.rds_sqlserver.storage_type
  iops                          = var.rds_sqlserver.iops
  storage_encrypted             = var.rds_sqlserver.storage_encrypted
  kms_key_arn                   = var.rds_sqlserver.kms_key_arn
  db_name                       = var.rds_sqlserver.db_name
  master_username               = var.rds_sqlserver.master_username
  manage_master_user_password   = var.rds_sqlserver.manage_master_user_password
  master_user_secret_kms_key_id = var.rds_sqlserver.master_user_secret_kms_key_id
  vpc_id                        = module.vpc.vpc_id
  subnet_ids                    = module.vpc.private_subnet_ids
  allowed_security_group_ids    = concat(
    var.rds_sqlserver.allowed_security_group_ids,
    local.jumpbox_enabled ? [module.jumpbox_windows[0].security_group_id] : []
  )
  backup_retention_days         = var.rds_sqlserver.backup_retention_days
  multi_az                      = var.rds_sqlserver.multi_az
  publicly_accessible           = var.rds_sqlserver.publicly_accessible
  deletion_protection           = var.rds_sqlserver.deletion_protection
  tags                          = var.rds_sqlserver.tags
}

module "kms" {
  source = "../modules/kms"

  keys = var.kms.keys
  tags = var.kms.tags
}

module "secrets" {
  source = "../modules/secrets"

  secrets = var.secrets.secrets
  tags    = var.secrets.tags
}

module "acm_use1" {
  source    = "../modules/acm_use1"
  providers = { aws = aws.use1 }

  domain_name             = var.acm.domain_name
  subject_alternative_names = var.acm.subject_alternative_names
  hosted_zone_id          = var.acm.hosted_zone_id
  validation_method       = var.acm.validation_method
  create_route53_records  = var.acm.create_route53_records
  tags                    = var.acm.tags
}

module "cloudfront" {
  count  = var.cloudfront.enabled ? 1 : 0
  source = "../modules/cloudfront"

  enabled                   = var.cloudfront.enabled
  aliases                   = var.cloudfront.aliases
  acm_certificate_arn       = module.acm_use1.certificate_arn
  origin_domain_name        = var.cloudfront.origin_domain_name
  origin_id                 = var.cloudfront.origin_id
  origin_protocol_policy    = var.cloudfront.origin_protocol_policy
  origin_ssl_protocols      = var.cloudfront.origin_ssl_protocols
  origin_read_timeout       = var.cloudfront.origin_read_timeout
  origin_keepalive_timeout  = var.cloudfront.origin_keepalive_timeout
  origin_custom_headers      = var.cloudfront.origin_custom_headers
  price_class               = var.cloudfront.price_class
  web_acl_id                = var.cloudfront.web_acl_id
  enable_logging            = var.cloudfront.enable_logging
  logging_bucket            = var.cloudfront.logging_bucket
  tags                      = var.cloudfront.tags
}

module "route53" {
  count  = var.cloudfront.enabled && var.route53.enabled ? 1 : 0
  source = "../modules/route53"

  hosted_zone_id         = var.route53.hosted_zone_id
  record_name            = var.route53.record_name
  record_type            = var.route53.record_type
  alias_name             = module.cloudfront[0].distribution_domain_name
  alias_zone_id          = module.cloudfront[0].hosted_zone_id
  evaluate_target_health = var.route53.evaluate_target_health
}

module "jumpbox_windows" {
  count  = local.jumpbox_enabled ? 1 : 0
  source = "../modules/jumpbox_windows"

  name                 = local.jumpbox_name
  vpc_id               = module.vpc.vpc_id
  subnet_id            = local.jumpbox_subnet_id
  instance_type        = var.jumpbox.instance_type
  ami_id               = var.jumpbox.ami_id
  key_name             = var.jumpbox.key_name
  iam_policy_arns      = var.jumpbox.iam_policy_arns
  assume_role_arn      = var.jumpbox.assume_role_arn
  associate_public_ip  = var.jumpbox.associate_public_ip
  root_volume_size_gb  = var.jumpbox.root_volume_size_gb
  enable_rdp_ingress   = var.jumpbox.enable_rdp_ingress
  allowed_rdp_cidrs    = var.jumpbox.allowed_rdp_cidrs
  user_data            = var.jumpbox.user_data
  tags                 = local.jumpbox_tags
}

resource "aws_ebs_volume" "app_fileshare" {
  count = local.app_ebs_enabled ? 1 : 0

  availability_zone = local.app_ebs_az
  size              = try(var.app_ebs.size_gb, 5)
  type              = try(var.app_ebs.type, "gp3")
  iops              = try(var.app_ebs.iops, null)
  throughput        = try(var.app_ebs.throughput, null)
  encrypted         = try(var.app_ebs.encrypted, true)
  kms_key_id         = try(var.app_ebs.kms_key_id, null)

  tags = merge(
    local.app_ebs_tags,
    { Name = "${var.eks.cluster_name}-fileshare" }
  )
}

locals {
  app_ebs_volume_id = local.app_ebs_enabled ? aws_ebs_volume.app_fileshare[0].id : var.app_ebs_volume_id
}

resource "aws_security_group_rule" "jumpbox_to_eks_api" {
  count = local.jumpbox_enabled ? 1 : 0

  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  security_group_id        = module.eks.cluster_security_group_id
  source_security_group_id = module.jumpbox_windows[0].security_group_id
  description              = "Allow jumpbox access to EKS API"
}

module "outputs_contract" {
  source = "../modules/outputs_contract"

  outputs = {
    region                     = var.region
    use1_region                = var.use1_region
    app_ebs_volume_id          = local.app_ebs_volume_id
    vpc_id                     = module.vpc.vpc_id
    public_subnet_ids          = module.vpc.public_subnet_ids
    private_subnet_ids         = module.vpc.private_subnet_ids
    cluster_name               = module.eks.cluster_name
    cluster_endpoint           = module.eks.cluster_endpoint
    cluster_ca_data            = module.eks.cluster_ca_data
    rds_endpoint               = module.rds_sqlserver.endpoint
    rds_port                   = module.rds_sqlserver.port
    rds_master_user_secret_arn = module.rds_sqlserver.master_user_secret_arn
    cloudfront_id              = var.cloudfront.enabled ? module.cloudfront[0].distribution_id : null
    cloudfront_domain_name     = var.cloudfront.enabled ? module.cloudfront[0].distribution_domain_name : null
    cloudfront_hosted_zone_id  = var.cloudfront.enabled ? module.cloudfront[0].hosted_zone_id : null
    route53_record_fqdn        = var.cloudfront.enabled && var.route53.enabled ? module.route53[0].record_fqdn : null
    acm_certificate_arn        = module.acm_use1.certificate_arn
    jumpbox_instance_id        = local.jumpbox_enabled ? module.jumpbox_windows[0].instance_id : null
    jumpbox_private_ip         = local.jumpbox_enabled ? module.jumpbox_windows[0].private_ip : null
    jumpbox_public_ip          = local.jumpbox_enabled ? module.jumpbox_windows[0].public_ip : null
    jumpbox_security_group_id  = local.jumpbox_enabled ? module.jumpbox_windows[0].security_group_id : null
    jumpbox_role_arn           = local.jumpbox_enabled ? module.jumpbox_windows[0].iam_role_arn : null
  }
}

