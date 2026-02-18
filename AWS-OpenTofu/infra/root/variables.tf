variable "region" {
  type        = string
  description = "Primary AWS region for the deployment."
}

variable "use1_region" {
  type        = string
  default     = "us-east-1"
  description = "AWS region for us-east-1 resources (CloudFront ACM certificates)."
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Tags applied to all resources via provider default_tags."
}

variable "settings_bucket" {
  type = object({
    enabled       = optional(bool, true)
    name          = optional(string)
    force_destroy = optional(bool, true)
    kms_key_arn   = optional(string)
    tags          = optional(map(string), {})
  })
  description = "S3 bucket for Settings.yaml and deployment artifacts."

  validation {
    condition     = !try(var.settings_bucket.enabled, true) || (try(var.settings_bucket.name, "") != "")
    error_message = "settings_bucket.name is required when settings_bucket.enabled is true."
  }
}

variable "app_ebs" {
  type = object({
    enabled           = optional(bool, true)
    availability_zone = optional(string)
    size_gb           = optional(number, 5)
    type              = optional(string, "gp3")
    iops              = optional(number)
    throughput        = optional(number)
    encrypted         = optional(bool, true)
    kms_key_id        = optional(string)
    tags              = optional(map(string), {})
  })
  default     = {}
  description = "EBS volume configuration for the app fileshare."
}

variable "app_ebs_volume_id" {
  type        = string
  default     = null
  description = "Optional existing EBS volume ID for the app fileshare (used only when app_ebs.enabled is false)."
}

variable "platform_deployer" {
  type = object({
    enabled      = optional(bool, false)
    image_uri    = optional(string)
    cpu          = optional(number, 1024)
    memory       = optional(number, 2048)
    settings_key = optional(string)
    tags         = optional(map(string), {})
    environment  = optional(map(string), {})
    secret_arns  = optional(map(string), {})
  })
  default     = {}
  description = "Fargate one-shot deployer for platform components (Traefik/addons)."

  validation {
    condition     = !try(var.platform_deployer.enabled, false) || (try(var.platform_deployer.image_uri, "") != "")
    error_message = "platform_deployer.image_uri is required when platform_deployer.enabled is true."
  }

  validation {
    condition     = !try(var.platform_deployer.enabled, false) || try(var.settings_bucket.enabled, true)
    error_message = "settings_bucket.enabled must be true when platform_deployer.enabled is true."
  }
}

variable "db_init" {
  type = object({
    enabled     = optional(bool, false)
    image_uri   = optional(string, "profisee.azurecr.io/profiseeplatformdev:aws-ecs-tools-latest")
    cpu         = optional(number, 512)
    memory      = optional(number, 1024)
    tags        = optional(map(string), {})
    environment = optional(map(string), {})
    secret_arns = optional(map(string), {})
  })
  default     = { enabled = true }
  description = "Fargate one-shot DB initializer for creating app SQL login/user."

  validation {
    condition     = !try(var.db_init.enabled, false) || (try(var.db_init.image_uri, "") != "")
    error_message = "db_init.image_uri is required when db_init.enabled is true."
  }

  validation {
    condition     = try(var.db_init.enabled, false) == true
    error_message = "db_init.enabled must be true (DB init is required)."
  }

  validation {
    condition     = !try(var.db_init.enabled, false) || try(var.rds_sqlserver.manage_master_user_password, true)
    error_message = "rds_sqlserver.manage_master_user_password must be true when db_init.enabled is true."
  }

  validation {
    condition     = !try(var.db_init.enabled, false) || (try(var.rds_sqlserver.db_name, "") != "")
    error_message = "rds_sqlserver.db_name must be set when db_init.enabled is true (app database name)."
  }
}

variable "app_deploy" {
  type = object({
    enabled      = optional(bool, true)
    release_name = optional(string, "profiseeplatform")
    namespace    = optional(string, "profisee")
  })
  default     = {}
  description = "App deployment toggles for the db_init ECS task (Stage E)."
}

variable "vpc" {
  type = object({
    name                 = string
    cidr_block           = string
    azs                  = list(string)
    public_subnet_cidrs  = list(string)
    private_subnet_cidrs = list(string)
    enable_nat_gateway   = optional(bool, true)
    single_nat_gateway   = optional(bool, true)
    enable_dns_hostnames = optional(bool, true)
    enable_dns_support   = optional(bool, true)
    public_subnet_tags   = optional(map(string), {})
    private_subnet_tags  = optional(map(string), {})
    vpc_tags             = optional(map(string), {})
    tags                 = optional(map(string), {})
  })
  description = "VPC configuration."
}

variable "eks" {
  type = object({
    cluster_name            = string
    cluster_version         = string
    authentication_mode     = optional(string, "API_AND_CONFIG_MAP")
    install_vpc_cni_addon   = optional(bool, true)
    install_ebs_csi_addon   = optional(bool, true)
    endpoint_public_access  = optional(bool, false)
    endpoint_private_access = optional(bool, true)
    enabled_cluster_log_types = optional(
      list(string),
      ["api", "audit", "authenticator"]
    )
    cluster_kms_key_arn = optional(string)
    linux_node_group = object({
      instance_types = list(string)
      min_size       = number
      max_size       = number
      desired_size   = number
      disk_size      = optional(number, 50)
      capacity_type  = optional(string, "ON_DEMAND")
    })
    windows_node_group = object({
      instance_types = list(string)
      min_size       = number
      max_size       = number
      desired_size   = number
      disk_size      = optional(number, 50)
      capacity_type  = optional(string, "ON_DEMAND")
    })
    tags = optional(map(string), {})
  })
  description = "EKS cluster and node group configuration."
}

variable "rds_sqlserver" {
  type = object({
    identifier                    = string
    engine_version                = string
    instance_class                = string
    allocated_storage             = number
    max_allocated_storage         = optional(number)
    storage_type                  = optional(string, "gp3")
    iops                          = optional(number)
    storage_encrypted             = optional(bool, true)
    kms_key_arn                   = optional(string)
    db_name                       = optional(string) # App DB name created by db_init (not the RDS initial DB)
    master_username               = string
    manage_master_user_password   = optional(bool, true)
    master_user_secret_kms_key_id = optional(string)
    allowed_security_group_ids    = optional(list(string), [])
    backup_retention_days         = optional(number, 0)
    multi_az                      = optional(bool, false)
    publicly_accessible           = optional(bool, false)
    deletion_protection           = optional(bool, false)
    tags                          = optional(map(string), {})
  })
  description = "RDS SQL Server configuration."
}

variable "kms" {
  type = object({
    keys = optional(map(object({
      description             = string
      enable_key_rotation     = optional(bool, true)
      deletion_window_in_days = optional(number, 7)
      alias                   = optional(string)
    })), {})
    tags = optional(map(string), {})
  })
  default     = {}
  description = "KMS keys configuration."
}

variable "secrets" {
  type = object({
    secrets = optional(map(object({
      name                    = string
      description             = optional(string, "")
      kms_key_arn             = optional(string)
      recovery_window_in_days = optional(number, 7)
      policy_json             = optional(string)
      tags                    = optional(map(string), {})
    })), {})
    tags = optional(map(string), {})
  })
  default     = {}
  description = "Secrets Manager configuration."
}

variable "acm" {
  type = object({
    domain_name               = string
    subject_alternative_names = optional(list(string), [])
    hosted_zone_id            = string
    validation_method         = optional(string, "DNS")
    create_route53_records    = optional(bool, true)
    tags                      = optional(map(string), {})
  })
  description = "ACM certificate configuration (us-east-1)."
}

variable "cloudfront" {
  type = object({
    enabled                  = optional(bool, true)
    aliases                  = optional(list(string), [])
    origin_domain_name       = optional(string)
    origin_id                = optional(string, "origin")
    origin_protocol_policy   = optional(string, "https-only")
    origin_ssl_protocols     = optional(list(string), ["TLSv1.2"])
    origin_read_timeout      = optional(number, 60)
    origin_keepalive_timeout = optional(number, 60)
    origin_custom_headers    = optional(map(string), {})
    price_class              = optional(string, "PriceClass_100")
    web_acl_id               = optional(string)
    enable_logging           = optional(bool, false)
    logging_bucket           = optional(string)
    tags                     = optional(map(string), {})
  })
  description = "CloudFront distribution configuration."

  validation {
    condition = !var.cloudfront.enabled || (
      var.cloudfront.origin_domain_name != null &&
      var.cloudfront.origin_domain_name != ""
    )
    error_message = "cloudfront.origin_domain_name is required when cloudfront.enabled is true."
  }
}

variable "route53" {
  type = object({
    enabled                = optional(bool, true)
    hosted_zone_id         = optional(string)
    record_name            = optional(string)
    record_type            = optional(string, "A")
    evaluate_target_health = optional(bool, false)
  })
  description = "Route53 record configuration for CloudFront."

  validation {
    condition = !var.route53.enabled || (
      var.route53.hosted_zone_id != null &&
      var.route53.hosted_zone_id != "" &&
      var.route53.record_name != null &&
      var.route53.record_name != ""
    )
    error_message = "route53.hosted_zone_id and route53.record_name are required when route53.enabled is true."
  }
}

variable "jumpbox" {
  type = object({
    enabled             = optional(bool, false)
    name                = optional(string, "jumpbox")
    subnet_id           = optional(string)
    instance_type       = optional(string, "m6i.large")
    ami_id              = optional(string)
    key_name            = optional(string)
    iam_policy_arns     = optional(list(string), [])
    assume_role_arn     = optional(string)
    associate_public_ip = optional(bool, false)
    root_volume_size_gb = optional(number, 80)
    enable_rdp_ingress  = optional(bool, false)
    allowed_rdp_cidrs   = optional(list(string), [])
    user_data           = optional(string)
    tags                = optional(map(string), {})
  })
  default     = {}
  description = "Windows jumpbox configuration."
}

