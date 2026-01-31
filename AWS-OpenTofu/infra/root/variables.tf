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
    endpoint_public_access  = optional(bool, true)
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
    identifier                  = string
    engine_version              = string
    instance_class              = string
    allocated_storage           = number
    max_allocated_storage       = optional(number)
    storage_type                = optional(string, "gp3")
    iops                        = optional(number)
    storage_encrypted           = optional(bool, true)
    kms_key_arn                 = optional(string)
    db_name                     = optional(string)
    master_username             = string
    manage_master_user_password = optional(bool, true)
    master_user_secret_kms_key_id = optional(string)
    allowed_security_group_ids  = optional(list(string), [])
    backup_retention_days       = optional(number, 7)
    multi_az                    = optional(bool, false)
    publicly_accessible         = optional(bool, false)
    deletion_protection         = optional(bool, true)
    tags                        = optional(map(string), {})
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
    domain_name             = string
    subject_alternative_names = optional(list(string), [])
    hosted_zone_id          = string
    validation_method       = optional(string, "DNS")
    create_route53_records  = optional(bool, true)
    tags                    = optional(map(string), {})
  })
  description = "ACM certificate configuration (us-east-1)."
}

variable "cloudfront" {
  type = object({
    enabled                = optional(bool, true)
    aliases                = optional(list(string), [])
    origin_domain_name     = string
    origin_id              = optional(string, "origin")
    origin_protocol_policy = optional(string, "https-only")
    origin_ssl_protocols   = optional(list(string), ["TLSv1.2"])
    origin_read_timeout    = optional(number, 60)
    origin_keepalive_timeout = optional(number, 60)
    origin_custom_header_name = optional(string, "X-Origin-Verify")
    price_class            = optional(string, "PriceClass_100")
    web_acl_id             = optional(string)
    enable_logging         = optional(bool, false)
    logging_bucket         = optional(string)
    tags                   = optional(map(string), {})
  })
  description = "CloudFront distribution configuration."
}

variable "cloudfront_origin_custom_header_value" {
  type        = string
  default     = null
  sensitive   = true
  description = "Custom origin header value for CloudFront (use with care; ends up in state)."
}

variable "route53" {
  type = object({
    hosted_zone_id         = string
    record_name            = string
    record_type            = optional(string, "A")
    evaluate_target_health = optional(bool, false)
  })
  description = "Route53 record configuration for CloudFront."
}

