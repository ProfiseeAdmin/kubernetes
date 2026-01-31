variable "enabled" {
  type        = bool
  default     = true
  description = "Whether to create the CloudFront distribution."
}

variable "aliases" {
  type        = list(string)
  default     = []
  description = "Alternate domain names (CNAMEs) for the distribution."
}

variable "acm_certificate_arn" {
  type        = string
  description = "ACM certificate ARN in us-east-1."
}

variable "origin_domain_name" {
  type        = string
  description = "Origin domain name (e.g., NLB DNS name)."
}

variable "origin_id" {
  type        = string
  default     = "origin"
  description = "Origin identifier."
}

variable "origin_protocol_policy" {
  type        = string
  default     = "https-only"
  description = "Protocol policy for origin connections."
}

variable "origin_ssl_protocols" {
  type        = list(string)
  default     = ["TLSv1.2"]
  description = "SSL protocols allowed when connecting to the origin."
}

variable "origin_read_timeout" {
  type        = number
  default     = 60
  description = "Origin read timeout in seconds."
}

variable "origin_keepalive_timeout" {
  type        = number
  default     = 60
  description = "Origin keepalive timeout in seconds."
}

variable "origin_custom_headers" {
  type        = map(string)
  default     = {}
  description = "Custom headers sent to the origin. Values are stored in state; do not use secrets."
}

variable "price_class" {
  type        = string
  default     = "PriceClass_100"
  description = "CloudFront price class."
}

variable "web_acl_id" {
  type        = string
  default     = null
  description = "WAFv2 Web ACL ID to associate with the distribution."
}

variable "enable_logging" {
  type        = bool
  default     = false
  description = "Whether to enable access logging."
}

variable "logging_bucket" {
  type        = string
  default     = null
  description = "S3 bucket for access logs (required if enable_logging is true)."

  validation {
    condition     = !var.enable_logging || (var.logging_bucket != null && var.logging_bucket != "")
    error_message = "logging_bucket must be set when enable_logging is true."
  }
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Tags applied to CloudFront resources."
}

