variable "domain_name" {
  type        = string
  description = "Primary domain name for the ACM certificate."
}

variable "subject_alternative_names" {
  type        = list(string)
  default     = []
  description = "Subject alternative names for the certificate."
}

variable "hosted_zone_id" {
  type        = string
  description = "Route53 hosted zone ID for DNS validation."
}

variable "validation_method" {
  type        = string
  default     = "DNS"
  description = "ACM validation method."
}

variable "create_route53_records" {
  type        = bool
  default     = true
  description = "Whether to create Route53 validation records."
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Tags applied to ACM resources."
}

