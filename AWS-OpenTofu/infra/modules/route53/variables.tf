variable "hosted_zone_id" {
  type        = string
  description = "Route53 hosted zone ID."
}

variable "record_name" {
  type        = string
  description = "DNS record name."
}

variable "record_type" {
  type        = string
  default     = "A"
  description = "DNS record type."
}

variable "alias_name" {
  type        = string
  description = "Alias target DNS name."
}

variable "alias_zone_id" {
  type        = string
  default     = null
  description = "Alias target hosted zone ID (required for alias record types such as A/AAAA)."
}

variable "evaluate_target_health" {
  type        = bool
  default     = false
  description = "Whether Route53 evaluates target health."
}

variable "ttl" {
  type        = number
  default     = 60
  description = "TTL for non-alias records (used for CNAME)."
}

