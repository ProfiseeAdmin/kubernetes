variable "keys" {
  type = map(object({
    description             = string
    enable_key_rotation     = optional(bool, true)
    deletion_window_in_days = optional(number, 7)
    alias                   = optional(string)
  }))
  default     = {}
  description = "Map of KMS keys to create."
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Tags applied to KMS resources."
}

