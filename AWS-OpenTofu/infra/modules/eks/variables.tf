variable "cluster_name" {
  type        = string
  description = "EKS cluster name."
}

variable "cluster_version" {
  type        = string
  description = "Kubernetes version for the EKS control plane."
}

variable "vpc_id" {
  type        = string
  description = "VPC ID for the EKS cluster."
}

variable "private_subnet_ids" {
  type        = list(string)
  description = "Private subnet IDs for EKS node groups."
}

variable "public_subnet_ids" {
  type        = list(string)
  default     = []
  description = "Public subnet IDs (optional)."
}

variable "endpoint_public_access" {
  type        = bool
  default     = true
  description = "Whether the Kubernetes API server endpoint is publicly accessible."
}

variable "endpoint_private_access" {
  type        = bool
  default     = true
  description = "Whether the Kubernetes API server endpoint is privately accessible."
}

variable "enabled_cluster_log_types" {
  type        = list(string)
  default     = ["api", "audit", "authenticator"]
  description = "Control plane log types to enable."
}

variable "cluster_kms_key_arn" {
  type        = string
  default     = null
  description = "KMS key ARN for Kubernetes secrets encryption."
}

variable "linux_node_group" {
  type = object({
    instance_types = list(string)
    min_size       = number
    max_size       = number
    desired_size   = number
    disk_size      = optional(number, 50)
    capacity_type  = optional(string, "ON_DEMAND")
    ami_type       = optional(string)
  })
  description = "Linux node group configuration."
}

variable "windows_node_group" {
  type = object({
    instance_types = list(string)
    min_size       = number
    max_size       = number
    desired_size   = number
    disk_size      = optional(number, 50)
    capacity_type  = optional(string, "ON_DEMAND")
    ami_type       = optional(string)
  })
  description = "Windows node group configuration."
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Tags applied to EKS resources."
}

