variable "name" {
  type        = string
  description = "Name prefix for the jumpbox instance."
}

variable "vpc_id" {
  type        = string
  description = "VPC ID for the jumpbox security group."
}

variable "subnet_id" {
  type        = string
  description = "Subnet ID for the jumpbox instance."
}

variable "instance_type" {
  type        = string
  default     = "m6i.large"
  description = "EC2 instance type for the Windows jumpbox."
}

variable "ami_id" {
  type        = string
  default     = null
  description = "Override AMI ID for the Windows jumpbox (optional)."
}

variable "key_name" {
  type        = string
  default     = null
  description = "EC2 key pair name for RDP access (optional if using SSM port forwarding)."
}

variable "iam_policy_arns" {
  type        = list(string)
  default     = []
  description = "Additional IAM policy ARNs to attach to the jumpbox role."
}

variable "assume_role_arn" {
  type        = string
  default     = null
  description = "Optional role ARN the jumpbox can assume via STS."
}

variable "associate_public_ip" {
  type        = bool
  default     = false
  description = "Whether to associate a public IP address."
}

variable "root_volume_size_gb" {
  type        = number
  default     = 80
  description = "Root volume size in GB."
}

variable "enable_rdp_ingress" {
  type        = bool
  default     = false
  description = "Whether to allow inbound RDP (3389) from allowed_rdp_cidrs."
}

variable "allowed_rdp_cidrs" {
  type        = list(string)
  default     = []
  description = "CIDR blocks allowed to RDP to the jumpbox."
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Tags applied to jumpbox resources."
}

variable "user_data" {
  type        = string
  default     = null
  description = "Windows user data script (optional). If null/empty, a default bootstrap script is used."
}
