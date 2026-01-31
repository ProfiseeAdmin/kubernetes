variable "identifier" {
  type        = string
  description = "RDS instance identifier."
}

variable "engine_version" {
  type        = string
  description = "SQL Server engine version."
}

variable "instance_class" {
  type        = string
  description = "RDS instance class."
}

variable "allocated_storage" {
  type        = number
  description = "Allocated storage in GB."
}

variable "max_allocated_storage" {
  type        = number
  default     = null
  description = "Maximum allocated storage in GB (autoscaling)."
}

variable "storage_type" {
  type        = string
  default     = "gp3"
  description = "Storage type (gp3, gp2, io1)."
}

variable "iops" {
  type        = number
  default     = null
  description = "Provisioned IOPS (required for io1, optional for gp3)."
}

variable "storage_encrypted" {
  type        = bool
  default     = true
  description = "Whether to enable storage encryption."
}

variable "kms_key_arn" {
  type        = string
  default     = null
  description = "KMS key ARN for storage encryption."
}

variable "db_name" {
  type        = string
  default     = null
  description = "Initial database name (optional)."
}

variable "master_username" {
  type        = string
  description = "Master username."
}

variable "manage_master_user_password" {
  type        = bool
  default     = true
  description = "Use AWS-managed Secrets Manager password."
}

variable "master_user_secret_kms_key_id" {
  type        = string
  default     = null
  description = "KMS key ID/ARN for the managed master user secret."
}

variable "vpc_id" {
  type        = string
  description = "VPC ID for the database."
}

variable "subnet_ids" {
  type        = list(string)
  description = "Subnet IDs for the DB subnet group."
}

variable "allowed_security_group_ids" {
  type        = list(string)
  default     = []
  description = "Security group IDs allowed to access the database."
}

variable "backup_retention_days" {
  type        = number
  default     = 7
  description = "Backup retention period in days."
}

variable "multi_az" {
  type        = bool
  default     = false
  description = "Whether to enable Multi-AZ."
}

variable "publicly_accessible" {
  type        = bool
  default     = false
  description = "Whether the DB instance is publicly accessible."
}

variable "deletion_protection" {
  type        = bool
  default     = true
  description = "Whether to enable deletion protection."
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Tags applied to RDS resources."
}

