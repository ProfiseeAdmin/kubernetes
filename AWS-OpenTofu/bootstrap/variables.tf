variable "region" {
  type        = string
  description = "AWS region to deploy bootstrap resources."
}

variable "state_bucket_name" {
  type        = string
  description = "Globally unique S3 bucket name for OpenTofu state."
}

variable "state_bucket_force_destroy" {
  type        = bool
  default     = false
  description = "Allow destroying the state bucket even if it contains objects."
}

variable "state_lock_table_name" {
  type        = string
  default     = "opentofu-state-locks"
  description = "DynamoDB table name for state locking."
}

variable "state_kms_alias" {
  type        = string
  default     = "alias/opentofu-state"
  description = "KMS alias for the state bucket key."
}

variable "state_key" {
  type        = string
  default     = "infra/root.tfstate"
  description = "Default key path for backend.hcl output (override per deployment)."
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Tags applied to all bootstrap resources."
}

variable "create_deploy_role" {
  type        = bool
  default     = false
  description = "Whether to create an IAM role that customers can use for deployments."
}

variable "deploy_role_name" {
  type        = string
  default     = "opentofu-deploy"
  description = "Name for the optional deployment role."
}

variable "deploy_role_trusted_principal_arns" {
  type        = list(string)
  default     = []
  description = "List of IAM principal ARNs allowed to assume the deploy role."

  validation {
    condition     = !var.create_deploy_role || length(var.deploy_role_trusted_principal_arns) > 0
    error_message = "When create_deploy_role is true, deploy_role_trusted_principal_arns must not be empty."
  }
}

variable "deploy_role_policy_arns" {
  type        = list(string)
  default     = []
  description = "Policy ARNs to attach to the deploy role."

  validation {
    condition     = !var.create_deploy_role || length(var.deploy_role_policy_arns) > 0
    error_message = "When create_deploy_role is true, deploy_role_policy_arns must not be empty."
  }
}

