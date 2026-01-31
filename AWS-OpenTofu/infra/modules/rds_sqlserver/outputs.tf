output "db_instance_arn" {
  description = "RDS instance ARN."
  value       = null
}

output "endpoint" {
  description = "Database endpoint address."
  value       = null
}

output "port" {
  description = "Database port."
  value       = null
}

output "master_user_secret_arn" {
  description = "Secrets Manager ARN for the managed master user password."
  value       = null
}

output "security_group_id" {
  description = "Security group ID for the database."
  value       = null
}

output "subnet_group_name" {
  description = "DB subnet group name."
  value       = null
}

