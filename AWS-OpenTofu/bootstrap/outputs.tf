output "region" {
  description = "AWS region used for bootstrap resources."
  value       = var.region
}

output "state_bucket_name" {
  description = "S3 bucket name used for OpenTofu state."
  value       = aws_s3_bucket.state.bucket
}

output "state_bucket_arn" {
  description = "S3 bucket ARN used for OpenTofu state."
  value       = aws_s3_bucket.state.arn
}

output "state_lock_table_name" {
  description = "DynamoDB table name used for state locking."
  value       = aws_dynamodb_table.state_lock.name
}

output "state_kms_key_arn" {
  description = "KMS key ARN used for state encryption."
  value       = aws_kms_key.state.arn
}

output "state_kms_key_id" {
  description = "KMS key ID used for state encryption."
  value       = aws_kms_key.state.key_id
}

output "state_kms_alias" {
  description = "KMS alias for the state key."
  value       = aws_kms_alias.state.name
}

output "backend_config" {
  description = "Backend config values for OpenTofu."
  value = {
    bucket         = aws_s3_bucket.state.bucket
    key            = var.state_key
    region         = var.region
    dynamodb_table = aws_dynamodb_table.state_lock.name
    encrypt        = true
    kms_key_id     = aws_kms_key.state.arn
  }
}

output "backend_hcl" {
  description = "Rendered backend.hcl content for OpenTofu."
  value = templatefile("${path.module}/templates/backend.hcl.tmpl", {
    state_bucket = aws_s3_bucket.state.bucket
    state_key    = var.state_key
    region       = var.region
    lock_table   = aws_dynamodb_table.state_lock.name
    kms_key_id   = aws_kms_key.state.arn
  })
}

output "deploy_role_arn" {
  description = "IAM role ARN for deployments (null if not created)."
  value       = var.create_deploy_role ? aws_iam_role.deploy[0].arn : null
}

output "deploy_role_name" {
  description = "IAM role name for deployments (null if not created)."
  value       = var.create_deploy_role ? aws_iam_role.deploy[0].name : null
}

