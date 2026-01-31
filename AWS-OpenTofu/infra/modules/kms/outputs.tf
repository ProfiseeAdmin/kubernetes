output "key_arns" {
  description = "Map of KMS key ARNs by key name."
  value       = { for key_name, key in aws_kms_key.this : key_name => key.arn }
}

output "key_ids" {
  description = "Map of KMS key IDs by key name."
  value       = { for key_name, key in aws_kms_key.this : key_name => key.key_id }
}

