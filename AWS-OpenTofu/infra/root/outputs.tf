output "region" {
  description = "Primary AWS region for the deployment."
  value       = var.region
}

output "use1_region" {
  description = "AWS region for us-east-1 resources."
  value       = var.use1_region
}

output "tags" {
  description = "Default tags applied via the AWS provider."
  value       = var.tags
}

