output "vpc_id" {
  description = "VPC ID."
  value       = null
}

output "vpc_cidr_block" {
  description = "VPC CIDR block."
  value       = var.cidr_block
}

output "public_subnet_ids" {
  description = "Public subnet IDs."
  value       = []
}

output "private_subnet_ids" {
  description = "Private subnet IDs."
  value       = []
}

