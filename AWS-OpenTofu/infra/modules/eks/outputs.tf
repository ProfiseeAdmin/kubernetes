output "cluster_name" {
  description = "EKS cluster name."
  value       = var.cluster_name
}

output "cluster_endpoint" {
  description = "EKS cluster API endpoint."
  value       = null
}

output "cluster_ca_data" {
  description = "Base64-encoded certificate authority data."
  value       = null
}

output "cluster_security_group_id" {
  description = "Cluster security group ID."
  value       = null
}

output "oidc_provider_arn" {
  description = "OIDC provider ARN for IRSA."
  value       = null
}

output "linux_node_group_name" {
  description = "Linux node group name."
  value       = null
}

output "windows_node_group_name" {
  description = "Windows node group name."
  value       = null
}

