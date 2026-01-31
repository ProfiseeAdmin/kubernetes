output "cluster_name" {
  description = "EKS cluster name."
  value       = var.cluster_name
}

output "cluster_endpoint" {
  description = "EKS cluster API endpoint."
  value       = aws_eks_cluster.this.endpoint
}

output "cluster_ca_data" {
  description = "Base64-encoded certificate authority data."
  value       = aws_eks_cluster.this.certificate_authority[0].data
}

output "cluster_security_group_id" {
  description = "Cluster security group ID."
  value       = aws_eks_cluster.this.vpc_config[0].cluster_security_group_id
}

output "oidc_provider_arn" {
  description = "OIDC provider ARN for IRSA."
  value       = aws_iam_openid_connect_provider.this.arn
}

output "linux_node_group_name" {
  description = "Linux node group name."
  value       = aws_eks_node_group.linux.node_group_name
}

output "windows_node_group_name" {
  description = "Windows node group name."
  value       = aws_eks_node_group.windows.node_group_name
}

