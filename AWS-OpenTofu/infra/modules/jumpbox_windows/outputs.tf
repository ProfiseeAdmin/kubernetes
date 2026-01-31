output "instance_id" {
  description = "Jumpbox instance ID."
  value       = aws_instance.this.id
}

output "private_ip" {
  description = "Jumpbox private IP."
  value       = aws_instance.this.private_ip
}

output "public_ip" {
  description = "Jumpbox public IP (if any)."
  value       = aws_instance.this.public_ip
}

output "security_group_id" {
  description = "Jumpbox security group ID."
  value       = aws_security_group.this.id
}

output "iam_role_arn" {
  description = "IAM role ARN attached to the jumpbox."
  value       = aws_iam_role.ssm.arn
}
