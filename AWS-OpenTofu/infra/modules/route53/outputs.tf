output "record_fqdn" {
  description = "Route53 record FQDN."
  value       = aws_route53_record.this.fqdn
}

