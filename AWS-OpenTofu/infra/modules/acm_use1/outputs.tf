output "certificate_arn" {
  description = "ACM certificate ARN."
  value       = aws_acm_certificate.this.arn
}

output "validation_record_fqdns" {
  description = "Route53 validation record FQDNs."
  value       = [for record in aws_route53_record.validation : record.fqdn]
}

