resource "aws_route53_record" "this" {
  zone_id         = var.hosted_zone_id
  name            = var.record_name
  type            = upper(var.record_type)
  allow_overwrite = true
  ttl             = upper(var.record_type) == "CNAME" ? var.ttl : null
  records         = upper(var.record_type) == "CNAME" ? [var.alias_name] : null

  lifecycle {
    precondition {
      condition     = upper(var.record_type) == "CNAME" || (var.alias_zone_id != null && trimspace(var.alias_zone_id) != "")
      error_message = "alias_zone_id is required when record_type is not CNAME."
    }
  }

  dynamic "alias" {
    for_each = upper(var.record_type) == "CNAME" ? [] : [1]
    content {
      name                   = var.alias_name
      zone_id                = var.alias_zone_id
      evaluate_target_health = var.evaluate_target_health
    }
  }
}

