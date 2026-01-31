locals {
  origin_headers = [
    for name, value in var.origin_custom_headers : {
      name  = name
      value = value
    }
  ]
}

resource "aws_cloudfront_cache_policy" "no_cache" {
  name        = "${replace(var.origin_id, "_", "-")}-no-cache"
  comment     = "Disable caching for dynamic/WebSocket traffic."
  default_ttl = 0
  max_ttl     = 0
  min_ttl     = 0

  parameters_in_cache_key_and_forwarded_to_origin {
    cookies_config {
      cookie_behavior = "none"
    }

    headers_config {
      header_behavior = "none"
    }

    query_strings_config {
      query_string_behavior = "none"
    }

    enable_accept_encoding_brotli = true
    enable_accept_encoding_gzip   = true
  }
}

resource "aws_cloudfront_origin_request_policy" "all_viewer" {
  name    = "${replace(var.origin_id, "_", "-")}-all-viewer"
  comment = "Forward all viewer headers, cookies, and query strings."

  cookies_config {
    cookie_behavior = "all"
  }

  headers_config {
    header_behavior = "allViewer"
  }

  query_strings_config {
    query_string_behavior = "all"
  }
}

resource "aws_cloudfront_distribution" "this" {
  enabled         = var.enabled
  is_ipv6_enabled = true
  price_class     = var.price_class
  aliases         = var.aliases
  web_acl_id      = var.web_acl_id

  origin {
    domain_name = var.origin_domain_name
    origin_id   = var.origin_id

    dynamic "custom_header" {
      for_each = local.origin_headers
      content {
        name  = custom_header.value.name
        value = custom_header.value.value
      }
    }

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = var.origin_protocol_policy
      origin_ssl_protocols   = var.origin_ssl_protocols
      origin_read_timeout    = var.origin_read_timeout
      origin_keepalive_timeout = var.origin_keepalive_timeout
    }
  }

  default_cache_behavior {
    target_origin_id       = var.origin_id
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods         = ["GET", "HEAD"]
    compress               = true

    cache_policy_id          = aws_cloudfront_cache_policy.no_cache.id
    origin_request_policy_id = aws_cloudfront_origin_request_policy.all_viewer.id
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = var.acm_certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }

  dynamic "logging_config" {
    for_each = var.enable_logging ? [1] : []
    content {
      bucket          = var.logging_bucket
      include_cookies = false
      prefix          = "cloudfront/"
    }
  }

  tags = var.tags
}

