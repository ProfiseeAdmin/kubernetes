# Template deployment folder

This folder is a safe-by-default template for customer deployments.

## Staged deployment flow

The infra layer supports staging so you can bring up core services first, then
add CloudFront + DNS only after the Kubernetes ingress/NLB exists.

### Stage A - Core infra

Bring up VPC + EKS + RDS + ACM (us-east-1). Leave CloudFront + Route53 disabled:

```json
"cloudfront": {
  "enabled": false
},
"route53": {
  "enabled": false
}
```

Apply infra. Then deploy the platform layer (NGINX OSS ingress/NLB).

### Stage B - Platform

Deploy Kubernetes add-ons and the NGINX OSS ingress controller. This creates the public NLB DNS name
that CloudFront uses as the origin.

### Stage C - Edge

Enable CloudFront + Route53 and set the origin domain name:

```json
"cloudfront": {
  "enabled": true,
  "origin_domain_name": "nlb-abc123.us-east-1.elb.amazonaws.com",
  "aliases": ["app.example.com"],
  "origin_custom_headers": {}
},
"route53": {
  "enabled": true,
  "hosted_zone_id": "Z1234567890ABC",
  "record_name": "app.example.com"
}
```

Re-apply infra. CloudFront and the Route53 alias record will be created.

## Important notes

- CloudFront origin headers are stored in state. Do not put secrets in
  `origin_custom_headers`. Use a different mechanism (e.g., manual update or
  runtime verification) if you need an origin secret.

