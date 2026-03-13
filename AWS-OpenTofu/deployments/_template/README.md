# Template deployment folder

This folder is a safe-by-default template for customer deployments.

## Staged deployment flow

The infra layer supports staging so you can bring up core services first, then
wire DNS after the Kubernetes ingress/NLB exists.

### Stage A - Core infra

Bring up VPC + EKS + RDS + ACM (us-east-1). Then deploy the platform layer
(NGINX OSS ingress/NLB).

### Stage B - Platform

Deploy Kubernetes add-ons and the NGINX OSS ingress controller. This creates the public NLB DNS name
used by Route53.

### Stage C - DNS

Enable Route53 and set the application record:

```json
"route53": {
  "enabled": true,
  "hosted_zone_id": "Z1234567890ABC",
  "record_name": "app.example.com"
}
```

Re-apply infra. Route53 will point to the current ingress load balancer.

