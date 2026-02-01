# Quickstart (GitHub Actions - Optional)

This repo is designed to run **locally first**. If a customer wants automation,
they can enable GitHub Actions in their **own fork**.

## Recommended approach

1. Fork this repo into the customer's GitHub org.
2. Copy workflows from:
   - `.github/workflows-disabled/*.example`
   into:
   - `.github/workflows/`
3. Create a GitHub secret named `AWS_ROLE_ARN` with the deploy role ARN.
4. Use GitHub OIDC to assume the deploy role (no static AWS keys).
5. Use environment approvals for apply steps.

## Notes

- The workflows are intentionally disabled in the public repo.
- OpenTofu can be installed via `opentofu/setup-opentofu`.
- Follow the same staged flow as local quickstart:
  Stage A (deployment folder) → Stage B (bootstrap) → Stage C (core infra) → Platform → CloudFront/DNS.
- For private EKS, the deploy workflow requires a self‑hosted runner with VPC access.

