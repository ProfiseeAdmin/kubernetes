# Uninstall

Uninstall in reverse order of deployment.

## Stage E (Edge)

Disable CloudFront and Route53 in the deployment config:

```json
"cloudfront": { "enabled": false },
"route53": { "enabled": false }
```

Apply:

```powershell
.\scripts\tofu-apply.ps1 -DeploymentName <name>
```

## Stage D (Platform + App)

Remove the app and platform components (Traefik/addons) from the cluster using
your platform deployer or Helm uninstall commands.

## Stage C (Core infra + DB init)

Destroy the core infra:

```powershell
tofu -chdir=infra/root destroy -var-file=..\..\customer-deployments\<name>\config.auto.tfvars.json
```

## Bootstrap (state backend)

Only when you are fully done, destroy the bootstrap stack:

```powershell
tofu -chdir=bootstrap destroy
```

If the state bucket is non‑empty, you must empty it or use
`state_bucket_force_destroy = true` in bootstrap variables.

