# Operations, Upgrade, Rollback

## Infra changes

Use OpenTofu for all infra changes:

```powershell
.\scripts\tofu-plan.ps1 -DeploymentName <name>
.\scripts\tofu-apply.ps1 -DeploymentName <name>
```

## Platform changes

Apply Helm changes via your platform scripts:

```powershell
.\scripts\deploy-platform.ps1 <name>
```

## Rolling back

- Revert the repo to a known good commit and re‑apply.
- For application rollback, use Helm rollback or redeploy the previous image tag.

## RDS

- Backups are enabled by default (retention configurable).
- For destructive changes, take a manual snapshot before apply.

