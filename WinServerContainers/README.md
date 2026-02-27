# WinServerContainers Quick Notes

## Prereqs
- Run deployment as Administrator.
- Windows feature `Containers` must be installed.
- Windows feature `Hyper-V` must be installed.
- Docker Engine (Docker CE) is installed/updated automatically by `Deploy-Profisee-SingleHost.ps1`.

## After VM Reboot
- Ensure nginx is running before testing access.
- Safe nginx command pattern:
```powershell
Set-Location C:\nginx
if (Get-Process nginx -ErrorAction SilentlyContinue) {
  nginx -s reload
} else {
  start nginx
}
```

## Deploy
- Default: run `.\Deploy-Profisee-SingleHost.ps1`.
- Script deploys a single container; default name is `profisee-0`.
- On rerun with the same name, existing container is removed and recreated.
- Host port is fixed to `HostAppPort` (default `18080`).
- At the end of each run, script downloads `nginx.conf` and reloads nginx.

## Optional Overrides
- Set container name: `.\Deploy-Profisee-SingleHost.ps1 -ContainerName profisee-0`
- Set host port: `.\Deploy-Profisee-SingleHost.ps1 -HostAppPort 18080`
