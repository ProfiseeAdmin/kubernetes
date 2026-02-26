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

## Deploy / Add Containers
- Default: run `.\Deploy-Profisee-SingleHost.ps1`.
- On reruns, the script auto-picks the next container name (`profisee-0`, `profisee-1`, `profisee-2`, ...).
- Host port is auto-resolved; if requested port is already used by any docker container, script increments to next free port.
- At the end of each run, script downloads `nginx.conf`, rebuilds upstream `profisee_upstream` from `profisee-*` containers, then reloads nginx.

## Optional Overrides
- Force a base name: `.\Deploy-Profisee-SingleHost.ps1 -ContainerName profisee`
- Request a starting host port: `.\Deploy-Profisee-SingleHost.ps1 -HostAppPort 18080`
