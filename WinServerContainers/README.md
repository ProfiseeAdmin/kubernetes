# WinServerContainers Quick Notes

## Hardware Prerequisites
- Profisee Windows container image is currently based on Windows Server 2022.
- Deployment uses Hyper-V isolation; host must have Windows feature `Hyper-V` installed.
- Host must also have Windows feature `Containers` installed.
- Windows Server 2025 with Hyper-V isolation should be able to run Profisee images based on Server 2022, but Profisee recommends matching host OS and container image OS versions whenever possible.

### Quick Feature Enable Script
Run in elevated PowerShell on the host/VM:
```powershell
Install-WindowsFeature -Name Containers,Hyper-V -IncludeManagementTools
Restart-Computer -Force
```

## Deployment Prerequisites
- Run deployment as Administrator.
- Docker Engine (Docker CE) is installed/updated automatically by `Deploy-Profisee-SingleHost.ps1`.
- nginx Open Source for Windows is installed/updated automatically from `nginx.org`.
- `nginx.conf` is downloaded from the WinServerContainers repo during deployment.

## Customer Prep Checklist
- Decide the production FQDN before deployment (example: `app.company.com`).
- Obtain a valid Profisee license (`.plic` file or base64 license string) for this deployment.
- Choose certificate model and prepare TLS assets for the chosen FQDN:
  - Internal CA: server cert/key for FQDN plus root CA certificate for trust injection.
  - Public CA: server cert/key for FQDN.
- Size container CPU/memory conservatively; do not allocate more than about `80-85%` of host resources to avoid starving the OS.
- Prepare IdP configuration (Entra or Okta) before running script:
  - Tenant/authority details (tenant ID for Entra or authority URL for Okta).
  - App client ID and app client secret.
  - Redirect URI in app registration:
    - `https://<FQDN>/<WebAppName>/auth/signin-microsoft`
    - Example: `https://domain.com/profisee/auth/signin-microsoft`
  - Ensure ID tokens are enabled in app registration.
  - OIDC claims mappings guide: `https://support.profisee.com/wikis/profiseeplatform/oidc_provider_info_and_claims_mappings`
  - Group claims setup:
    - Entra groups: `https://support.profisee.com/wikis/profiseeplatform/Managing_security_in_Profisee_using_Entra_ID_Groups`
    - Okta groups: `https://support.profisee.com/wikis/profiseeplatform/Managing_security_in_Profisee_using_Okta_Groups`
    - Caveat: Okta group setup is currently not working as documented; a documentation fix is in progress due to Okta-side changes.
  - Purview prerequisites (if used): `https://support.profisee.com/wikis/profiseeplatform/prerequisites_for_integrating_with_purview`
  - Purview integration uses a separate app registration and its required permissions must receive Global Admin consent/approval.

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

## Helpful Docker Commands
- Important:
  - `Deploy-Profisee-SingleHost.ps1` retains prior run values; on reruns it is often "press Enter through prompts" unless a value changed.
  - Running only `docker run <image>` is not sufficient for Profisee.
  - The container requires deployment environment variables and mounts (provided by `Deploy-Profisee-SingleHost.ps1`).
  - Use the deployment script for normal startup/redeploy instead of a bare `docker run`.
- List running containers:
  - `docker ps`
- List all containers (running + stopped):
  - `docker ps -a`
- Show logs:
  - `docker logs profisee-0`
- Follow logs:
  - `docker logs -f profisee-0`
- Exec into container (PowerShell):
  - `docker exec -it profisee-0 powershell`
- Stop container:
  - `docker stop profisee-0`
- Start container:
  - `docker start profisee-0`
- Restart container:
  - `docker restart profisee-0`
- Remove container (must be stopped):
  - `docker rm profisee-0`
- Force remove container:
  - `docker rm -f profisee-0`
- Inspect effective env vars:
  - `docker inspect profisee-0 --format "{{range .Config.Env}}{{println .}}{{end}}"`
- Show image list:
  - `docker images`

## stop/start vs stop/remove/start
- `docker stop` + `docker start`:
  - Restarts the same container instance.
  - Keeps the same container ID and original runtime config (env vars, port mapping, mounts, entrypoint).
  - Use when you just need to bounce the service.
- `docker stop` + `docker rm` + `docker run` (or redeploy script):
  - Deletes the old container and creates a new one.
  - Gets a new container ID and applies current script inputs/image/config.
  - Use when config/image/env/mounts changed or when you want a clean recreate.
