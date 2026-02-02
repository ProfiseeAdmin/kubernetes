# RDP via AWS Systems Manager (SSM)

You can get full GUI access to the Windows jumpbox without opening inbound RDP.
Use **Fleet Manager Remote Desktop** (recommended).

## Fleet Manager Remote Desktop (recommended)

This avoids CredSSP/NTLM issues on your local machine. It uses the
browser-based RDP client inside AWS Systems Manager.

Steps:
1. AWS Console → Systems Manager → Fleet Manager
2. Select the jumpbox instance
3. Click **Remote Desktop**
4. Log in as `Administrator` with the instance password (decrypted using your PEM)

> If you prefer **classic RDP**, you must supply `jumpbox.key_name` in your
> config and keep the `.pem` file locally. AWS only lets you download the PEM
> once at key pair creation time.

Create a key pair (only if you plan to use classic RDP):

```powershell
$secretsDir = ".\\customer-deployments\\acme-prod\\secrets"
New-Item -ItemType Directory -Path $secretsDir -Force | Out-Null
aws ec2 create-key-pair --region us-east-1 --key-name profisee-jumpbox-key `
  --query "KeyMaterial" --output text | Out-File -FilePath "$secretsDir\\profisee-jumpbox-key.pem" -Encoding ascii
```

To get the Windows Administrator password (if using a key pair):

```powershell
aws ec2 get-password-data `
  --instance-id i-xxxxxxxxxxxxxxxxx `
  --priv-launch-key C:\path\to\key.pem
```
