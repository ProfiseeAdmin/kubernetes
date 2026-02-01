# RDP via AWS Systems Manager (SSM)

You can get full GUI access to the Windows jumpbox without opening inbound RDP.
This uses SSM port forwarding or Fleet Manager Remote Desktop.

## Option A - Port forwarding (recommended)

Prereqs:
- Session Manager plugin installed
- The instance has the SSM agent (default on Windows AMIs)
- The jumpbox role includes `AmazonSSMManagedInstanceCore`
- No EC2 key pair is required for port forwarding

Start a port‑forwarding session to the instance:

```powershell
aws ssm start-session `
  --target i-xxxxxxxxxxxxxxxxx `
  --document-name AWS-StartPortForwardingSession `
  --parameters "portNumber=3389,localPortNumber=13389"
```

Then RDP to:
```
localhost:13389
```

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

## Option B - Fleet Manager Remote Desktop

In AWS Console:
Systems Manager → Fleet Manager → select instance → Remote Desktop.

This also uses SSM and does not require inbound 3389.
