# RDP via AWS Systems Manager (SSM)

You can get full GUI access to the Windows jumpbox without opening inbound RDP.
This uses SSM port forwarding or Fleet Manager Remote Desktop.

## Option A - Port forwarding (recommended)

Prereqs:
- Session Manager plugin installed
- The instance has the SSM agent (default on Windows AMIs)
- The jumpbox role includes `AmazonSSMManagedInstanceCore`

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
