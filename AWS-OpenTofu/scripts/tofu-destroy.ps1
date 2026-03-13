param(
  [Parameter(Mandatory = $true)]
  [string]$DeploymentName,

  [string]$RepoRoot,
  [string]$BackendConfigPath,
  [string]$VarFilePath,
  [string]$ExtraVarFile,
  [switch]$AutoApprove
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Get-Command tofu -ErrorAction SilentlyContinue)) {
  throw "OpenTofu (tofu) is not on PATH. Install OpenTofu and try again."
}

function Get-OptionalProperty($obj, [string]$Name) {
  if ($null -eq $obj) { return $null }
  $prop = $obj.PSObject.Properties[$Name]
  if ($null -eq $prop) { return $null }
  return $prop.Value
}

function Convert-AwsCliOutputToString($Output) {
  if ($null -eq $Output) { return "" }
  if ($Output -is [System.Array]) {
    return (($Output | ForEach-Object { [string]$_ }) -join [Environment]::NewLine).Trim()
  }
  return ([string]$Output).Trim()
}

function Remove-S3BucketContents([string]$Bucket, [string]$Region) {
  $awsCmd = Get-Command aws -ErrorAction SilentlyContinue
  if (-not $awsCmd) {
    Write-Host "AWS CLI not found; skipping S3 purge for $Bucket."
    return
  }

  Write-Host ("Purging S3 bucket contents (including versions): {0}" -f $Bucket)
  $listArgs = @("s3api", "list-object-versions", "--bucket", $Bucket, "--region", $Region, "--output", "json")
  $raw = & aws @listArgs 2>&1
  if ($LASTEXITCODE -ne 0) {
    if ($raw -match "NoSuchBucket") {
      Write-Host "Bucket $Bucket does not exist; skipping purge."
      return
    }
    throw "Failed to list objects in S3 bucket $Bucket (exit code $LASTEXITCODE)."
  }
  if (-not $raw) {
    Write-Host "No objects found in bucket."
    return
  }

  $data = $raw | ConvertFrom-Json
  $objects = @()
  $versions = Get-OptionalProperty $data "Versions"
  $markers = Get-OptionalProperty $data "DeleteMarkers"
  if ($versions) {
    foreach ($v in $versions) {
      $objects += @{ Key = $v.Key; VersionId = $v.VersionId }
    }
  }
  if ($markers) {
    foreach ($m in $markers) {
      $objects += @{ Key = $m.Key; VersionId = $m.VersionId }
    }
  }

  if ($objects.Count -eq 0) {
    Write-Host "Bucket already empty."
    return
  }

  $chunkSize = 1000
  for ($i = 0; $i -lt $objects.Count; $i += $chunkSize) {
    $chunk = $objects[$i..([Math]::Min($i + $chunkSize - 1, $objects.Count - 1))]
    $payload = @{ Objects = $chunk } | ConvertTo-Json -Compress
    $tmp = [System.IO.Path]::GetTempFileName()
    try {
      # Write JSON without BOM to avoid AWS CLI parse errors
      [System.IO.File]::WriteAllText($tmp, $payload, [System.Text.UTF8Encoding]::new($false))
      & aws s3api delete-objects --bucket $Bucket --region $Region --delete ("file://{0}" -f $tmp) | Out-Null
      if ($LASTEXITCODE -ne 0) {
        throw "Failed to delete objects in S3 bucket $Bucket (exit code $LASTEXITCODE)."
      }
    } finally {
      Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    }
  }
}

function Get-VpcIdByName([string]$VpcName, [string]$Region) {
  if (-not $VpcName) { return $null }
  $awsCmd = Get-Command aws -ErrorAction SilentlyContinue
  if (-not $awsCmd) {
    Write-Host "AWS CLI not found; skipping VPC lookup."
    return $null
  }
  $tagName = "$VpcName-vpc"
  $args = @("ec2", "describe-vpcs", "--filters", "Name=tag:Name,Values=$tagName", "--query", "Vpcs[0].VpcId", "--output", "text", "--region", $Region)
  $raw = & aws @args 2>&1
  if ($LASTEXITCODE -ne 0) {
    Write-Host ("Failed to lookup VPC by tag Name={0}: {1}" -f $tagName, $raw)
    return $null
  }
  if ($raw -and $raw -ne "None") { return $raw.Trim() }
  return $null
}

function Remove-LoadBalancers([string]$VpcId, [string]$Region) {
  if (-not $VpcId) { return }
  $awsCmd = Get-Command aws -ErrorAction SilentlyContinue
  if (-not $awsCmd) {
    Write-Host "AWS CLI not found; skipping load balancer cleanup."
    return
  }

  Write-Host ("Checking for load balancers in VPC {0}..." -f $VpcId)

  # ELBv2 (ALB/NLB)
  $lbArgs = @("elbv2", "describe-load-balancers", "--region", $Region, "--query", "LoadBalancers[?VpcId=='$VpcId'].{Arn:LoadBalancerArn,Name:LoadBalancerName}", "--output", "json")
  $lbRaw = & aws @lbArgs 2>&1
  if ($LASTEXITCODE -ne 0) {
    throw "Failed to list ELBv2 load balancers in VPC $VpcId (exit code $LASTEXITCODE)."
  }
  $lbList = @()
  if ($lbRaw) { $lbList = @($lbRaw | ConvertFrom-Json) }
  foreach ($lb in $lbList) {
    $arn = $null
    $name = $null

    if ($lb -is [string]) {
      # Defensive fallback if JSON shape is unexpectedly a string.
      $arn = $lb
      $name = $lb
    } elseif ($lb -is [System.Collections.IList]) {
      if ($lb.Count -gt 0) { $arn = $lb[0] }
      if ($lb.Count -gt 1) { $name = $lb[1] }
    } else {
      $arn = Get-OptionalProperty $lb "Arn"
      if (-not $arn) { $arn = Get-OptionalProperty $lb "LoadBalancerArn" }
      $name = Get-OptionalProperty $lb "Name"
      if (-not $name) { $name = Get-OptionalProperty $lb "LoadBalancerName" }
    }

    if ($arn) {
      if ($arn -notmatch '^arn:') {
        Write-Host ("Skipping ELBv2 entry with non-ARN value: {0}" -f $arn)
        continue
      }
      Write-Host ("Deleting ELBv2 load balancer: {0} ({1})" -f $name, $arn)
      & aws elbv2 delete-load-balancer --load-balancer-arn $arn --region $Region | Out-Null
      if ($LASTEXITCODE -ne 0) {
        throw "Failed to delete ELBv2 load balancer $name (exit code $LASTEXITCODE)."
      }
    }
  }

  # Classic ELB
  $elbArgs = @("elb", "describe-load-balancers", "--region", $Region, "--query", "LoadBalancerDescriptions[?VPCId=='$VpcId'].LoadBalancerName", "--output", "json")
  $elbRaw = & aws @elbArgs 2>&1
  if ($LASTEXITCODE -ne 0) {
    throw "Failed to list classic ELBs in VPC $VpcId (exit code $LASTEXITCODE)."
  }
  $elbList = @()
  if ($elbRaw) { $elbList = $elbRaw | ConvertFrom-Json }
  foreach ($name in $elbList) {
    if ($name) {
      Write-Host ("Deleting classic ELB: {0}" -f $name)
      & aws elb delete-load-balancer --load-balancer-name $name --region $Region | Out-Null
      if ($LASTEXITCODE -ne 0) {
        throw "Failed to delete classic ELB $name (exit code $LASTEXITCODE)."
      }
    }
  }
}

function ConvertTo-IntOrZero($Value) {
  $parsed = 0
  [void][int]::TryParse(([string]$Value).Trim(), [ref]$parsed)
  return $parsed
}

function Get-ElasticLoadBalancerEnis([string]$VpcId, [string]$Region) {
  if (-not $VpcId) { return @() }
  $awsCmd = Get-Command aws -ErrorAction SilentlyContinue
  if (-not $awsCmd) { return @() }

  $args = @("ec2", "describe-network-interfaces", "--filters", "Name=vpc-id,Values=$VpcId", "--region", $Region, "--output", "json")
  $raw = & aws @args 2>&1
  if ($LASTEXITCODE -ne 0) {
    Write-Host ("Failed to list network interfaces in VPC {0}: {1}" -f $VpcId, $raw)
    return @()
  }
  if (-not $raw) { return @() }

  $data = $raw | ConvertFrom-Json
  $interfaces = @()
  $items = Get-OptionalProperty $data "NetworkInterfaces"
  if (-not $items) { return @() }

  foreach ($eni in $items) {
    $desc = [string](Get-OptionalProperty $eni "Description")
    $requesterId = [string](Get-OptionalProperty $eni "RequesterId")
    if ($desc -match '(?i)\belb\b' -or $requesterId -match '(?i)amazon-elb') {
      $interfaces += $eni
    }
  }

  return $interfaces
}

function Remove-DetachedElasticLoadBalancerEnis([string]$VpcId, [string]$Region) {
  $enis = @(Get-ElasticLoadBalancerEnis -VpcId $VpcId -Region $Region)
  foreach ($eni in $enis) {
    $eniId = Get-OptionalProperty $eni "NetworkInterfaceId"
    if (-not $eniId) { continue }
    $attachment = Get-OptionalProperty $eni "Attachment"
    if ($attachment -and (Get-OptionalProperty $attachment "AttachmentId")) {
      continue
    }

    Write-Host ("Deleting detached ELB ENI: {0}" -f $eniId)
    $deleteRaw = & aws ec2 delete-network-interface --network-interface-id $eniId --region $Region 2>&1
    if ($LASTEXITCODE -ne 0) {
      Write-Host ("Unable to delete detached ENI {0}: {1}" -f $eniId, $deleteRaw)
    }
  }
}

function Wait-ForLoadBalancerCleanup([string]$VpcId, [string]$Region, [int]$TimeoutSeconds = 600) {
  if (-not $VpcId) { return }
  $awsCmd = Get-Command aws -ErrorAction SilentlyContinue
  if (-not $awsCmd) { return }

  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  while ((Get-Date) -lt $deadline) {
    $elbv2Raw = & aws elbv2 describe-load-balancers --region $Region --query "length(LoadBalancers[?VpcId=='$VpcId'])" --output text 2>&1
    if ($LASTEXITCODE -ne 0) {
      Write-Host ("Failed to query ELBv2 load balancers in VPC {0}: {1}" -f $VpcId, $elbv2Raw)
      break
    }
    $classicRaw = & aws elb describe-load-balancers --region $Region --query "length(LoadBalancerDescriptions[?VPCId=='$VpcId'])" --output text 2>&1
    if ($LASTEXITCODE -ne 0) {
      Write-Host ("Failed to query classic ELBs in VPC {0}: {1}" -f $VpcId, $classicRaw)
      break
    }

    $elbv2Count = ConvertTo-IntOrZero $elbv2Raw
    $classicCount = ConvertTo-IntOrZero $classicRaw
    Remove-DetachedElasticLoadBalancerEnis -VpcId $VpcId -Region $Region
    $eniCount = @(Get-ElasticLoadBalancerEnis -VpcId $VpcId -Region $Region).Count

    if ($elbv2Count -eq 0 -and $classicCount -eq 0 -and $eniCount -eq 0) {
      Write-Host ("Load balancer artifacts in VPC {0} are fully removed." -f $VpcId)
      return
    }

    Write-Host ("Waiting for load balancer cleanup in VPC {0} (elbv2={1}, classic={2}, elb_enis={3})..." -f $VpcId, $elbv2Count, $classicCount, $eniCount)
    Start-Sleep -Seconds 15
  }

  Write-Host ("Timed out waiting for load balancer cleanup in VPC {0}; continuing with destroy attempt." -f $VpcId)
}

function Get-LoadBalancersBySecurityGroup([string]$GroupId, [string]$Region) {
  if (-not $GroupId) { return @() }
  $awsCmd = Get-Command aws -ErrorAction SilentlyContinue
  if (-not $awsCmd) { return @() }

  $args = @("elbv2", "describe-load-balancers", "--region", $Region, "--query", "LoadBalancers[?contains(SecurityGroups, '$GroupId')].{Arn:LoadBalancerArn,Name:LoadBalancerName}", "--output", "json")
  $raw = & aws @args 2>&1
  if ($LASTEXITCODE -ne 0) {
    Write-Host ("Failed to list ELBv2 load balancers for security group {0}: {1}" -f $GroupId, $raw)
    return @()
  }
  if (-not $raw) { return @() }
  return @($raw | ConvertFrom-Json)
}

function Remove-LoadBalancersBySecurityGroup([string]$GroupId, [string]$Region) {
  $lbs = @(Get-LoadBalancersBySecurityGroup -GroupId $GroupId -Region $Region)
  foreach ($lb in $lbs) {
    $arn = Get-OptionalProperty $lb "Arn"
    if (-not $arn) { $arn = Get-OptionalProperty $lb "LoadBalancerArn" }
    $name = Get-OptionalProperty $lb "Name"
    if (-not $name) { $name = Get-OptionalProperty $lb "LoadBalancerName" }
    if (-not $arn) { continue }

    Write-Host ("Deleting ELBv2 load balancer attached to security group {0}: {1} ({2})" -f $GroupId, $name, $arn)
    $deleteRaw = & aws elbv2 delete-load-balancer --load-balancer-arn $arn --region $Region 2>&1
    if ($LASTEXITCODE -ne 0) {
      Write-Host ("Unable to delete ELBv2 load balancer {0} ({1}): {2}" -f $name, $arn, $deleteRaw)
    }
  }
}

function Get-NetworkInterfacesBySecurityGroup([string]$GroupId, [string]$Region) {
  if (-not $GroupId) { return @() }
  $awsCmd = Get-Command aws -ErrorAction SilentlyContinue
  if (-not $awsCmd) { return @() }

  $args = @("ec2", "describe-network-interfaces", "--filters", "Name=group-id,Values=$GroupId", "--region", $Region, "--output", "json")
  $raw = & aws @args 2>&1
  if ($LASTEXITCODE -ne 0) {
    Write-Host ("Failed to list network interfaces for security group {0}: {1}" -f $GroupId, $raw)
    return @()
  }
  if (-not $raw) { return @() }
  $data = $raw | ConvertFrom-Json
  $items = Get-OptionalProperty $data "NetworkInterfaces"
  if (-not $items) { return @() }
  return @($items)
}

function Remove-DetachedEnisBySecurityGroup([string]$GroupId, [string]$Region) {
  $enis = @(Get-NetworkInterfacesBySecurityGroup -GroupId $GroupId -Region $Region)
  foreach ($eni in $enis) {
    $eniId = Get-OptionalProperty $eni "NetworkInterfaceId"
    if (-not $eniId) { continue }
    $attachment = Get-OptionalProperty $eni "Attachment"
    if ($attachment -and (Get-OptionalProperty $attachment "AttachmentId")) {
      continue
    }

    $desc = [string](Get-OptionalProperty $eni "Description")
    $requesterId = [string](Get-OptionalProperty $eni "RequesterId")
    if ($desc -notmatch '(?i)\belb\b' -and $requesterId -notmatch '(?i)amazon-elb') {
      continue
    }

    Write-Host ("Deleting detached ELB ENI tied to security group {0}: {1}" -f $GroupId, $eniId)
    $deleteRaw = & aws ec2 delete-network-interface --network-interface-id $eniId --region $Region 2>&1
    if ($LASTEXITCODE -ne 0) {
      Write-Host ("Unable to delete ENI {0}: {1}" -f $eniId, $deleteRaw)
    }
  }
}

function Remove-SecurityGroupRuleReferences([string]$TargetGroupId, [string]$Region) {
  if (-not $TargetGroupId) { return }
  $awsCmd = Get-Command aws -ErrorAction SilentlyContinue
  if (-not $awsCmd) { return }

  $args = @("ec2", "describe-security-group-rules", "--filters", "Name=referenced-group-id,Values=$TargetGroupId", "--region", $Region, "--output", "json")
  $raw = & aws @args 2>&1
  if ($LASTEXITCODE -ne 0) {
    $rawText = Convert-AwsCliOutputToString $raw
    Write-Host ("Failed to list security group rule references for {0}: {1}" -f $TargetGroupId, $rawText)
    Remove-SecurityGroupRuleReferencesLegacy -TargetGroupId $TargetGroupId -Region $Region
    return
  }
  if (-not $raw) { return }

  $data = $raw | ConvertFrom-Json
  $rules = Get-OptionalProperty $data "SecurityGroupRules"
  if (-not $rules) { return }

  foreach ($rule in $rules) {
    $ruleId = Get-OptionalProperty $rule "SecurityGroupRuleId"
    $groupId = Get-OptionalProperty $rule "GroupId"
    $isEgress = [bool](Get-OptionalProperty $rule "IsEgress")
    if (-not $ruleId -or -not $groupId) { continue }

    if ($groupId -eq $TargetGroupId) { continue }

    if ($isEgress) {
      Write-Host ("Revoking egress SG rule reference {0} from {1} to {2}" -f $ruleId, $groupId, $TargetGroupId)
      $revokeRaw = & aws ec2 revoke-security-group-egress --group-id $groupId --security-group-rule-ids $ruleId --region $Region 2>&1
    } else {
      Write-Host ("Revoking ingress SG rule reference {0} from {1} to {2}" -f $ruleId, $groupId, $TargetGroupId)
      $revokeRaw = & aws ec2 revoke-security-group-ingress --group-id $groupId --security-group-rule-ids $ruleId --region $Region 2>&1
    }
    if ($LASTEXITCODE -ne 0) {
      Write-Host ("Unable to revoke referenced rule {0}: {1}" -f $ruleId, $revokeRaw)
    }
  }
}

function Remove-SecurityGroupRuleReferencesLegacy([string]$TargetGroupId, [string]$Region) {
  if (-not $TargetGroupId) { return }
  $awsCmd = Get-Command aws -ErrorAction SilentlyContinue
  if (-not $awsCmd) { return }

  # Ingress references to target SG.
  $ingressRaw = & aws ec2 describe-security-groups --filters "Name=ip-permission.group-id,Values=$TargetGroupId" --region $Region --output json 2>&1
  if ($LASTEXITCODE -ne 0) {
    $ingressText = Convert-AwsCliOutputToString $ingressRaw
    Write-Host ("Fallback ingress SG reference scan failed for {0}: {1}" -f $TargetGroupId, $ingressText)
  } else {
    $ingressData = $ingressRaw | ConvertFrom-Json
    $ingressGroups = Get-OptionalProperty $ingressData "SecurityGroups"
    foreach ($sg in @($ingressGroups)) {
      $groupId = Get-OptionalProperty $sg "GroupId"
      if (-not $groupId -or $groupId -eq $TargetGroupId) { continue }
      foreach ($perm in @((Get-OptionalProperty $sg "IpPermissions"))) {
        $pairs = @((Get-OptionalProperty $perm "UserIdGroupPairs") | Where-Object { (Get-OptionalProperty $_ "GroupId") -eq $TargetGroupId })
        if ($pairs.Count -eq 0) { continue }

        $pairPayload = @()
        foreach ($p in $pairs) {
          $pairObj = @{ GroupId = (Get-OptionalProperty $p "GroupId") }
          $userId = Get-OptionalProperty $p "UserId"
          if ($userId) { $pairObj.UserId = $userId }
          $pairPayload += $pairObj
        }

        $permPayload = @{
          IpProtocol        = (Get-OptionalProperty $perm "IpProtocol")
          UserIdGroupPairs  = $pairPayload
        }
        $fromPort = Get-OptionalProperty $perm "FromPort"
        $toPort = Get-OptionalProperty $perm "ToPort"
        if ($null -ne $fromPort) { $permPayload.FromPort = $fromPort }
        if ($null -ne $toPort) { $permPayload.ToPort = $toPort }

        $ipPermissionsJson = @{ IpPermissions = @($permPayload) } | ConvertTo-Json -Depth 10 -Compress
        Write-Host ("Fallback revoking ingress SG reference from {0} to {1}" -f $groupId, $TargetGroupId)
        $revokeRaw = & aws ec2 revoke-security-group-ingress --group-id $groupId --ip-permissions $ipPermissionsJson --region $Region 2>&1
        if ($LASTEXITCODE -ne 0) {
          $revokeText = Convert-AwsCliOutputToString $revokeRaw
          Write-Host ("Fallback ingress revoke failed for group {0}: {1}" -f $groupId, $revokeText)
        }
      }
    }
  }

  # Egress references to target SG.
  $egressRaw = & aws ec2 describe-security-groups --filters "Name=egress.ip-permission.group-id,Values=$TargetGroupId" --region $Region --output json 2>&1
  if ($LASTEXITCODE -ne 0) {
    $egressText = Convert-AwsCliOutputToString $egressRaw
    Write-Host ("Fallback egress SG reference scan failed for {0}: {1}" -f $TargetGroupId, $egressText)
    return
  }

  $egressData = $egressRaw | ConvertFrom-Json
  $egressGroups = Get-OptionalProperty $egressData "SecurityGroups"
  foreach ($sg in @($egressGroups)) {
    $groupId = Get-OptionalProperty $sg "GroupId"
    if (-not $groupId -or $groupId -eq $TargetGroupId) { continue }
    foreach ($perm in @((Get-OptionalProperty $sg "IpPermissionsEgress"))) {
      $pairs = @((Get-OptionalProperty $perm "UserIdGroupPairs") | Where-Object { (Get-OptionalProperty $_ "GroupId") -eq $TargetGroupId })
      if ($pairs.Count -eq 0) { continue }

      $pairPayload = @()
      foreach ($p in $pairs) {
        $pairObj = @{ GroupId = (Get-OptionalProperty $p "GroupId") }
        $userId = Get-OptionalProperty $p "UserId"
        if ($userId) { $pairObj.UserId = $userId }
        $pairPayload += $pairObj
      }

      $permPayload = @{
        IpProtocol       = (Get-OptionalProperty $perm "IpProtocol")
        UserIdGroupPairs = $pairPayload
      }
      $fromPort = Get-OptionalProperty $perm "FromPort"
      $toPort = Get-OptionalProperty $perm "ToPort"
      if ($null -ne $fromPort) { $permPayload.FromPort = $fromPort }
      if ($null -ne $toPort) { $permPayload.ToPort = $toPort }

      $ipPermissionsJson = @{ IpPermissions = @($permPayload) } | ConvertTo-Json -Depth 10 -Compress
      Write-Host ("Fallback revoking egress SG reference from {0} to {1}" -f $groupId, $TargetGroupId)
      $revokeRaw = & aws ec2 revoke-security-group-egress --group-id $groupId --ip-permissions $ipPermissionsJson --region $Region 2>&1
      if ($LASTEXITCODE -ne 0) {
        $revokeText = Convert-AwsCliOutputToString $revokeRaw
        Write-Host ("Fallback egress revoke failed for group {0}: {1}" -f $groupId, $revokeText)
      }
    }
  }
}

function Wait-ForSecurityGroupRelease([string]$GroupId, [string]$Region, [int]$TimeoutSeconds = 300) {
  if (-not $GroupId) { return }
  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  while ((Get-Date) -lt $deadline) {
    Remove-LoadBalancersBySecurityGroup -GroupId $GroupId -Region $Region
    Remove-DetachedEnisBySecurityGroup -GroupId $GroupId -Region $Region
    Remove-SecurityGroupRuleReferences -TargetGroupId $GroupId -Region $Region

    $lbCount = @(Get-LoadBalancersBySecurityGroup -GroupId $GroupId -Region $Region).Count
    $eniCount = @(Get-NetworkInterfacesBySecurityGroup -GroupId $GroupId -Region $Region).Count
    if ($lbCount -eq 0 -and $eniCount -eq 0) {
      return
    }

    Write-Host ("Waiting for security group {0} dependencies to clear (elbv2={1}, enis={2})..." -f $GroupId, $lbCount, $eniCount)
    Start-Sleep -Seconds 10
  }

  Write-Host ("Timed out waiting for security group {0} dependencies; continuing delete attempt." -f $GroupId)
}

function Remove-KubernetesServiceSecurityGroups([string]$VpcId, [string]$Region) {
  if (-not $VpcId) { return }
  $awsCmd = Get-Command aws -ErrorAction SilentlyContinue
  if (-not $awsCmd) { return }

  $args = @("ec2", "describe-security-groups", "--filters", "Name=vpc-id,Values=$VpcId", "--region", $Region, "--output", "json")
  $raw = & aws @args 2>&1
  if ($LASTEXITCODE -ne 0) {
    Write-Host ("Failed to list security groups in VPC {0}: {1}" -f $VpcId, $raw)
    return
  }
  if (-not $raw) { return }

  $data = $raw | ConvertFrom-Json
  $groups = Get-OptionalProperty $data "SecurityGroups"
  if (-not $groups) { return }

  foreach ($sg in $groups) {
    $groupId = Get-OptionalProperty $sg "GroupId"
    $groupName = [string](Get-OptionalProperty $sg "GroupName")
    if (-not $groupId -or $groupName -eq "default") { continue }

    $hasServiceTag = $false
    $tags = Get-OptionalProperty $sg "Tags"
    if ($tags) {
      foreach ($tag in $tags) {
        if ((Get-OptionalProperty $tag "Key") -eq "kubernetes.io/service-name") {
          $hasServiceTag = $true
          break
        }
      }
    }

    $description = [string](Get-OptionalProperty $sg "Description")
    $isK8sElbDescription = $description -match '(?i)^Security group for Kubernetes ELB'
    if (-not $hasServiceTag -and $groupName -notlike "k8s-elb-*" -and -not $isK8sElbDescription) {
      continue
    }

    Remove-LoadBalancersBySecurityGroup -GroupId $groupId -Region $Region
    Remove-SecurityGroupRuleReferences -TargetGroupId $groupId -Region $Region
    Wait-ForSecurityGroupRelease -GroupId $groupId -Region $Region

    Write-Host ("Deleting Kubernetes load balancer security group: {0} ({1})" -f $groupName, $groupId)
    $deleteRaw = & aws ec2 delete-security-group --group-id $groupId --region $Region 2>&1
    if ($LASTEXITCODE -ne 0) {
      Write-Host ("Initial delete failed for security group {0}: {1}" -f $groupId, $deleteRaw)
      Remove-LoadBalancersBySecurityGroup -GroupId $groupId -Region $Region
      Remove-SecurityGroupRuleReferences -TargetGroupId $groupId -Region $Region
      Wait-ForSecurityGroupRelease -GroupId $groupId -Region $Region
      $deleteRawRetry = & aws ec2 delete-security-group --group-id $groupId --region $Region 2>&1
      if ($LASTEXITCODE -ne 0) {
        Write-Host ("Unable to delete security group {0} after retry: {1}" -f $groupId, $deleteRawRetry)
      }
    }
  }
}

function Invoke-VpcDependencyCleanup([string]$VpcId, [string]$Region) {
  if (-not $VpcId) { return }
  Remove-LoadBalancers -VpcId $VpcId -Region $Region
  Wait-ForLoadBalancerCleanup -VpcId $VpcId -Region $Region
  Remove-KubernetesServiceSecurityGroups -VpcId $VpcId -Region $Region
}

$resolvedRepoRoot = if ($RepoRoot) { Resolve-Path $RepoRoot } else { Resolve-Path (Join-Path $PSScriptRoot "..") }
$deploymentPath = Join-Path $resolvedRepoRoot "customer-deployments\$DeploymentName"

$backendConfig = if ($BackendConfigPath) { $BackendConfigPath } else { Join-Path $deploymentPath "backend.hcl" }
$varFile = if ($VarFilePath) { $VarFilePath } else { Join-Path $deploymentPath "config.auto.tfvars.json" }

if (-not (Test-Path -LiteralPath $backendConfig)) {
  throw "backend.hcl not found: $backendConfig"
}
if (-not (Test-Path -LiteralPath $varFile)) {
  throw "config.auto.tfvars.json not found: $varFile"
}

$config = Get-Content -Raw -Path $varFile | ConvertFrom-Json
$settingsBucket = Get-OptionalProperty $config "settings_bucket"
$settingsEnabled = Get-OptionalProperty $settingsBucket "enabled"
if ($null -eq $settingsEnabled) { $settingsEnabled = $true }
$settingsForceDestroy = [bool](Get-OptionalProperty $settingsBucket "force_destroy")
$settingsBucketName = Get-OptionalProperty $settingsBucket "name"
$region = Get-OptionalProperty $config "region"
if (-not $region) { $region = "us-east-1" }

if ($settingsEnabled -and $settingsForceDestroy -and $settingsBucketName) {
  Remove-S3BucketContents -Bucket $settingsBucketName -Region $region
}

$vpcCfg = Get-OptionalProperty $config "vpc"
$vpcName = Get-OptionalProperty $vpcCfg "name"
$vpcId = Get-VpcIdByName -VpcName $vpcName -Region $region
if ($vpcId) {
  Invoke-VpcDependencyCleanup -VpcId $vpcId -Region $region
} else {
  Write-Host "VPC ID not found; skipping load balancer cleanup."
}

$infraRoot = Join-Path $resolvedRepoRoot "infra\root"
if (-not (Test-Path -LiteralPath $infraRoot)) {
  throw "Infra root not found: $infraRoot"
}

Push-Location $infraRoot
try {
  tofu init "-backend-config=$backendConfig" | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw "OpenTofu init failed (exit code $LASTEXITCODE)."
  }

  $destroyArgs = @("destroy", "-var-file=$varFile")
  if ($ExtraVarFile) {
    $destroyArgs += "-var-file=$ExtraVarFile"
  }
  if ($AutoApprove) {
    $destroyArgs += "-auto-approve"
  }
  $maxDestroyAttempts = if ($vpcId) { 2 } else { 1 }
  $destroySucceeded = $false
  $destroyExitCode = 1
  for ($attempt = 1; $attempt -le $maxDestroyAttempts; $attempt++) {
    Write-Host ("Running OpenTofu destroy (attempt {0}/{1})..." -f $attempt, $maxDestroyAttempts)
    tofu @destroyArgs
    $destroyExitCode = $LASTEXITCODE
    if ($destroyExitCode -eq 0) {
      $destroySucceeded = $true
      break
    }

    if ($attempt -lt $maxDestroyAttempts -and $vpcId) {
      Write-Host "Destroy failed; retrying after extra VPC dependency cleanup."
      Invoke-VpcDependencyCleanup -VpcId $vpcId -Region $region
      continue
    }
  }

  if (-not $destroySucceeded) {
    throw "OpenTofu destroy failed (exit code $destroyExitCode)."
  }
} finally {
  Pop-Location
}

