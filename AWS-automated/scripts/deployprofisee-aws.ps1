param(
  [string]$SettingsTemplate = "Settings-aws.yaml",
  [string]$SettingsOut = "Settings-aws.rendered.yaml",
  [string]$StackName = "",
  [string]$AwsProfile = "",
  [string]$AwsRegion = "",
  [ValidateSet("LetsEncrypt","SecretsManager")]
  [string]$TraefikTlsMode = "LetsEncrypt",
  [string]$TraefikTlsSecretArn = "",
  [string]$TraefikTlsSecretName = "profisee-tls",
  [string]$TraefikServiceName = "traefik",
  [ValidateSet("true","false")]
  [string]$CloudFrontEnabled = "false",
  [ValidateSet("ACMRequest","ACMImport")]
  [string]$CloudFrontCertMode = "ACMRequest",
  [string]$CloudFrontAlias = "",
  [string]$CloudFrontHostedZoneId = "",
  [string]$CloudFrontOriginDomainName = "",
  [string]$CloudFrontCertSecretArn = "",
  [string]$CloudFrontCertArn = "",
  [string]$CloudFrontAcmRegion = "us-east-1",
  [ValidateSet("FSx","EBS")]
  [string]$StorageMode = "FSx",
  [string]$RdsEndpoint,
  [string]$DbName,
  [string]$DbUser,
  [string]$DbPassword,
  [string]$DbSecretArn = "",
  [string]$FsxDnsName,
  [string]$FsxUser,
  [string]$FsxPassword,
  [string]$EbsVolumeId = "",
  [string]$ExternalFqdn,
  [string]$WebAppName,
  [string]$AdminAccount,
  [string]$InfraAdminAccount,
  [string]$ImageRegistry,
  [string]$ImageRepository,
  [string]$ImageTag,
  [string]$RegistryUsername,
  [string]$RegistryPassword,
  [string]$RegistryEmail,
  [string]$LicenseBase64,
  [string]$LicenseSecretArn = "",
  [string]$PreInitBase64 = "Cg==",
  [string]$PostInitBase64 = "Cg==",
  [ValidateSet("true","false")]
  [string]$UseLetsEncrypt = "false",
  [string]$OidcName = "Azure Active Directory",
  [string]$OidcAuthority = "",
  [string]$OidcClientId = "",
  [string]$OidcClientSecret = "",
  [string]$OidcUsernameClaim = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
  [string]$OidcUserIdClaim = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier",
  [string]$OidcFirstNameClaim = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
  [string]$OidcLastNameClaim = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
  [string]$OidcEmailClaim = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
  [string]$Namespace = "profisee"
)

if (-not (Test-Path $SettingsTemplate)) {
  throw "Settings template not found: $SettingsTemplate"
}

$awsArgs = @()
if (-not [string]::IsNullOrWhiteSpace($AwsProfile)) { $awsArgs += @("--profile", $AwsProfile) }
if (-not [string]::IsNullOrWhiteSpace($AwsRegion)) { $awsArgs += @("--region", $AwsRegion) }

if (-not [string]::IsNullOrWhiteSpace($StackName)) {

  $stackJson = aws @awsArgs cloudformation describe-stacks --stack-name $StackName | ConvertFrom-Json
  $outputs = @{}
  foreach ($o in $stackJson.Stacks[0].Outputs) {
    $outputs[$o.OutputKey] = $o.OutputValue
  }

  if (-not $RdsEndpoint) { $RdsEndpoint = $outputs["RDSInstanceEndpoint"] }
  if (-not $FsxDnsName) { $FsxDnsName = $outputs["FSxDnsName"] }
  if (-not $EbsVolumeId) { $EbsVolumeId = $outputs["EBSVolumeId"] }
  if (-not $DbSecretArn) { $DbSecretArn = $outputs["RDSMasterSecretArn"] }
}

if ([string]::IsNullOrWhiteSpace($RdsEndpoint)) { throw "RdsEndpoint is required (or provide StackName with RDSInstanceEndpoint output)." }
if ([string]::IsNullOrWhiteSpace($DbName)) { throw "DbName is required." }
if ([string]::IsNullOrWhiteSpace($ExternalFqdn)) { throw "ExternalFqdn is required." }
if ([string]::IsNullOrWhiteSpace($WebAppName)) { throw "WebAppName is required." }
if ([string]::IsNullOrWhiteSpace($AdminAccount)) { throw "AdminAccount is required." }
if ([string]::IsNullOrWhiteSpace($InfraAdminAccount)) { throw "InfraAdminAccount is required." }
if ([string]::IsNullOrWhiteSpace($ImageRegistry)) { throw "ImageRegistry is required." }
if ([string]::IsNullOrWhiteSpace($ImageRepository)) { throw "ImageRepository is required." }
if ([string]::IsNullOrWhiteSpace($ImageTag)) { throw "ImageTag is required." }
if ([string]::IsNullOrWhiteSpace($RegistryUsername)) { throw "RegistryUsername is required." }
if ([string]::IsNullOrWhiteSpace($RegistryPassword)) { throw "RegistryPassword is required." }
if ([string]::IsNullOrWhiteSpace($RegistryEmail)) { throw "RegistryEmail is required." }

if ($StorageMode -eq "FSx") {
  if ([string]::IsNullOrWhiteSpace($FsxDnsName)) { throw "FsxDnsName is required for FSx." }
  if ([string]::IsNullOrWhiteSpace($FsxUser)) { throw "FsxUser is required for FSx." }
  if ([string]::IsNullOrWhiteSpace($FsxPassword)) { throw "FsxPassword is required for FSx." }
}

if ($TraefikTlsMode -eq "SecretsManager" -and [string]::IsNullOrWhiteSpace($TraefikTlsSecretArn)) {
  throw "TraefikTlsSecretArn is required when TraefikTlsMode=SecretsManager."
}

if ($CloudFrontEnabled -eq "true" -and [string]::IsNullOrWhiteSpace($CloudFrontAlias)) {
  throw "CloudFrontAlias is required when CloudFrontEnabled=true."
}

if ($UseLetsEncrypt -eq "false" -and $TraefikTlsMode -eq "LetsEncrypt") {
  $UseLetsEncrypt = "true"
}

function Get-SecretJson {
  param([string]$SecretArn)
  $secretValue = aws @awsArgs secretsmanager get-secret-value --secret-id $SecretArn | ConvertFrom-Json
  if ($secretValue.SecretString) {
    return ($secretValue.SecretString | ConvertFrom-Json)
  }
  if ($secretValue.SecretBinary) {
    $json = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($secretValue.SecretBinary))
    return ($json | ConvertFrom-Json)
  }
  throw "Secret $SecretArn has no SecretString or SecretBinary."
}

function Write-TempFile {
  param([string]$Content, [string]$Suffix)
  $tmp = [System.IO.Path]::GetTempFileName()
  $target = "$tmp$Suffix"
  Move-Item -Force $tmp $target
  Set-Content -Path $target -Value $Content -NoNewline
  return $target
}

if ([string]::IsNullOrWhiteSpace($DbPassword) -and -not [string]::IsNullOrWhiteSpace($DbSecretArn)) {
  $dbSecret = Get-SecretJson -SecretArn $DbSecretArn
  if (-not $DbUser) { $DbUser = $dbSecret.username }
  if (-not $DbPassword) { $DbPassword = $dbSecret.password }
}

if ([string]::IsNullOrWhiteSpace($DbUser)) { throw "DbUser is required (or provide DbSecretArn)." }
if ([string]::IsNullOrWhiteSpace($DbPassword)) { throw "DbPassword is required (or provide DbSecretArn)." }

$licenseValue = $LicenseBase64
if ([string]::IsNullOrWhiteSpace($licenseValue) -and -not [string]::IsNullOrWhiteSpace($LicenseSecretArn)) {
  $licSecret = Get-SecretJson -SecretArn $LicenseSecretArn
  $licenseValue = $licSecret.license
  if (-not $licenseValue) { $licenseValue = $licSecret.value }
  if (-not $licenseValue) { $licenseValue = $licSecret.License }
  if (-not $licenseValue) { throw "License secret must contain 'license' or 'value' field." }
}
if ([string]::IsNullOrWhiteSpace($licenseValue)) { throw "LicenseBase64 is required (or provide LicenseSecretArn)." }

$regAuth = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("$RegistryUsername`:$RegistryPassword"))
$settings = Get-Content -Raw -Path $SettingsTemplate

$settings = $settings.Replace("<RDS_ENDPOINT>", $RdsEndpoint)
$settings = $settings.Replace("<DB_NAME>", $DbName)
$settings = $settings.Replace("<DB_MASTER_USERNAME>", $DbUser)
$settings = $settings.Replace("<DB_MASTER_PASSWORD>", $DbPassword)
$settings = $settings.Replace("<ADMIN_ACCOUNT_EMAIL>", $AdminAccount)
$settings = $settings.Replace("<INFRA_ADMIN_EMAIL>", $InfraAdminAccount)
$settings = $settings.Replace("<FQDN>", $ExternalFqdn)
$settings = $settings.Replace("<WEBAPPNAME>", $WebAppName)
$settings = $settings.Replace("<IMAGE_REGISTRY>", $ImageRegistry)
$settings = $settings.Replace("<IMAGE_REPOSITORY>", $ImageRepository)
$settings = $settings.Replace("<IMAGE_TAG>", $ImageTag)
$settings = $settings.Replace("<REGISTRY_USERNAME>", $RegistryUsername)
$settings = $settings.Replace("<REGISTRY_PASSWORD>", $RegistryPassword)
$settings = $settings.Replace("<REGISTRY_EMAIL>", $RegistryEmail)
$settings = $settings.Replace("<REGISTRY_AUTH_BASE64>", $regAuth)
$settings = $settings.Replace("<LICENSE_BASE64>", $licenseValue)
$settings = $settings.Replace("<PREINIT_BASE64>", $PreInitBase64)
$settings = $settings.Replace("<POSTINIT_BASE64>", $PostInitBase64)
$settings = $settings.Replace("<USE_LETS_ENCRYPT>", $UseLetsEncrypt)
$settings = $settings.Replace("<OIDC_NAME>", $OidcName)
$settings = $settings.Replace("<OIDC_AUTHORITY_URL>", $OidcAuthority)
$settings = $settings.Replace("<OIDC_CLIENT_ID>", $OidcClientId)
$settings = $settings.Replace("<OIDC_CLIENT_SECRET>", $OidcClientSecret)
$settings = $settings.Replace("<OIDC_USERNAME_CLAIM>", $OidcUsernameClaim)
$settings = $settings.Replace("<OIDC_USERID_CLAIM>", $OidcUserIdClaim)
$settings = $settings.Replace("<OIDC_FIRSTNAME_CLAIM>", $OidcFirstNameClaim)
$settings = $settings.Replace("<OIDC_LASTNAME_CLAIM>", $OidcLastNameClaim)
$settings = $settings.Replace("<OIDC_EMAIL_CLAIM>", $OidcEmailClaim)

if ($StorageMode -eq "FSx") {
  $settings = $settings.Replace("<FSX_DNS_NAME>", $FsxDnsName)
  $settings = $settings.Replace("<DOMAIN_USER>", $FsxUser)
  $settings = $settings.Replace("<DOMAIN_PASSWORD>", $FsxPassword)
  $settings = $settings.Replace("<EBS_VOLUME_ID>", "")
} else {
  $settings = $settings.Replace("<FSX_DNS_NAME>", "localhost")
  $settings = $settings.Replace("<DOMAIN_USER>", "unused")
  $settings = $settings.Replace("<DOMAIN_PASSWORD>", "unused")
  $settings = $settings.Replace("\\\\<FSX_DNS_NAME>\\share", "C:\\fileshare")
  $settings = $settings.Replace("<EBS_VOLUME_ID>", $EbsVolumeId)
}

Set-Content -Path $SettingsOut -Value $settings

Write-Host "Rendered settings written to $SettingsOut"

if ($TraefikTlsMode -eq "SecretsManager") {
  if (-not (Get-Command kubectl -ErrorAction SilentlyContinue)) {
    throw "kubectl not found in PATH; required to create TLS secret from Secrets Manager."
  }
  $tlsSecret = Get-SecretJson -SecretArn $TraefikTlsSecretArn
  $cert = $tlsSecret."tls.crt"
  $key = $tlsSecret."tls.key"
  if (-not $cert) { $cert = $tlsSecret.cert }
  if (-not $key) { $key = $tlsSecret.key }
  if (-not $cert -or -not $key) { throw "Secret must contain tls.crt and tls.key (or cert/key) fields." }

  $certFile = Write-TempFile -Content $cert -Suffix ".crt"
  $keyFile = Write-TempFile -Content $key -Suffix ".key"

  kubectl -n $Namespace create secret tls $TraefikTlsSecretName --cert=$certFile --key=$keyFile --dry-run=client -o yaml | kubectl apply -f -
  Remove-Item -Force $certFile, $keyFile
  Write-Host "Created TLS secret $TraefikTlsSecretName in namespace $Namespace from Secrets Manager."
}

if ($CloudFrontEnabled -eq "true") {
  if (-not (Get-Command aws -ErrorAction SilentlyContinue)) {
    throw "aws CLI not found in PATH; required for CloudFront/ACM operations."
  }
  $originDomain = $CloudFrontOriginDomainName
  if ([string]::IsNullOrWhiteSpace($originDomain)) {
    if (-not (Get-Command kubectl -ErrorAction SilentlyContinue)) {
      throw "CloudFrontOriginDomainName not provided and kubectl not available to discover Traefik service."
    }
    $originDomain = kubectl -n $Namespace get svc $TraefikServiceName -o "jsonpath={.status.loadBalancer.ingress[0].hostname}"
    if ([string]::IsNullOrWhiteSpace($originDomain)) {
      $originDomain = kubectl -n $Namespace get svc $TraefikServiceName -o "jsonpath={.status.loadBalancer.ingress[0].ip}"
    }
    if ([string]::IsNullOrWhiteSpace($originDomain)) {
      throw "Unable to determine Traefik service load balancer hostname."
    }
  }

  if ([string]::IsNullOrWhiteSpace($CloudFrontCertArn)) {
    if ($CloudFrontCertMode -eq "ACMRequest") {
      $req = aws --region $CloudFrontAcmRegion acm request-certificate --domain-name $CloudFrontAlias --validation-method DNS | ConvertFrom-Json
      $CloudFrontCertArn = $req.CertificateArn
      Write-Host "Requested ACM cert: $CloudFrontCertArn"

      $cert = aws --region $CloudFrontAcmRegion acm describe-certificate --certificate-arn $CloudFrontCertArn | ConvertFrom-Json
      $rr = $cert.Certificate.DomainValidationOptions[0].ResourceRecord
      if (-not $rr) { throw "ACM validation record not available yet. Re-run after a short delay." }

      if (-not [string]::IsNullOrWhiteSpace($CloudFrontHostedZoneId)) {
        $change = @{
          Comment = "ACM validation record"
          Changes = @(
            @{
              Action = "UPSERT"
              ResourceRecordSet = @{
                Name = $rr.Name
                Type = $rr.Type
                TTL = 300
                ResourceRecords = @(@{ Value = $rr.Value })
              }
            }
          )
        } | ConvertTo-Json -Depth 6
        $tmpChange = Write-TempFile -Content $change -Suffix ".json"
        aws route53 change-resource-record-sets --hosted-zone-id $CloudFrontHostedZoneId --change-batch file://$tmpChange | Out-Null
        Remove-Item -Force $tmpChange
        Write-Host "Created Route53 validation record for $CloudFrontAlias."
      } else {
        Write-Host "Create this DNS validation record in your DNS:"
        Write-Host ("  Name: {0}`n  Type: {1}`n  Value: {2}" -f $rr.Name, $rr.Type, $rr.Value)
      }
      Write-Host "Wait for ACM certificate to be issued before CloudFront creation."
    } else {
      if ([string]::IsNullOrWhiteSpace($CloudFrontCertSecretArn)) {
        throw "CloudFrontCertSecretArn is required when CloudFrontCertMode=ACMImport."
      }
      $cfSecret = Get-SecretJson -SecretArn $CloudFrontCertSecretArn
      $cfCert = $cfSecret."tls.crt"
      $cfKey = $cfSecret."tls.key"
      $cfChain = $cfSecret."tls.chain"
      if (-not $cfCert) { $cfCert = $cfSecret.cert }
      if (-not $cfKey) { $cfKey = $cfSecret.key }
      if (-not $cfChain) { $cfChain = $cfSecret.chain }
      if (-not $cfCert -or -not $cfKey) { throw "Secret must contain tls.crt and tls.key (and optionally tls.chain)." }

      $certFile = Write-TempFile -Content $cfCert -Suffix ".crt"
      $keyFile = Write-TempFile -Content $cfKey -Suffix ".key"
      $chainFile = $null
      if ($cfChain) { $chainFile = Write-TempFile -Content $cfChain -Suffix ".chain" }

      $importArgs = @("--region", $CloudFrontAcmRegion, "acm", "import-certificate", "--certificate", "fileb://$certFile", "--private-key", "fileb://$keyFile")
      if ($chainFile) { $importArgs += @("--certificate-chain", "fileb://$chainFile") }
      $import = aws @importArgs | ConvertFrom-Json
      $CloudFrontCertArn = $import.CertificateArn

      Remove-Item -Force $certFile, $keyFile
      if ($chainFile) { Remove-Item -Force $chainFile }
      Write-Host "Imported ACM cert: $CloudFrontCertArn"
    }
  }

  if (-not [string]::IsNullOrWhiteSpace($CloudFrontCertArn)) {
    $distConfig = @{
      CallerReference = [System.Guid]::NewGuid().ToString()
      Comment = "Profisee CloudFront"
      Enabled = $true
      Aliases = @{
        Quantity = 1
        Items = @($CloudFrontAlias)
      }
      Origins = @{
        Quantity = 1
        Items = @(
          @{
            Id = "origin-1"
            DomainName = $originDomain
            CustomOriginConfig = @{
              HTTPPort = 80
              HTTPSPort = 443
              OriginProtocolPolicy = "https-only"
              OriginSSLProtocols = @{
                Quantity = 1
                Items = @("TLSv1.2")
              }
            }
          }
        )
      }
      DefaultCacheBehavior = @{
        TargetOriginId = "origin-1"
        ViewerProtocolPolicy = "redirect-to-https"
        AllowedMethods = @{
          Quantity = 7
          Items = @("GET","HEAD","OPTIONS","PUT","POST","PATCH","DELETE")
          CachedMethods = @{
            Quantity = 2
            Items = @("GET","HEAD")
          }
        }
        ForwardedValues = @{
          QueryString = $true
          Cookies = @{
            Forward = "all"
          }
        }
        MinTTL = 0
        DefaultTTL = 0
        MaxTTL = 0
      }
      ViewerCertificate = @{
        ACMCertificateArn = $CloudFrontCertArn
        SSLSupportMethod = "sni-only"
        MinimumProtocolVersion = "TLSv1.2_2021"
      }
    } | ConvertTo-Json -Depth 10

    $distFile = Write-TempFile -Content $distConfig -Suffix ".json"
      $dist = aws cloudfront create-distribution --distribution-config file://$distFile | ConvertFrom-Json
      Remove-Item -Force $distFile
    $cfDomain = $dist.Distribution.DomainName
    Write-Host "Created CloudFront distribution: $cfDomain"

    if (-not [string]::IsNullOrWhiteSpace($CloudFrontHostedZoneId)) {
      $cfHostedZoneId = "Z2FDTNDATAQYW2"
      $changeAlias = @{
        Comment = "CloudFront alias"
        Changes = @(
          @{
            Action = "UPSERT"
            ResourceRecordSet = @{
              Name = $CloudFrontAlias
              Type = "A"
              AliasTarget = @{
                HostedZoneId = $cfHostedZoneId
                DNSName = $cfDomain
                EvaluateTargetHealth = $false
              }
            }
          },
          @{
            Action = "UPSERT"
            ResourceRecordSet = @{
              Name = $CloudFrontAlias
              Type = "AAAA"
              AliasTarget = @{
                HostedZoneId = $cfHostedZoneId
                DNSName = $cfDomain
                EvaluateTargetHealth = $false
              }
            }
          }
        )
      } | ConvertTo-Json -Depth 8

      $aliasFile = Write-TempFile -Content $changeAlias -Suffix ".json"
      aws route53 change-resource-record-sets --hosted-zone-id $CloudFrontHostedZoneId --change-batch file://$aliasFile | Out-Null
      Remove-Item -Force $aliasFile
      Write-Host "Created Route53 alias records for $CloudFrontAlias."
    }
  }
}

Write-Host "Next steps (run from a shell with kubectl/helm configured):"
Write-Host "1) kubectl create namespace $Namespace (if not exists)"
Write-Host "2) If StorageMode=FSx, install SMB CSI driver + create secret/sc:"
Write-Host "   helm repo add csi-driver-smb https://raw.githubusercontent.com/kubernetes-csi/csi-driver-smb/master/charts"
Write-Host "   helm repo update"
Write-Host "   helm upgrade --install smb-csi csi-driver-smb/csi-driver-smb -n kube-system -f smb-csi-values.yaml"
Write-Host "   kubectl apply -f smb-secret.yaml"
Write-Host "   kubectl apply -f smb-storageclass.yaml"
Write-Host "   kubectl apply -f smb-pvc.yaml"
Write-Host "   If StorageMode=EBS, install the EBS CSI driver and create a PV/PVC using the EBS volume ID."
Write-Host "3) Install Traefik:"
Write-Host "   helm repo add traefik https://traefik.github.io/charts"
Write-Host "   helm repo update"
Write-Host "   helm upgrade --install traefik traefik/traefik -n $Namespace -f traefik-values.yaml"
Write-Host "   For public TLS: use -f traefik-values-public.yaml instead"
Write-Host "   For Let's Encrypt DNS-01: install cert-manager + apply cert-manager-route53-issuer.yaml and cert-manager-certificate.yaml"
Write-Host "   For customer-provided cert (Secrets Manager): set TraefikTlsMode=SecretsManager and TraefikTlsSecretArn"
Write-Host "4) Install Profisee:"
Write-Host "   helm repo add profisee https://profisee.github.io/kubernetes"
Write-Host "   helm repo update"
Write-Host "   helm upgrade --install profiseeplatform profisee/profisee-platform -n $Namespace -f $SettingsOut"
