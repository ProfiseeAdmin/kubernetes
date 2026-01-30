param(
  [string]$StackName,
  [string]$TemplateFile = "infra/FullyPrivateEKS.yaml",
  [string]$ParametersFile = "",
  [string]$AwsProfile = "",
  [string]$AwsRegion = "us-east-1",
  [string]$SettingsTemplate = "values/Settings-aws.yaml",
  [string]$SettingsOut = "Settings-aws.rendered.yaml",
  [ValidateSet("FSx","EBS")]
  [string]$StorageMode = "FSx",
  [ValidateSet("LetsEncrypt","SecretsManager")]
  [string]$TraefikTlsMode = "LetsEncrypt",
  [string]$TraefikTlsSecretArn = "",
  [string]$TraefikTlsSecretName = "profisee-tls",
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
  [string]$DbName,
  [string]$DbUser,
  [string]$DbPassword,
  [string]$DbSecretArn,
  [string]$FsxUser,
  [string]$FsxPassword,
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
  [string]$LicenseSecretArn = ""
  ,[ValidateSet("true","false")]
  [string]$UseLetsEncrypt = "false"
)

if ([string]::IsNullOrWhiteSpace($StackName)) { throw "StackName is required." }
if (-not (Test-Path $TemplateFile)) { throw "Template file not found: $TemplateFile" }

$awsArgs = @()
if (-not [string]::IsNullOrWhiteSpace($AwsProfile)) { $awsArgs += @("--profile", $AwsProfile) }
if (-not [string]::IsNullOrWhiteSpace($AwsRegion)) { $awsArgs += @("--region", $AwsRegion) }

$deployArgs = @("cloudformation", "deploy", "--stack-name", $StackName, "--template-file", $TemplateFile, "--capabilities", "CAPABILITY_NAMED_IAM")
if (-not [string]::IsNullOrWhiteSpace($ParametersFile)) {
  if (-not (Test-Path $ParametersFile)) { throw "Parameters file not found: $ParametersFile" }
  $deployArgs += @("--parameter-overrides", (Get-Content -Raw -Path $ParametersFile))
}

Write-Host "Deploying CloudFormation stack $StackName..."
aws @awsArgs @deployArgs

Write-Host "Running post-deploy config..."
.\deployprofisee-aws.ps1 `
  -StackName $StackName `
  -AwsProfile $AwsProfile `
  -AwsRegion $AwsRegion `
  -SettingsTemplate $SettingsTemplate `
  -SettingsOut $SettingsOut `
  -StorageMode $StorageMode `
  -TraefikTlsMode $TraefikTlsMode `
  -TraefikTlsSecretArn $TraefikTlsSecretArn `
  -TraefikTlsSecretName $TraefikTlsSecretName `
  -CloudFrontEnabled $CloudFrontEnabled `
  -CloudFrontCertMode $CloudFrontCertMode `
  -CloudFrontAlias $CloudFrontAlias `
  -CloudFrontHostedZoneId $CloudFrontHostedZoneId `
  -CloudFrontOriginDomainName $CloudFrontOriginDomainName `
  -CloudFrontCertSecretArn $CloudFrontCertSecretArn `
  -CloudFrontCertArn $CloudFrontCertArn `
  -CloudFrontAcmRegion $CloudFrontAcmRegion `
  -DbName $DbName `
  -DbUser $DbUser `
  -DbPassword $DbPassword `
  -DbSecretArn $DbSecretArn `
  -FsxUser $FsxUser `
  -FsxPassword $FsxPassword `
  -ExternalFqdn $ExternalFqdn `
  -WebAppName $WebAppName `
  -AdminAccount $AdminAccount `
  -InfraAdminAccount $InfraAdminAccount `
  -ImageRegistry $ImageRegistry `
  -ImageRepository $ImageRepository `
  -ImageTag $ImageTag `
  -RegistryUsername $RegistryUsername `
  -RegistryPassword $RegistryPassword `
  -RegistryEmail $RegistryEmail `
  -LicenseBase64 $LicenseBase64 `
  -LicenseSecretArn $LicenseSecretArn `
  -UseLetsEncrypt $UseLetsEncrypt
