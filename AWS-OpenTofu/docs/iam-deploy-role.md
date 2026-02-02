# IAM Deploy Role Plan

This repo is designed for customer‑run installs. The recommended model is:

- **Bootstrap role** (one‑time / rare): create the state backend and (optionally) the deploy role.
- **Deploy role** (regular): create VPC, EKS, RDS, ACM, CloudFront, Route53, and supporting IAM roles.

Both roles are **account‑scoped** and trusted only by principals in the same AWS account.

## Trust policy (example)

Replace `<ACCOUNT_ID>` and `<PRINCIPAL_ARN>` with your IAM user/role that will assume the deploy role.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::<ACCOUNT_ID>:root" },
      "Action": "sts:AssumeRole",
      "Condition": {
        "ArnEquals": {
          "aws:PrincipalArn": "arn:aws:iam::<ACCOUNT_ID>:role/<PRINCIPAL_ARN>"
        }
      }
    }
  ]
}
```

### Add the jumpbox role (recommended)

If you enable the Windows jumpbox and want it to assume the deploy role, add the
jumpbox role ARN (output by the module) to the trust policy. Example:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::<ACCOUNT_ID>:role/<JUMPBOX_ROLE_NAME>" },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

Automation helper:

```powershell
# Replace 'opentofu-deploy' if you used a custom deploy role name.
.\scripts\tofu-apply.ps1 -DeploymentName <name> -DeployRoleName opentofu-deploy
```

## Bootstrap role policy (baseline)

This is a practical baseline for the **state backend**. It is still scoped to the
account and named resources.

Replace placeholders:
- `<STATE_BUCKET>`: S3 bucket name for state
- `<LOCK_TABLE>`: DynamoDB lock table
- `<KMS_ALIAS>`: e.g., `alias/opentofu-state`
- If you use a custom deploy role name, replace `opentofu-deploy` in the policy below.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "StateBucket",
      "Effect": "Allow",
      "Action": [
        "s3:CreateBucket",
        "s3:PutBucketVersioning",
        "s3:PutBucketEncryption",
        "s3:PutBucketPublicAccessBlock",
        "s3:PutBucketPolicy",
        "s3:GetBucketLocation",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::<STATE_BUCKET>",
        "arn:aws:s3:::<STATE_BUCKET>/*"
      ]
    },
    {
      "Sid": "StateLockTable",
      "Effect": "Allow",
      "Action": [
        "dynamodb:CreateTable",
        "dynamodb:DescribeTable",
        "dynamodb:UpdateTable"
      ],
      "Resource": "arn:aws:dynamodb:*:<ACCOUNT_ID>:table/<LOCK_TABLE>"
    },
    {
      "Sid": "StateKms",
      "Effect": "Allow",
      "Action": [
        "kms:CreateKey",
        "kms:CreateAlias",
        "kms:EnableKeyRotation",
        "kms:DescribeKey",
        "kms:PutKeyPolicy"
      ],
      "Resource": "*"
    },
    {
      "Sid": "OptionalCreateDeployRole",
      "Effect": "Allow",
      "Action": [
        "iam:CreateRole",
        "iam:AttachRolePolicy",
        "iam:PutRolePolicy",
        "iam:TagRole",
        "iam:PassRole"
      ],
      "Resource": "arn:aws:iam::<ACCOUNT_ID>:role/opentofu-deploy"
    }
  ]
}
```

## Deploy role policy (baseline)

This policy is scoped to the services this repo manages. It is not fully
least‑privilege yet, but is a good starting point for a proof run. After the
first successful deployment, use IAM Access Analyzer or CloudTrail to tighten
the policy.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CoreServices",
      "Effect": "Allow",
      "Action": [
        "ec2:*",
        "elasticloadbalancing:*",
        "eks:*",
        "rds:*",
        "kms:*",
        "acm:*",
        "cloudfront:*",
        "route53:*",
        "logs:*",
        "iam:*"
      ],
      "Resource": "*"
    },
    {
      "Sid": "StateBackendRead",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket",
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:DeleteItem",
        "dynamodb:UpdateItem"
      ],
      "Resource": [
        "arn:aws:s3:::<STATE_BUCKET>",
        "arn:aws:s3:::<STATE_BUCKET>/*",
        "arn:aws:dynamodb:*:<ACCOUNT_ID>:table/<LOCK_TABLE>"
      ]
    }
  ]
}
```

## Tightening after first run (recommended)

1. Run a full deployment with the baseline policy.
2. Use **IAM Access Analyzer policy generation** or **CloudTrail** to capture
   the exact actions used.
3. Replace broad `*` actions/resources with the generated least‑privilege policy.

### Access Analyzer (guided)

1. IAM → Access Analyzer → Policy generation
2. Create policy for the deploy role
3. Specify the time window of your deployment
4. Review and export the generated policy

### CloudTrail (manual)

1. Filter events by the deploy role ARN
2. Export the event list
3. Extract `eventSource` + `eventName` into allowed actions
4. Scope resources where possible (S3 bucket, DynamoDB table, KMS alias, hosted zone ID)

This yields an account‑scoped role that only allows what the installer actually uses.
