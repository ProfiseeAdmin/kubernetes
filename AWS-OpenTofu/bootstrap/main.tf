locals {
  tags = merge(
    {
      ManagedBy = "OpenTofu"
      Component = "bootstrap"
    },
    var.tags
  )
}

provider "aws" {
  region = var.region

  default_tags {
    tags = local.tags
  }
}

resource "aws_kms_key" "state" {
  description             = "KMS key for OpenTofu state encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  tags                    = local.tags
}

resource "aws_kms_alias" "state" {
  name          = var.state_kms_alias
  target_key_id = aws_kms_key.state.key_id
}

resource "aws_s3_bucket" "state" {
  bucket        = var.state_bucket_name
  force_destroy = var.state_bucket_force_destroy
  tags          = local.tags
}

resource "aws_s3_bucket_ownership_controls" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket = aws_s3_bucket.state.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.state.arn
    }
  }
}

data "aws_iam_policy_document" "state_bucket" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.state.arn,
      "${aws_s3_bucket.state.arn}/*"
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "state" {
  bucket = aws_s3_bucket.state.id
  policy = data.aws_iam_policy_document.state_bucket.json
}

resource "aws_dynamodb_table" "state_lock" {
  name         = var.state_lock_table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = local.tags
}

data "aws_iam_policy_document" "deploy_role_assume" {
  count = var.create_deploy_role ? 1 : 0

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = var.deploy_role_trusted_principal_arns
    }
  }
}

resource "aws_iam_role" "deploy" {
  count = var.create_deploy_role ? 1 : 0

  name               = var.deploy_role_name
  assume_role_policy = data.aws_iam_policy_document.deploy_role_assume[0].json
  tags               = local.tags
}

data "aws_iam_policy_document" "deploy_scope" {
  count = var.create_deploy_role ? 1 : 0

  statement {
    sid    = "OpenTofuDeploymentScope"
    effect = "Allow"
    actions = [
      "acm:*",
      "autoscaling:*",
      "cloudwatch:*",
      "dynamodb:*",
      "ec2:*",
      "ecs:*",
      "eks:*",
      "elasticloadbalancing:*",
      "iam:AddRoleToInstanceProfile",
      "iam:AttachRolePolicy",
      "iam:CreateInstanceProfile",
      "iam:CreateOpenIDConnectProvider",
      "iam:CreatePolicy",
      "iam:CreatePolicyVersion",
      "iam:CreateRole",
      "iam:CreateServiceLinkedRole",
      "iam:DeleteInstanceProfile",
      "iam:DeleteOpenIDConnectProvider",
      "iam:DeletePolicy",
      "iam:DeletePolicyVersion",
      "iam:DeleteRole",
      "iam:DeleteRolePolicy",
      "iam:DetachRolePolicy",
      "iam:Get*",
      "iam:List*",
      "iam:PassRole",
      "iam:PutRolePolicy",
      "iam:RemoveRoleFromInstanceProfile",
      "iam:Tag*",
      "iam:Untag*",
      "iam:UpdateAssumeRolePolicy",
      "iam:UpdateOpenIDConnectProviderThumbprint",
      "kms:*",
      "logs:*",
      "rds:*",
      "route53:*",
      "s3:*",
      "secretsmanager:*",
      "ssm:*",
      "sts:GetCallerIdentity"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "deploy_scope" {
  count = var.create_deploy_role ? 1 : 0

  name   = "${var.deploy_role_name}-scope"
  role   = aws_iam_role.deploy[0].id
  policy = data.aws_iam_policy_document.deploy_scope[0].json
}

resource "aws_iam_role_policy_attachment" "deploy" {
  for_each = var.create_deploy_role ? toset(var.deploy_role_policy_arns) : toset([])

  role       = aws_iam_role.deploy[0].name
  policy_arn = each.value
}

