data "aws_ami" "windows" {
  count       = var.ami_id == null ? 1 : 0
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["Windows_Server-2022-English-Full-Base-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }
}

locals {
  ami_id = var.ami_id != null ? var.ami_id : data.aws_ami.windows[0].id
  default_user_data = <<-EOF
    <powershell>
    $ProgressPreference = 'SilentlyContinue'
    # Give IAM/SSM/EKS time to settle and permissions to propagate
    Start-Sleep -Seconds 300

    Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    choco upgrade chocolatey kubernetes-cli eksctl kubernetes-helm awscli opentofu awscli-session-manager sqlcmd -y
    Import-Module C:\\ProgramData\\chocolatey\\helpers\\chocolateyProfile.psm1
    refreshenv

    # Pull kubeconfig from the App Settings bucket (if configured).
    $kubeBucket = "${var.settings_bucket_name}"
    $kubeKey = "${var.kubeconfig_s3_key}"
    $kubeRegion = "${var.region}"
    if ($kubeBucket -and $kubeKey -and $kubeRegion) {
      $kubeDir = "C:\\kubeconfig"
      New-Item -ItemType Directory -Path $kubeDir -Force | Out-Null
      $kubePath = Join-Path $kubeDir "kubeconfig"
      $maxAttempts = 60
      $delaySeconds = 60
      for ($i = 1; $i -le $maxAttempts; $i++) {
        try {
          aws s3 cp ("s3://{0}/{1}" -f $kubeBucket, $kubeKey) $kubePath --region $kubeRegion | Out-Null
          if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $kubePath)) {
            setx KUBECONFIG $kubePath /M | Out-Null
            Write-Host ("Kubeconfig downloaded to {0}" -f $kubePath)
            break
          }
        } catch {
          # Ignore and retry
        }
        Start-Sleep -Seconds $delaySeconds
      }
    } else {
      Write-Host "Kubeconfig S3 details not set; skipping download."
    }
    </powershell>
  EOF
  user_data = (var.user_data != null && trim(var.user_data) != "") ? var.user_data : local.default_user_data
}

data "aws_iam_policy_document" "ec2_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ssm" {
  name               = "${var.name}-ssm-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.ssm.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "additional" {
  count = length(var.iam_policy_arns)

  role       = aws_iam_role.ssm.name
  policy_arn = var.iam_policy_arns[count.index]
}

data "aws_iam_policy_document" "assume_role" {
  count = var.assume_role_arn == null || var.assume_role_arn == "" ? 0 : 1

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    resources = [var.assume_role_arn]
  }
}

resource "aws_iam_role_policy" "assume_role" {
  count = length(data.aws_iam_policy_document.assume_role) == 0 ? 0 : 1

  name   = "${var.name}-assume-role"
  role   = aws_iam_role.ssm.id
  policy = data.aws_iam_policy_document.assume_role[0].json
}

resource "aws_iam_instance_profile" "ssm" {
  name = "${var.name}-ssm-profile"
  role = aws_iam_role.ssm.name
}

resource "aws_security_group" "this" {
  name        = "${var.name}-sg"
  description = "Windows jumpbox access"
  vpc_id      = var.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = var.tags
}

resource "aws_security_group_rule" "rdp" {
  count = var.enable_rdp_ingress ? 1 : 0

  type              = "ingress"
  from_port         = 3389
  to_port           = 3389
  protocol          = "tcp"
  security_group_id = aws_security_group.this.id
  cidr_blocks       = var.allowed_rdp_cidrs
  description       = "RDP access to jumpbox"
}

resource "aws_instance" "this" {
  ami                         = local.ami_id
  instance_type               = var.instance_type
  subnet_id                   = var.subnet_id
  vpc_security_group_ids      = [aws_security_group.this.id]
  associate_public_ip_address = var.associate_public_ip
  key_name                    = var.key_name
  iam_instance_profile        = aws_iam_instance_profile.ssm.name
  user_data                   = local.user_data

  root_block_device {
    volume_size           = var.root_volume_size_gb
    volume_type           = "gp3"
    delete_on_termination = true
  }

  tags = merge(
    var.tags,
    {
      Name = var.name
    }
  )
}
