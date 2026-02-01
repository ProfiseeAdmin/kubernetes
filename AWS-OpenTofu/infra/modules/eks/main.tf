locals {
  cluster_subnet_ids = concat(var.private_subnet_ids, var.public_subnet_ids)
}

data "aws_iam_policy_document" "cluster_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cluster" {
  name               = "${var.cluster_name}-cluster-role"
  assume_role_policy = data.aws_iam_policy_document.cluster_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "cluster" {
  for_each = toset([
    "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy",
    "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
  ])

  role       = aws_iam_role.cluster.name
  policy_arn = each.value
}

resource "aws_eks_cluster" "this" {
  name     = var.cluster_name
  role_arn = aws_iam_role.cluster.arn
  version  = var.cluster_version

  vpc_config {
    subnet_ids              = local.cluster_subnet_ids
    endpoint_public_access  = var.endpoint_public_access
    endpoint_private_access = var.endpoint_private_access
  }

  enabled_cluster_log_types = var.enabled_cluster_log_types

  dynamic "encryption_config" {
    for_each = var.cluster_kms_key_arn == null ? [] : [var.cluster_kms_key_arn]
    content {
      provider {
        key_arn = encryption_config.value
      }
      resources = ["secrets"]
    }
  }

  depends_on = [aws_iam_role_policy_attachment.cluster]

  tags = var.tags
}

data "tls_certificate" "oidc" {
  url = aws_eks_cluster.this.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "this" {
  url             = aws_eks_cluster.this.identity[0].oidc[0].issuer
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.oidc.certificates[0].sha1_fingerprint]

  tags = var.tags
}

data "aws_iam_policy_document" "node_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "linux_nodes" {
  name               = "${var.cluster_name}-linux-ng-role"
  assume_role_policy = data.aws_iam_policy_document.node_assume.json
  tags               = var.tags
}

resource "aws_iam_role" "windows_nodes" {
  name               = "${var.cluster_name}-windows-ng-role"
  assume_role_policy = data.aws_iam_policy_document.node_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "linux_nodes" {
  for_each = toset([
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  ])

  role       = aws_iam_role.linux_nodes.name
  policy_arn = each.value
}

resource "aws_iam_role_policy_attachment" "windows_nodes" {
  for_each = toset([
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  ])

  role       = aws_iam_role.windows_nodes.name
  policy_arn = each.value
}

resource "aws_eks_node_group" "linux" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "${var.cluster_name}-linux"
  node_role_arn   = aws_iam_role.linux_nodes.arn
  subnet_ids      = var.private_subnet_ids
  ami_type        = "AL2_x86_64"
  capacity_type   = var.linux_node_group.capacity_type
  disk_size       = var.linux_node_group.disk_size
  instance_types  = var.linux_node_group.instance_types

  scaling_config {
    desired_size = var.linux_node_group.desired_size
    max_size     = var.linux_node_group.max_size
    min_size     = var.linux_node_group.min_size
  }

  depends_on = [aws_iam_role_policy_attachment.linux_nodes]

  tags = var.tags
}

resource "aws_eks_node_group" "windows" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "${var.cluster_name}-windows"
  node_role_arn   = aws_iam_role.windows_nodes.arn
  subnet_ids      = var.private_subnet_ids
  ami_type        = "WINDOWS_CORE_2022_x86_64"
  capacity_type   = var.windows_node_group.capacity_type
  disk_size       = var.windows_node_group.disk_size
  instance_types  = var.windows_node_group.instance_types

  scaling_config {
    desired_size = var.windows_node_group.desired_size
    max_size     = var.windows_node_group.max_size
    min_size     = var.windows_node_group.min_size
  }

  depends_on = [aws_iam_role_policy_attachment.windows_nodes]

  tags = var.tags
}

