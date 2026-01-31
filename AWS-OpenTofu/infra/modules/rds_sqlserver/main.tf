locals {
  ingress_sg_map = {
    for sg_id in var.allowed_security_group_ids : sg_id => sg_id
  }
}

resource "aws_db_subnet_group" "this" {
  name       = "${var.identifier}-subnet-group"
  subnet_ids = var.subnet_ids

  tags = var.tags
}

resource "aws_security_group" "this" {
  name        = "${var.identifier}-db-sg"
  description = "RDS SQL Server access"
  vpc_id      = var.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = var.tags
}

resource "aws_security_group_rule" "ingress" {
  for_each = local.ingress_sg_map

  type                     = "ingress"
  from_port                = 1433
  to_port                  = 1433
  protocol                 = "tcp"
  security_group_id        = aws_security_group.this.id
  source_security_group_id = each.value
  description              = "SQL Server access from allowed security groups"
}

resource "aws_db_instance" "this" {
  identifier = var.identifier

  engine         = "sqlserver-se"
  engine_version = var.engine_version
  license_model  = "license-included"

  instance_class        = var.instance_class
  allocated_storage     = var.allocated_storage
  max_allocated_storage = var.max_allocated_storage
  storage_type          = var.storage_type
  iops                  = var.iops

  storage_encrypted = var.storage_encrypted
  kms_key_id        = var.kms_key_arn

  db_name = var.db_name

  username                    = var.master_username
  manage_master_user_password = var.manage_master_user_password
  master_user_secret_kms_key_id = var.master_user_secret_kms_key_id

  vpc_security_group_ids = [aws_security_group.this.id]
  db_subnet_group_name   = aws_db_subnet_group.this.name

  backup_retention_period = var.backup_retention_days
  multi_az                = var.multi_az
  publicly_accessible     = var.publicly_accessible
  deletion_protection     = var.deletion_protection

  skip_final_snapshot = true

  tags = var.tags
}

