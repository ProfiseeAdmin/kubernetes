resource "aws_kms_key" "this" {
  for_each = var.keys

  description             = each.value.description
  enable_key_rotation     = each.value.enable_key_rotation
  deletion_window_in_days = each.value.deletion_window_in_days

  tags = var.tags
}

resource "aws_kms_alias" "this" {
  for_each = {
    for key_name, cfg in var.keys :
    key_name => cfg if try(cfg.alias, null) != null && cfg.alias != ""
  }

  name          = each.value.alias
  target_key_id = aws_kms_key.this[each.key].key_id
}

