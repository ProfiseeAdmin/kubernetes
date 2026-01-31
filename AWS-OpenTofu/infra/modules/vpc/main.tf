locals {
  public_subnet_map = {
    for idx, az in var.azs :
    az => {
      az    = az
      cidr  = var.public_subnet_cidrs[idx]
      index = idx
    }
  }
  private_subnet_map = {
    for idx, az in var.azs :
    az => {
      az    = az
      cidr  = var.private_subnet_cidrs[idx]
      index = idx
    }
  }
  nat_azs = var.enable_nat_gateway ? (var.single_nat_gateway ? [var.azs[0]] : var.azs) : []
  private_route_table_map = var.single_nat_gateway ? {
    single = { az = var.azs[0] }
  } : {
    for az in var.azs : az => { az = az }
  }
}

resource "aws_vpc" "this" {
  cidr_block           = var.cidr_block
  enable_dns_hostnames = var.enable_dns_hostnames
  enable_dns_support   = var.enable_dns_support

  tags = merge(
    var.tags,
    var.vpc_tags,
    {
      Name = "${var.name}-vpc"
    }
  )
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = merge(
    var.tags,
    {
      Name = "${var.name}-igw"
    }
  )
}

resource "aws_subnet" "public" {
  for_each = local.public_subnet_map

  vpc_id                  = aws_vpc.this.id
  availability_zone       = each.value.az
  cidr_block              = each.value.cidr
  map_public_ip_on_launch = true

  tags = merge(
    var.tags,
    var.public_subnet_tags,
    {
      Name = "${var.name}-public-${each.value.az}"
    }
  )
}

resource "aws_subnet" "private" {
  for_each = local.private_subnet_map

  vpc_id            = aws_vpc.this.id
  availability_zone = each.value.az
  cidr_block        = each.value.cidr

  tags = merge(
    var.tags,
    var.private_subnet_tags,
    {
      Name = "${var.name}-private-${each.value.az}"
    }
  )
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  tags = merge(
    var.tags,
    {
      Name = "${var.name}-public-rt"
    }
  )
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route_table_association" "public" {
  for_each = aws_subnet.public

  subnet_id      = each.value.id
  route_table_id = aws_route_table.public.id
}

resource "aws_eip" "nat" {
  for_each = toset(local.nat_azs)

  domain = "vpc"

  tags = merge(
    var.tags,
    {
      Name = "${var.name}-nat-eip-${each.value}"
    }
  )
}

resource "aws_nat_gateway" "this" {
  for_each = toset(local.nat_azs)

  allocation_id = aws_eip.nat[each.value].id
  subnet_id     = aws_subnet.public[each.value].id

  tags = merge(
    var.tags,
    {
      Name = "${var.name}-nat-${each.value}"
    }
  )
}

resource "aws_route_table" "private" {
  for_each = local.private_route_table_map

  vpc_id = aws_vpc.this.id

  tags = merge(
    var.tags,
    {
      Name = var.single_nat_gateway ? "${var.name}-private-rt" : "${var.name}-private-${each.key}"
    }
  )
}

resource "aws_route" "private_nat" {
  for_each = var.enable_nat_gateway ? aws_route_table.private : {}

  route_table_id         = each.value.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id = var.single_nat_gateway ? aws_nat_gateway.this[var.azs[0]].id : aws_nat_gateway.this[each.key].id
}

resource "aws_route_table_association" "private" {
  for_each = aws_subnet.private

  subnet_id = each.value.id
  route_table_id = var.single_nat_gateway ? aws_route_table.private["single"].id : aws_route_table.private[each.key].id
}

