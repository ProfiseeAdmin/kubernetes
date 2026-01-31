variable "name" {
  type        = string
  description = "Name prefix for VPC resources."
}

variable "cidr_block" {
  type        = string
  description = "CIDR block for the VPC."
}

variable "azs" {
  type        = list(string)
  description = "Availability zones to use."
}

variable "public_subnet_cidrs" {
  type        = list(string)
  description = "CIDR blocks for public subnets."

  validation {
    condition     = length(var.public_subnet_cidrs) == length(var.azs)
    error_message = "public_subnet_cidrs must have the same length as azs."
  }
}

variable "private_subnet_cidrs" {
  type        = list(string)
  description = "CIDR blocks for private subnets."

  validation {
    condition     = length(var.private_subnet_cidrs) == length(var.azs)
    error_message = "private_subnet_cidrs must have the same length as azs."
  }
}

variable "enable_nat_gateway" {
  type        = bool
  default     = true
  description = "Whether to create NAT gateways."
}

variable "single_nat_gateway" {
  type        = bool
  default     = true
  description = "Whether to use a single NAT gateway."
}

variable "enable_dns_hostnames" {
  type        = bool
  default     = true
  description = "Enable DNS hostnames in the VPC."
}

variable "enable_dns_support" {
  type        = bool
  default     = true
  description = "Enable DNS support in the VPC."
}

variable "public_subnet_tags" {
  type        = map(string)
  default     = {}
  description = "Additional tags for public subnets."
}

variable "private_subnet_tags" {
  type        = map(string)
  default     = {}
  description = "Additional tags for private subnets."
}

variable "vpc_tags" {
  type        = map(string)
  default     = {}
  description = "Additional tags for the VPC."
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Tags applied to all VPC module resources."
}

