locals {
  default_tags = merge(
    {
      ManagedBy = "OpenTofu"
      Component = "infra-root"
    },
    var.tags
  )
}

provider "aws" {
  region = var.region

  default_tags {
    tags = local.default_tags
  }
}

provider "aws" {
  alias  = "use1"
  region = var.use1_region

  default_tags {
    tags = local.default_tags
  }
}

