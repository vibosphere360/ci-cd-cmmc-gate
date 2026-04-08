terraform {
  required_version = ">= 1.7"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
  backend "s3" {
    bucket         = "ci-cd-cmmc-gate-evidence-vadeleke-vibosphere"
    key            = "terraform/state/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
  }
}

provider "aws" {
  region = "us-east-1"
  default_tags {
    tags = {
      Project      = "ci-cd-cmmc-gate"
      Environment  = "production"
      CUI_Boundary = "true"
      Owner        = "vibosphere360"
    }
  }
}
