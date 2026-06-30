terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {}
}

variable "endpoint" {
  type    = string
  default = "http://localhost:4566"
}

variable "aws_access_key" {
  type    = string
  default = "test"
}

variable "aws_secret_key" {
  type      = string
  sensitive = true
  default   = "test"
}

provider "aws" {
  region     = "us-east-1"
  access_key = var.aws_access_key
  secret_key = var.aws_secret_key

  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  s3_use_path_style           = true

  endpoints {
    s3             = var.endpoint
    sqs            = var.endpoint
    sns            = var.endpoint
    dynamodb       = var.endpoint
    lambda         = var.endpoint
    iam            = var.endpoint
    sts            = var.endpoint
    ssm            = var.endpoint
    secretsmanager = var.endpoint
    kms            = var.endpoint
    ec2            = var.endpoint
    route53        = var.endpoint
  }
}
