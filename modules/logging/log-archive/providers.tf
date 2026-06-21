# Provider Configuration for Log Archive Module
# This module requires two providers: one for primary region (eu-west-2 - London)
# and one for replica region (eu-west-1 - Ireland)

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = "~> 5.0"
      configuration_aliases = [aws.replica]
    }
  }
}
