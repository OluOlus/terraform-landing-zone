# Provider Configuration for Log Archive Module
# This module requires two providers: one for primary region (us-east-1)
# and one for replica region (us-west-2)

terraform {
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = "~> 5.0"
      configuration_aliases = [aws.replica]
    }
  }
}
