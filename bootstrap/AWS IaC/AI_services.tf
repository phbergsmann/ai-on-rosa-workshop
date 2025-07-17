variable "tags" {
  type = map(string)
  default = {
    environment = "development"
    owner       = "your@email.address"
  }
}

variable "location" {
  type        = string
  default     = "eu-west-2"
  description = "London region"
}

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.3.0"
    }
  }
}

provider "aws" {
  region = var.location
}

data "aws_caller_identity" "current" {}

data "aws_bedrock_foundation_model" "base_model" {
  // TODO: cheapskate but this needs to be confirmed against pro
  model_id = "amazon.nova-micro-v1:0" # Choose an appropriate model ID
}

resource "aws_s3_bucket" "rag_data" {
  bucket = "rag_data"

  tags = var.tags
}

resource "aws_iam_role" "bedrock_role" {
  name = "bedrock-custom-model-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "bedrock.amazonaws.com"
        }
      },
    ]
  })
}

resource "aws_iam_role_policy" "bedrock_s3_access" {
  name = "bedrock-s3-access"
  role = aws_iam_role.bedrock_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
          "s3:PutObject"
        ]
        Effect = "Allow"
        Resource = [
          aws_s3_bucket.rag_data.arn,
          "${aws_s3_bucket.rag_data.arn}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy" "pod_bedrock_policy" {
  name = "pod_bedrock_policy"
  role = aws_iam_role.pod_bedrock_role.id

  // This policy is used to allow the pod to assume the role
  // TODO: Workout how to pass in the OIDC provider details
  // export OIDC_PROVIDER=$(oc get authentication.config.openshift.io cluster -o json | jq -r .spec.serviceAccountIssuer | sed 's/https:\/\///')
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRoleWithWebIdentity"
        Effect = "Allow"
        Principal = {
          Federated = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/${var.oidc_provider}"
        }
        Condition = {

        }
      }
    ]
  })
}

resource "aws_iam_role" "test_role" {
  name = "test_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
}
