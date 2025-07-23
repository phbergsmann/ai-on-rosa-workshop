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

variable "kb_s3_bucket_name_prefix" {
  description = "The name prefix of the S3 bucket for the data source of the knowledge base."
  type        = string
  default     = "california-drivers-kb"
}

variable "kb_oss_collection_name" {
  description = "The name of the OSS collection for the knowledge base."
  type        = string
  default     = "bedrock-kb-california-drivers-kb"
}

variable "kb_model_id" {
  description = "The ID of the foundational model used by the knowledge base."
  type        = string
  default     = "amazon.titan-embed-text-v2:0"
}

variable "kb_name" {
  description = "The knowledge base name."
  type        = string
  default     = "california-drivers-kb"
}

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.3.0"
    }
    opensearch = {
      source  = "opensearch-project/opensearch"
      version = "2.3.2"
    }
    random = {
      source  = "hashicorp/random"
      version = "3.5.1"
    }
  }
}
provider "aws" {
  region = var.location
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.region
  partition  = data.aws_partition.current.partition
}

resource "aws_iam_role" "bedrock_kb_california_drivers_kb" {
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
        # Condition = {
        #   StringEquals = {
        #     "aws:SourceAccount" = local.account_id
        #     #"aws:SourceArn"     = "arn:${local.partition}:bedrock:${local.region}:${local.account_id}:foundation-model/${var.kb_model_id}"
        #   }
        # }
      },
    ]
  })
}

data "aws_bedrock_foundation_model" "kb" {
  model_id = var.kb_model_id
}

resource "aws_iam_role_policy" "bedrock_kb_california_drivers_kb_model" {
  name = "AmazonBedrockFoundationModelPolicyForKnowledgeBase_${var.kb_name}"
  role = aws_iam_role.bedrock_kb_california_drivers_kb.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "bedrock:InvokeModel"
        Effect   = "Allow"
        Resource = data.aws_bedrock_foundation_model.kb.model_arn
      }
    ]
  })
}

resource "random_id" "rag_data_bucket_name" {
  byte_length = 4
}

resource "aws_s3_bucket" "rag_data" {
  bucket        = "${var.kb_s3_bucket_name_prefix}-${random_id.rag_data_bucket_name.hex}"
  force_destroy = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "rag_data" {
  bucket = aws_s3_bucket.rag_data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}


# TODO: This is not needed for the RAG data bucket for the workshop
resource "aws_s3_bucket_versioning" "rag_data" {
  bucket = aws_s3_bucket.rag_data.id
  versioning_configuration {
    status = "Disabled"
  }
  depends_on = [aws_s3_bucket_server_side_encryption_configuration.rag_data]
}


resource "aws_s3_object" "rag_data" {
  bucket = aws_s3_bucket.rag_data.id
  key    = "cal-driver.pdf"
  source = "${path.module}/cal-driver.pdf"
}

resource "aws_iam_role_policy" "bedrock_kb_rag_data_s3" {
  name = "AmazonBedrockS3PolicyForKnowledgeBase_${var.kb_name}"
  role = aws_iam_role.bedrock_kb_california_drivers_kb.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "S3ListBucketStatement"
        Action   = "s3:ListBucket"
        Effect   = "Allow"
        Resource = aws_s3_bucket.rag_data.arn
        Condition = {
          StringEquals = {
            "aws:PrincipalAccount" = local.account_id
          }
      } },
      {
        Sid      = "S3GetObjectStatement"
        Action   = "s3:GetObject"
        Effect   = "Allow"
        Resource = "${aws_s3_bucket.rag_data.arn}/*"
        Condition = {
          StringEquals = {
            "aws:PrincipalAccount" = local.account_id
          }
        }
      }
    ]
  })
}

resource "aws_opensearchserverless_access_policy" "rag_data" {
  name = var.kb_oss_collection_name
  type = "data"
  policy = jsonencode([
    {
      Rules = [
        {
          ResourceType = "index"
          Resource = [
            "index/${var.kb_oss_collection_name}/*"
          ]
          Permission = [
            "aoss:CreateIndex",
            "aoss:DeleteIndex",
            "aoss:DescribeIndex",
            "aoss:ReadDocument",
            "aoss:UpdateIndex",
            "aoss:WriteDocument"
          ]
        },
        {
          ResourceType = "collection"
          Resource = [
            "collection/${var.kb_oss_collection_name}"
          ]
          Permission = [
            "aoss:CreateCollectionItems",
            "aoss:DescribeCollectionItems",
            "aoss:UpdateCollectionItems"
          ]
        }
      ],
      Principal = [
        aws_iam_role.bedrock_kb_california_drivers_kb.arn,
        data.aws_caller_identity.current.arn
      ]
    }
  ])
}

resource "aws_opensearchserverless_security_policy" "rag_data_encryption" {
  name = var.kb_oss_collection_name
  type = "encryption"
  policy = jsonencode({
    Rules = [
      {
        Resource = [
          "collection/${var.kb_oss_collection_name}"
        ]
        ResourceType = "collection"
      }
    ],
    AWSOwnedKey = true
  })
}


# TODO: This will need input from the VPC if you want to make it private
resource "aws_opensearchserverless_security_policy" "rag_data_network" {
  name = var.kb_oss_collection_name
  type = "network"
  policy = jsonencode([
    {
      Rules = [
        {
          ResourceType = "collection"
          Resource = [
            "collection/${var.kb_oss_collection_name}"
          ]
        },
        {
          ResourceType = "dashboard"
          Resource = [
            "collection/${var.kb_oss_collection_name}"
          ]
        }
      ]
      AllowFromPublic = true
    }
  ])
}

resource "aws_opensearchserverless_collection" "rag_data" {
  name = var.kb_oss_collection_name
  type = "VECTORSEARCH"
  depends_on = [
    aws_opensearchserverless_access_policy.rag_data,
    aws_opensearchserverless_security_policy.rag_data_encryption,
    aws_opensearchserverless_security_policy.rag_data_network
  ]
  tags = var.tags
}

resource "aws_iam_role_policy" "bedrock_kb_rag_data_oss" {
  name = "AmazonBedrockOSSPolicyForKnowledgeBase_${var.kb_name}"
  role = aws_iam_role.bedrock_kb_california_drivers_kb.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "aoss:APIAccessAll"
        Effect   = "Allow"
        Resource = aws_opensearchserverless_collection.rag_data.arn
      }
    ]
  })
}

# healthcheck argument is set to false because the client health check does not really work with OpenSearch Serverless.
# but it appears this is the only way to automate the index creation.
provider "opensearch" {
  url         = aws_opensearchserverless_collection.rag_data.collection_endpoint
  healthcheck = false
}

resource "opensearch_index" "rag_data" {
  name                           = "bedrock-knowledge-base-default-index"
  number_of_shards               = "2"
  number_of_replicas             = "0"
  index_knn                      = true
  index_knn_algo_param_ef_search = "512"
  mappings                       = <<-EOF
    {
      "properties": {
        "bedrock-knowledge-base-default-vector": {
          "type": "knn_vector",
          "dimension": 1024,
          "method": {
            "name": "hnsw",
            "engine": "faiss",
            "parameters": {
              "m": 16,
              "ef_construction": 512
            },
            "space_type": "l2"
          }
        },
        "AMAZON_BEDROCK_METADATA": {
          "type": "text",
          "index": "false"
        },
        "AMAZON_BEDROCK_TEXT_CHUNK": {
          "type": "text",
          "index": "true"
        }
      }
    }
  EOF
  force_destroy                  = true
  depends_on                     = [aws_opensearchserverless_collection.rag_data]
}

resource "time_sleep" "aws_iam_role_policy_bedrock_kb_rag_data_oss" {
  create_duration = "20s"
  depends_on      = [aws_iam_role_policy.bedrock_kb_rag_data_oss]
}

resource "aws_bedrockagent_knowledge_base" "rag_data" {
  name     = var.kb_name
  role_arn = aws_iam_role.bedrock_kb_california_drivers_kb.arn
  knowledge_base_configuration {
    vector_knowledge_base_configuration {
      embedding_model_arn = data.aws_bedrock_foundation_model.kb.model_arn
    }
    type = "VECTOR"
  }
  storage_configuration {
    type = "OPENSEARCH_SERVERLESS"
    opensearch_serverless_configuration {
      collection_arn    = aws_opensearchserverless_collection.rag_data.arn
      vector_index_name = "bedrock-knowledge-base-default-index"
      field_mapping {
        vector_field   = "bedrock-knowledge-base-default-vector"
        text_field     = "AMAZON_BEDROCK_TEXT_CHUNK"
        metadata_field = "AMAZON_BEDROCK_METADATA"
      }
    }
  }
  depends_on = [
    aws_iam_role_policy.bedrock_kb_california_drivers_kb_model,
    aws_iam_role_policy.bedrock_kb_rag_data_s3,
    opensearch_index.rag_data,
    time_sleep.aws_iam_role_policy_bedrock_kb_rag_data_oss
  ]
}

resource "aws_bedrockagent_data_source" "rag_data" {
  knowledge_base_id = aws_bedrockagent_knowledge_base.rag_data.id
  name              = "${var.kb_name}DataSource"
  data_source_configuration {
    type = "S3"
    s3_configuration {
      bucket_arn = aws_s3_bucket.rag_data.arn
    }
  }
}


# Not sure if the application templates get applied here or in the application.
# resource "aws_bedrockagent_agent_knowledge_base_association" "rag_data" {
#   agent_id             = aws_bedrockagent_agent.rag_asst.id
#   description          = file("${path.module}/prompt_templates/kb_instruction.txt")
#   knowledge_base_id    = aws_bedrockagent_knowledge_base.rag_data.id
#   knowledge_base_state = "ENABLED"
# }


# resource "aws_iam_role_policy" "pod_bedrock_policy" {
#   name = "pod_bedrock_policy"
#   role = aws_iam_role.pod_bedrock_role.id

#   // This policy is used to allow the pod to assume the role
#   // TODO: Workout how to pass in the OIDC provider details
#   // export OIDC_PROVIDER=$(oc get authentication.config.openshift.io cluster -o json | jq -r .spec.serviceAccountIssuer | sed 's/https:\/\///')
#   policy = jsonencode({
#     Version = "2012-10-17"
#     Statement = [
#       {
#         Action = "sts:AssumeRoleWithWebIdentity"
#         Effect = "Allow"
#         Principal = {
#           Federated = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/${var.oidc_provider}"
#         }
#         Condition = {

#         }
#       }
#     ]
#   })
# }

# resource "aws_iam_role" "test_role" {
#   name = "test_role"

#   assume_role_policy = jsonencode({
#     Version = "2012-10-17"
#     Statement = [
#       {
#         Action = "sts:AssumeRole"
#         Effect = "Allow"
#         Sid    = ""
#         Principal = {
#           Service = "ec2.amazonaws.com"
#         }
#       },
#     ]
#   })
# }
