```terraform
module.bedrock_kb.data.aws_caller_identity.current: Reading...
module.bedrock_kb.data.aws_caller_identity.current: Read complete after 0s [id=052666565139]

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  + create

Terraform will perform the following actions:

  # module.bedrock_kb.aws_bedrockagent_data_source.s3_bedrock_bucket will be created
  + resource "aws_bedrockagent_data_source" "s3_bedrock_bucket" {
      + data_deletion_policy = (known after apply)
      + data_source_id       = (known after apply)
      + id                   = (known after apply)
      + knowledge_base_id    = (known after apply)
      + name                 = "s3_bedrock_bucket"

      + data_source_configuration {
          + type = "S3"

          + s3_configuration {
              + bucket_arn = "arn:aws:s3:::bedrock-kb-052666565139"
            }
        }
    }

  # module.bedrock_kb.aws_bedrockagent_knowledge_base.main will be created
  + resource "aws_bedrockagent_knowledge_base" "main" {
      + arn             = (known after apply)
      + created_at      = (known after apply)
      + failure_reasons = (known after apply)
      + id              = (known after apply)
      + name            = "my-bedrock-kb"
      + role_arn        = (known after apply)
      + tags_all        = {}
      + updated_at      = (known after apply)

      + knowledge_base_configuration {
          + type = "VECTOR"

          + vector_knowledge_base_configuration {
              + embedding_model_arn = "arn:aws:bedrock:us-west-2::foundation-model/amazon.titan-embed-text-v1"
            }
        }

      + storage_configuration {
          + type = "RDS"

          + rds_configuration {
              + credentials_secret_arn = "arn:aws:secretsmanager:us-west-2:052666565139:secret:my-aurora-serverless-veVq6D"
              + database_name          = "myapp"
              + resource_arn           = "arn:aws:secretsmanager:us-west-2:052666565139:secret:Pinecone_API_Key-ntoC6S"
              + table_name             = "bedrock_integration.bedrock_kb"

              + field_mapping {
                  + metadata_field    = "metadata"
                  + primary_key_field = "id"
                  + text_field        = "chunks"
                  + vector_field      = "embedding"
                }
            }
        }
    }

  # module.bedrock_kb.aws_iam_policy.bedrock_kb_rds_access will be created
  + resource "aws_iam_policy" "bedrock_kb_rds_access" {
      + arn              = (known after apply)
      + attachment_count = (known after apply)
      + description      = "IAM policy for Bedrock Knowledge Base to access RDS"
      + id               = (known after apply)
      + name             = "bedrock_kb_rds_access"
      + name_prefix      = (known after apply)
      + path             = "/"
      + policy           = jsonencode(
            {
              + Statement = [
                  + {
                      + Action   = [
                          + "rds:DescribeDBClusters",
                          + "rds:DescribeDBInstances",
                          + "rds:DescribeDBSubnetGroups",
                          + "rds:ListTagsForResource",
                          + "s3:ListBucket",
                          + "s3:GetObject",
                        ]
                      + Effect   = "Allow"
                      + Resource = "*"
                    },
                  + {
                      + Action   = [
                          + "secretsmanager:GetSecretValue",
                          + "secretsmanager:DescribeSecret",
                        ]
                      + Effect   = "Allow"
                      + Resource = "arn:aws:secretsmanager:us-west-2:052666565139:secret:my-aurora-serverless-veVq6D"
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + policy_id        = (known after apply)
      + tags_all         = (known after apply)
    }

  # module.bedrock_kb.aws_iam_policy.rds_data_api_policy will be created
  + resource "aws_iam_policy" "rds_data_api_policy" {
      + arn              = (known after apply)
      + attachment_count = (known after apply)
      + description      = "IAM policy for RDS Data API access"
      + id               = (known after apply)
      + name             = "my-bedrock-kb-rds-data-api-policy"
      + name_prefix      = (known after apply)
      + path             = "/"
      + policy           = jsonencode(
            {
              + Statement = [
                  + {
                      + Action   = [
                          + "rds-data:ExecuteStatement",
                          + "rds-data:BatchExecuteStatement",
                          + "rds-data:BeginTransaction",
                          + "rds-data:CommitTransaction",
                          + "rds-data:RollbackTransaction",
                        ]
                      + Effect   = "Allow"
                      + Resource = "arn:aws:secretsmanager:us-west-2:052666565139:secret:Pinecone_API_Key-ntoC6S"
                    },
                  + {
                      + Action   = [
                          + "secretsmanager:GetSecretValue",
                        ]
                      + Effect   = "Allow"
                      + Resource = "arn:aws:secretsmanager:us-west-2:052666565139:secret:my-aurora-serverless-veVq6D"
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + policy_id        = (known after apply)
      + tags_all         = (known after apply)
    }

  # module.bedrock_kb.aws_iam_role.bedrock_kb_role will be created
  + resource "aws_iam_role" "bedrock_kb_role" {
      + arn                   = (known after apply)
      + assume_role_policy    = jsonencode(
            {
              + Statement = [
                  + {
                      + Action    = "sts:AssumeRole"
                      + Effect    = "Allow"
                      + Principal = {
                          + Service = "bedrock.amazonaws.com"
                        }
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + create_date           = (known after apply)
      + force_detach_policies = false
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = "my-bedrock-kb-role"
      + name_prefix           = (known after apply)
      + path                  = "/"
      + tags_all              = (known after apply)
      + unique_id             = (known after apply)

      + inline_policy (known after apply)
    }

  # module.bedrock_kb.aws_iam_role_policy_attachment.bedrock_kb_policy will be created
  + resource "aws_iam_role_policy_attachment" "bedrock_kb_policy" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonBedrockFullAccess"
      + role       = "my-bedrock-kb-role"
    }

  # module.bedrock_kb.aws_iam_role_policy_attachment.rds_data_api_policy_attachment will be created
  + resource "aws_iam_role_policy_attachment" "rds_data_api_policy_attachment" {
      + id         = (known after apply)
      + policy_arn = (known after apply)
      + role       = "my-bedrock-kb-role"
    }

  # module.bedrock_kb.aws_iam_role_policy_attachment.rds_policy_attachment will be created
  + resource "aws_iam_role_policy_attachment" "rds_policy_attachment" {
      + id         = (known after apply)
      + policy_arn = (known after apply)
      + role       = "my-bedrock-kb-role"
    }

  # module.bedrock_kb.time_sleep.wait_10_seconds will be created
  + resource "time_sleep" "wait_10_seconds" {
      + create_duration = "10s"
      + id              = (known after apply)
    }

Plan: 9 to add, 0 to change, 0 to destroy.

Changes to Outputs:
  + bedrock_knowledge_base_arn = (known after apply)
  + bedrock_knowledge_base_id  = (known after apply)

Do you want to perform these actions?
  Terraform will perform the actions described above.
  Only 'yes' will be accepted to approve.

  Enter a value: yes


```
