provider "aws" {
  region = "us-west-2"  
}

module "bedrock_kb" {
  source = "../modules/bedrock_kb" 

  knowledge_base_name        = "my-bedrock-kb"
  knowledge_base_description = "Knowledge base connected to Aurora Serverless database"

  aurora_arn        = "arn:aws:secretsmanager:us-west-2:052666565139:secret:Pinecone_API_Key-ntoC6S" #TODO Update with output from stack1
  aurora_db_name    = "myapp"
  aurora_endpoint   = "https://bedrock-integration-9g3q57n.svc.aped-4627-b74a.pinecone.io" # TODO Update with output from stack1
  aurora_table_name = "bedrock_integration.bedrock_kb"
  aurora_primary_key_field = "id"
  aurora_metadata_field = "metadata"
  aurora_text_field = "chunks"
  aurora_verctor_field = "embedding"
  aurora_username   = "dbadmin"
  aurora_secret_arn = "arn:aws:secretsmanager:us-west-2:052666565139:secret:my-aurora-serverless-veVq6D" #TODO Update with output from stack1
  s3_bucket_arn = "arn:aws:s3:::bedrock-kb-052666565139" #TODO Update with output from stack1
}

# Service Role Name: AmazonBedrockExecutionRoleForKnowledgeBase_rmtxp
# Data Source Name: knowledge-base-quick-start-ctzat-data-source
