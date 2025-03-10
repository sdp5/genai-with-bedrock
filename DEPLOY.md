## Deployment Steps

1. Clone [this](https://github.com/udacity/cd13926-Building-Generative-AI-Applications-with-Amazon-Bedrock-and-Python-project-solution.git) repository to your local machine.
2. Navigate to the project `stack1`. This stack includes VPC, Aurora servlerless and S3.
3. Initialize Terraform: `terraform init`
4. Review and modify the Terraform variables in main.tf as needed, particularly:
    - AWS region
    - VPC CIDR block
    - Aurora Serverless configuration 
    - s3 bucket
5. Deploy the infrastructure: `terraform apply` Review the planned changes and type "yes" to confirm.
6. After the Terraform deployment is complete, note the outputs, particularly the Aurora cluster endpoint.
7. Prepare the Aurora Postgres database. This is done by running the sql queries in the script/ folder. This can be done through Amazon RDS console and the Query Editor.
8. Navigate to the project Stack 2. This stack includes Bedrock Knowledgebase
9. Initialize Terraform: `terraform init`
10. Use the values outputs of the stack 1 to modify the values in `main.tf` as needed:
    - Bedrock Knowledgebase configuration
11. Deploy the infrastructure: `terraform apply` Review the planned changes and type "yes" to confirm.
12. Upload pdf files to S3, place your files in the `spec-sheets` folder and run: `python scripts/upload_to_s3.py` Make sure to update the S3 bucket name in the script before running.
13. Sync the data source in the knowledgebase to make it available to the LLM.

