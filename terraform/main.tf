provider "aws" {
  region = var.aws_region
}

#Configuração do Terraform State
terraform {
  backend "s3" {
    bucket = "terraform-state-soat"
    key    = "hackathon-authentication-lambda/terraform.tfstate"
    region = "us-east-1"

    dynamodb_table = "terraform-state-soat-locking"
    encrypt        = true
  }
}

## .zip do código
data "archive_file" "code" {
  type        = "zip"
  source_dir  = "../src/code"
  output_path = "../src/code/code.zip"
}

#Security Group ECS
resource "aws_security_group" "security_group_auth_lambda" {
  name_prefix = "hackathon_security_group_auth_lambda"
  description = "HACKATHON SG for Authentication Lambda"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    infra   = "lambda"
    service = "gateway"
    Name    = "security_group_auth_lambda"
  }
}

## Infra lambda
resource "aws_lambda_function" "lambda_authentication" {
  function_name    = "hackathon-lambda-authentication"
  handler          = "lambda.main"
  runtime          = "python3.8"
  filename         = data.archive_file.code.output_path
  source_code_hash = data.archive_file.code.output_base64sha256
  role             = var.lambda_execution_role
  timeout          = 30
  description      = "Hackathon - Lambda para autenticar"

  vpc_config {
    subnet_ids         = [var.subnet_a, var.subnet_b]
    security_group_ids = [aws_security_group.security_group_auth_lambda.id]
  }

  environment {
    variables = {
      "RDS_ENDPOINT"    = var.rds_endpoint
      "DB_NAME"         = var.rds_db_name
      "SECRET_NAME"     = var.secret_name
      "SECRET_KEY_AUTH" = var.secret_name_auth
    }
  }
}
