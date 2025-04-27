terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
  
  backend "s3" {
    # These values will be filled in during deployment
    # bucket         = "msdefender-slack-terraform-state"
    # key            = "terraform.tfstate"
    # region         = "us-east-1"
    # dynamodb_table = "msdefender-slack-terraform-lock"
  }
}

provider "aws" {
  region = var.aws_region
}

# API Gateway for receiving Microsoft Defender webhooks
resource "aws_api_gateway_rest_api" "defender_webhook" {
  name        = "${var.project_name}-api"
  description = "API Gateway for Microsoft Defender webhook"
}

resource "aws_api_gateway_resource" "defender_webhook" {
  rest_api_id = aws_api_gateway_rest_api.defender_webhook.id
  parent_id   = aws_api_gateway_rest_api.defender_webhook.root_resource_id
  path_part   = "webhook"
}

resource "aws_api_gateway_method" "defender_webhook" {
  rest_api_id   = aws_api_gateway_rest_api.defender_webhook.id
  resource_id   = aws_api_gateway_resource.defender_webhook.id
  http_method   = "POST"
  authorization_type = "NONE"  # Simple MVP, consider adding API key or other auth for production
}

resource "aws_api_gateway_integration" "lambda_integration" {
  rest_api_id = aws_api_gateway_rest_api.defender_webhook.id
  resource_id = aws_api_gateway_resource.defender_webhook.id
  http_method = aws_api_gateway_method.defender_webhook.http_method

  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.alert_processor.invoke_arn
}

# Deploy the API Gateway
resource "aws_api_gateway_deployment" "defender_webhook" {
  depends_on = [
    aws_api_gateway_integration.lambda_integration
  ]

  rest_api_id = aws_api_gateway_rest_api.defender_webhook.id
  stage_name  = var.environment

  lifecycle {
    create_before_destroy = true
  }
}

# Alert Processor Lambda
resource "aws_lambda_function" "alert_processor" {
  function_name = "${var.project_name}-alert-processor"
  handler       = "functions.alert_processor.handler"
  role          = aws_iam_role.lambda_exec.arn
  runtime       = "python3.9"

  filename      = var.lambda_package_path
  source_code_hash = filebase64sha256(var.lambda_package_path)

  timeout       = 30
  memory_size   = 256

  environment {
    variables = {
      SLACK_CHANNEL = var.slack_channel
      ENVIRONMENT   = var.environment
    }
  }
}

# Summary Generator Lambda
resource "aws_lambda_function" "summary_generator" {
  function_name = "${var.project_name}-summary-generator"
  handler       = "functions.summary_generator.handler"
  role          = aws_iam_role.lambda_exec.arn
  runtime       = "python3.9"

  filename      = var.lambda_package_path
  source_code_hash = filebase64sha256(var.lambda_package_path)

  timeout       = 60
  memory_size   = 256

  environment {
    variables = {
      SLACK_CHANNEL = var.slack_channel
      ENVIRONMENT   = var.environment
    }
  }
}

# EventBridge rule for daily summary - runs at 9:00 AM on weekdays
resource "aws_cloudwatch_event_rule" "daily_summary" {
  name        = "${var.project_name}-daily-summary"
  description = "Trigger daily summary report generation at 9:00 AM on weekdays"
  
  # Schedule expression for 9:00 AM UTC Monday-Friday
  schedule_expression = "cron(0 9 ? * MON-FRI *)"
}

resource "aws_cloudwatch_event_target" "daily_summary" {
  rule      = aws_cloudwatch_event_rule.daily_summary.name
  target_id = "lambda"
  arn       = aws_lambda_function.summary_generator.arn
}

# IAM role for Lambda functions
resource "aws_iam_role" "lambda_exec" {
  name = "${var.project_name}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

# IAM policy for Lambda functions
resource "aws_iam_policy" "lambda_policy" {
  name        = "${var.project_name}-lambda-policy"
  description = "IAM policy for Lambda functions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Effect   = "Allow"
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Effect   = "Allow"
        Resource = aws_secretsmanager_secret.api_keys.arn
      }
    ]
  })
}

# Attach policy to role
resource "aws_iam_role_policy_attachment" "lambda_policy_attachment" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}

# Permission for API Gateway to invoke Lambda
resource "aws_lambda_permission" "api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.alert_processor.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.defender_webhook.execution_arn}/*/${aws_api_gateway_method.defender_webhook.http_method}${aws_api_gateway_resource.defender_webhook.path}"
}

# Permission for EventBridge to invoke Lambda
resource "aws_lambda_permission" "events" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.summary_generator.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.daily_summary.arn
}

# Secret for storing API keys
resource "aws_secretsmanager_secret" "api_keys" {
  name        = "${var.project_name}-api-keys"
  description = "API keys for Microsoft Defender and Slack"
}

# Default secret value (this is just a placeholder, real values should be populated outside of Terraform)
resource "aws_secretsmanager_secret_version" "api_keys" {
  secret_id     = aws_secretsmanager_secret.api_keys.id
  secret_string = jsonencode({
    microsoft_defender_client_id     = "placeholder",
    microsoft_defender_client_secret = "placeholder",
    slack_api_token                  = "placeholder"
  })
}

# Output the API Gateway URL
output "api_gateway_url" {
  value = "${aws_api_gateway_deployment.defender_webhook.invoke_url}${aws_api_gateway_resource.defender_webhook.path}"
} 