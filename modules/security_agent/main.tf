locals {
  function_name           = "${var.project_name}-security-agent"
  responder_function_name = "${var.project_name}-security-agent-responder"
}

# ---------------------------------------------------------------
# Shared Lambda package (handler.py + responder.py + fixes.py)
# ---------------------------------------------------------------

data "archive_file" "security_agent" {
  type        = "zip"
  source_dir  = "${path.module}/lambda"
  output_path = "${path.module}/lambda/package.zip"
  excludes    = ["handler.zip", "package.zip"]
}

# ---------------------------------------------------------------
# DynamoDB — pending human-approval fixes
# ---------------------------------------------------------------

resource "aws_dynamodb_table" "pending_fixes" {
  name         = "${var.project_name}-pending-fixes"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "phone_number"

  attribute {
    name = "phone_number"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }
}

# ---------------------------------------------------------------
# Lambda — Security Agent (GuardDuty → Claude → fix or ask)
# ---------------------------------------------------------------

resource "aws_iam_role" "security_agent" {
  name = "${var.project_name}-security-agent"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "security_agent" {
  name = "agent-policy"
  role = aws_iam_role.security_agent.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadSecrets"
        Effect = "Allow"
        Action = "secretsmanager:GetSecretValue"
        Resource = [
          var.twilio_secret_arn,
          "arn:aws:secretsmanager:${var.aws_region}:${var.aws_account_id}:secret:${var.claude_secret_name}*"
        ]
      },
      {
        Sid      = "DynamoDBWrite"
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem"]
        Resource = aws_dynamodb_table.pending_fixes.arn
      },
      {
        Sid    = "EC2Remediation"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:RevokeSecurityGroupIngress"
        ]
        Resource = "*"
      },
      {
        Sid      = "S3Remediation"
        Effect   = "Allow"
        Action   = "s3:PutBucketPublicAccessBlock"
        Resource = "*"
      },
      {
        Sid    = "IAMRemediation"
        Effect = "Allow"
        Action = [
          "iam:DeleteAccessKey",
          "iam:ListAttachedUserPolicies",
          "iam:DetachUserPolicy"
        ]
        Resource = "*"
      },
      {
        Sid    = "WriteLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.security_agent.arn}:*"
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "security_agent" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = 30
}

resource "aws_lambda_function" "security_agent" {
  filename         = data.archive_file.security_agent.output_path
  function_name    = local.function_name
  role             = aws_iam_role.security_agent.arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.security_agent.output_base64sha256
  timeout          = 60

  environment {
    variables = {
      TWILIO_SECRET_ARN  = var.twilio_secret_arn
      CLAUDE_SECRET_NAME = var.claude_secret_name
      WHATSAPP_FROM      = var.twilio_whatsapp_from
      WHATSAPP_TO        = var.twilio_whatsapp_to
      TABLE_NAME         = aws_dynamodb_table.pending_fixes.name
    }
  }

  depends_on = [aws_cloudwatch_log_group.security_agent]
}

# ---------------------------------------------------------------
# Lambda — Security Agent Responder (Twilio webhook → execute fix)
# ---------------------------------------------------------------

resource "aws_iam_role" "security_agent_responder" {
  name = "${var.project_name}-security-agent-responder"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "security_agent_responder" {
  name = "responder-policy"
  role = aws_iam_role.security_agent_responder.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadTwilioSecret"
        Effect   = "Allow"
        Action   = "secretsmanager:GetSecretValue"
        Resource = var.twilio_secret_arn
      },
      {
        Sid    = "DynamoDBReadWrite"
        Effect = "Allow"
        Action = ["dynamodb:GetItem", "dynamodb:DeleteItem"]
        Resource = aws_dynamodb_table.pending_fixes.arn
      },
      {
        Sid    = "EC2Remediation"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:RevokeSecurityGroupIngress"
        ]
        Resource = "*"
      },
      {
        Sid      = "S3Remediation"
        Effect   = "Allow"
        Action   = "s3:PutBucketPublicAccessBlock"
        Resource = "*"
      },
      {
        Sid    = "IAMRemediation"
        Effect = "Allow"
        Action = [
          "iam:DeleteAccessKey",
          "iam:ListAttachedUserPolicies",
          "iam:DetachUserPolicy"
        ]
        Resource = "*"
      },
      {
        Sid    = "WriteLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.security_agent_responder.arn}:*"
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "security_agent_responder" {
  name              = "/aws/lambda/${local.responder_function_name}"
  retention_in_days = 30
}

resource "aws_lambda_function" "security_agent_responder" {
  filename         = data.archive_file.security_agent.output_path
  function_name    = local.responder_function_name
  role             = aws_iam_role.security_agent_responder.arn
  handler          = "responder.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.security_agent.output_base64sha256
  timeout          = 60

  environment {
    variables = {
      TWILIO_SECRET_ARN = var.twilio_secret_arn
      WHATSAPP_FROM     = var.twilio_whatsapp_from
      WHATSAPP_TO       = var.twilio_whatsapp_to
      TABLE_NAME        = aws_dynamodb_table.pending_fixes.name
    }
  }

  depends_on = [aws_cloudwatch_log_group.security_agent_responder]
}

# ---------------------------------------------------------------
# API Gateway HTTP API — Twilio webhook endpoint
# ---------------------------------------------------------------

resource "aws_apigatewayv2_api" "webhook" {
  name          = "${var.project_name}-whatsapp-webhook"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_integration" "responder" {
  api_id                 = aws_apigatewayv2_api.webhook.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.security_agent_responder.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "webhook" {
  api_id    = aws_apigatewayv2_api.webhook.id
  route_key = "POST /webhook"
  target    = "integrations/${aws_apigatewayv2_integration.responder.id}"
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.webhook.id
  name        = "$default"
  auto_deploy = true
}

resource "aws_lambda_permission" "api_gateway_responder" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.security_agent_responder.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.webhook.execution_arn}/*/*"
}

# ---------------------------------------------------------------
# GuardDuty → EventBridge → security_agent Lambda
# ---------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "guardduty" {
  name        = "${var.project_name}-guardduty-whatsapp"
  description = "Forward all GuardDuty findings to the security agent Lambda"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
  })
}

resource "aws_cloudwatch_event_target" "guardduty_lambda" {
  rule      = aws_cloudwatch_event_rule.guardduty.name
  target_id = "SecurityAgentLambda"
  arn       = aws_lambda_function.security_agent.arn
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.security_agent.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty.arn
}
