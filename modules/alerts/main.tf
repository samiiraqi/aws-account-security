locals {
  lambda_function_name = "${var.project_name}-billing-whatsapp"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          title   = "Billing — Estimated Charges (USD)"
          view    = "timeSeries"
          region  = "us-east-1"
          stat    = "Maximum"
          period  = 86400
          metrics = [
            ["AWS/Billing", "EstimatedCharges", "Currency", "USD"]
          ]
          yAxis = { left = { min = 0 } }
          annotations = {
            horizontal = [
              {
                label = "Budget limit"
                value = var.billing_alarm_threshold
                color = "#ff6961"
              }
            ]
          }
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          title   = "SNS — Messages Published"
          view    = "timeSeries"
          region  = var.aws_region
          stat    = "Sum"
          period  = 300
          metrics = [
            ["AWS/SNS", "NumberOfMessagesPublished", "TopicName", aws_sns_topic.security_alerts.name]
          ]
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6
        properties = {
          title   = "Lambda — Invocations"
          view    = "timeSeries"
          region  = var.aws_region
          stat    = "Sum"
          period  = 300
          metrics = [
            ["AWS/Lambda", "Invocations", "FunctionName", local.lambda_function_name]
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 6
        width  = 12
        height = 6
        properties = {
          title   = "Lambda — Errors"
          view    = "timeSeries"
          region  = var.aws_region
          stat    = "Sum"
          period  = 300
          metrics = [
            ["AWS/Lambda", "Errors", "FunctionName", local.lambda_function_name]
          ]
          yAxis = { left = { min = 0 } }
        }
      }
    ]
  })
}

# ---------------------------------------------------------------
# SNS Topic
# Budget sends email directly — SNS is used only to trigger Lambda.
# The email subscription is omitted to avoid duplicate emails.
# ---------------------------------------------------------------

resource "aws_sns_topic" "security_alerts" {
  name = "security-alerts"
}

resource "aws_sns_topic_policy" "security_alerts" {
  arn = aws_sns_topic.security_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowBudgetsPublish"
        Effect = "Allow"
        Principal = {
          Service = "budgets.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.security_alerts.arn
      }
    ]
  })
}

# ---------------------------------------------------------------
# AWS Budget — Monthly Cost
# Direct email + SNS (SNS triggers Lambda → WhatsApp)
# ---------------------------------------------------------------

resource "aws_budgets_budget" "monthly" {
  name         = "${var.project_name}-monthly-budget"
  budget_type  = "COST"
  limit_amount = tostring(var.billing_alarm_threshold)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.alert_email]
    subscriber_sns_topic_arns  = [aws_sns_topic.security_alerts.arn]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [var.alert_email]
    subscriber_sns_topic_arns  = [aws_sns_topic.security_alerts.arn]
  }
}

# ---------------------------------------------------------------
# Twilio Credentials — Secrets Manager
# ---------------------------------------------------------------

resource "aws_secretsmanager_secret" "twilio" {
  name        = "${var.project_name}/twilio"
  description = "Twilio Account SID and Auth Token for WhatsApp alerts"
}

resource "aws_secretsmanager_secret_version" "twilio" {
  secret_id = aws_secretsmanager_secret.twilio.id
  secret_string = jsonencode({
    account_sid = "REPLACE_WITH_TWILIO_ACCOUNT_SID"
    auth_token  = "REPLACE_WITH_TWILIO_AUTH_TOKEN"
  })

  # Prevents Terraform from overwriting real credentials after initial creation
  lifecycle {
    ignore_changes = [secret_string]
  }
}

# ---------------------------------------------------------------
# Lambda — Billing WhatsApp Forwarder
# ---------------------------------------------------------------

data "archive_file" "lambda" {
  type        = "zip"
  source_file = "${path.module}/lambda/handler.py"
  output_path = "${path.module}/lambda/handler.zip"
}

resource "aws_iam_role" "lambda" {
  name = "${var.project_name}-billing-whatsapp"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "lambda" {
  name = "secretsmanager-and-logs"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadTwilioSecret"
        Effect   = "Allow"
        Action   = "secretsmanager:GetSecretValue"
        Resource = aws_secretsmanager_secret.twilio.arn
      },
      {
        Sid    = "WriteLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.lambda.arn}:*"
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${local.lambda_function_name}"
  retention_in_days = 30
}

resource "aws_lambda_function" "billing_whatsapp" {
  filename         = data.archive_file.lambda.output_path
  function_name    = local.lambda_function_name
  role             = aws_iam_role.lambda.arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.lambda.output_base64sha256
  timeout          = 30

  environment {
    variables = {
      TWILIO_SECRET_ARN = aws_secretsmanager_secret.twilio.arn
      WHATSAPP_FROM     = var.twilio_whatsapp_from
      WHATSAPP_TO       = var.twilio_whatsapp_to
      BUDGET_LIMIT_USD  = tostring(var.billing_alarm_threshold)
    }
  }

  depends_on = [aws_cloudwatch_log_group.lambda]
}

resource "aws_sns_topic_subscription" "lambda" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.billing_whatsapp.arn
}

resource "aws_lambda_permission" "sns" {
  statement_id  = "AllowSNSInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.billing_whatsapp.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.security_alerts.arn
}

# ---------------------------------------------------------------
# CloudWatch Dashboard
# ---------------------------------------------------------------

resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "account-security"
  dashboard_body = local.dashboard_body
}
