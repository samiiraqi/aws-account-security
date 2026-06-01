locals {
  lambda_function_name = "${var.project_name}-alerts-formatter"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 8
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
                label = "Alarm threshold"
                value = var.billing_alarm_threshold
                color = "#ff6961"
              }
            ]
          }
        }
      },
      {
        type   = "metric"
        x      = 8
        y      = 0
        width  = 8
        height = 6
        properties = {
          title   = "GuardDuty — Finding Count"
          view    = "timeSeries"
          region  = var.aws_region
          stat    = "Sum"
          period  = 300
          metrics = [
            ["AWS/GuardDuty", "FindingCount"]
          ]
        }
      },
      {
        type   = "metric"
        x      = 16
        y      = 0
        width  = 8
        height = 6
        properties = {
          title   = "Config — Non-Compliant Rules"
          view    = "timeSeries"
          region  = var.aws_region
          stat    = "Sum"
          period  = 300
          metrics = [
            ["AWS/Config", "ComplianceByConfigRule", "ComplianceType", "NON_COMPLIANT"]
          ]
        }
      }
    ]
  })
}

# ---------------------------------------------------------------
# 1 + 2. SNS Topic & Email Subscription
# EventBridge now routes through Lambda — only CloudWatch (billing)
# publishes directly to SNS, so the topic policy reflects that.
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
        Sid    = "AllowCloudWatchPublish"
        Effect = "Allow"
        Principal = {
          Service = "cloudwatch.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.security_alerts.arn
      }
    ]
  })
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ---------------------------------------------------------------
# 3. AWS Budget — Monthly Cost
# Actual > 100% ($20) and Forecast > 80% ($16) trigger email
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
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [var.alert_email]
  }
}

# ---------------------------------------------------------------
# Lambda — Alert Formatter
# ---------------------------------------------------------------

data "archive_file" "lambda_alerts" {
  type        = "zip"
  source_file = "${path.module}/lambda/handler.py"
  output_path = "${path.module}/lambda/handler.zip"
}

resource "aws_iam_role" "lambda_alerts" {
  name = "${var.project_name}-lambda-alerts"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "lambda_alerts" {
  name = "sns-publish-and-logs"
  role = aws_iam_role.lambda_alerts.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "PublishToSNS"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.security_alerts.arn
      },
      {
        Sid    = "WriteLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.lambda_alerts.arn}:*"
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "lambda_alerts" {
  name              = "/aws/lambda/${local.lambda_function_name}"
  retention_in_days = 30
}

resource "aws_lambda_function" "alerts_formatter" {
  filename         = data.archive_file.lambda_alerts.output_path
  function_name    = local.lambda_function_name
  role             = aws_iam_role.lambda_alerts.arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.lambda_alerts.output_base64sha256
  timeout          = 30

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.security_alerts.arn
    }
  }

  depends_on = [aws_cloudwatch_log_group.lambda_alerts]
}

# ---------------------------------------------------------------
# 4. GuardDuty → EventBridge → Lambda → SNS
# ---------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "guardduty" {
  name        = "guardduty-findings"
  description = "Forward GuardDuty findings to the alert formatter Lambda"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
  })
}

resource "aws_cloudwatch_event_target" "guardduty_lambda" {
  rule      = aws_cloudwatch_event_rule.guardduty.name
  target_id = "GuardDutyToLambda"
  arn       = aws_lambda_function.alerts_formatter.arn
}

resource "aws_lambda_permission" "guardduty" {
  statement_id  = "AllowEventBridgeGuardDuty"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.alerts_formatter.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty.arn
}

# ---------------------------------------------------------------
# 5. Security Hub → EventBridge → Lambda → SNS
# Filter: only NEW + ACTIVE + FAILED findings
# ---------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "securityhub" {
  name        = "securityhub-findings"
  description = "Forward Security Hub failed findings to the alert formatter Lambda"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity    = { Label = ["CRITICAL", "HIGH"] }
        Compliance  = { Status = ["FAILED"] }
        Workflow    = { Status = ["NEW"] }
        RecordState = ["ACTIVE"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "securityhub_lambda" {
  rule      = aws_cloudwatch_event_rule.securityhub.name
  target_id = "SecurityHubToLambda"
  arn       = aws_lambda_function.alerts_formatter.arn
}

resource "aws_lambda_permission" "securityhub" {
  statement_id  = "AllowEventBridgeSecurityHub"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.alerts_formatter.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.securityhub.arn
}

# ---------------------------------------------------------------
# 6. CloudWatch Dashboard
# ---------------------------------------------------------------

resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "account-security"
  dashboard_body = local.dashboard_body
}
