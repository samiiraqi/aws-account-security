# ---------------------------------------------------------------
# 1 + 2. SNS Topic & Email Subscription
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
        Sid    = "AllowEventBridgePublish"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.security_alerts.arn
      },
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
# 3. Billing Alarm
# Billing metrics are global but published only to us-east-1
# ---------------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "billing" {
  alarm_name          = "billing-threshold-${var.billing_alarm_threshold}-usd"
  alarm_description   = "Estimated charges exceeded $${var.billing_alarm_threshold} USD"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "EstimatedCharges"
  namespace           = "AWS/Billing"
  period              = 86400
  statistic           = "Maximum"
  threshold           = var.billing_alarm_threshold
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]

  dimensions = {
    Currency = "USD"
  }
}

# ---------------------------------------------------------------
# 4. GuardDuty → EventBridge → SNS
# ---------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "guardduty" {
  name        = "guardduty-findings"
  description = "Forward GuardDuty findings to SNS"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
  })
}

resource "aws_cloudwatch_event_target" "guardduty_sns" {
  rule      = aws_cloudwatch_event_rule.guardduty.name
  target_id = "GuardDutyToSNS"
  arn       = aws_sns_topic.security_alerts.arn
}

# ---------------------------------------------------------------
# 5. Security Hub → EventBridge → SNS
# Filter: only NEW + ACTIVE + FAILED findings
# ---------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "securityhub" {
  name        = "securityhub-findings"
  description = "Forward Security Hub failed findings to SNS"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Compliance  = { Status = ["FAILED"] }
        Workflow    = { Status = ["NEW"] }
        RecordState = ["ACTIVE"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "securityhub_sns" {
  rule      = aws_cloudwatch_event_rule.securityhub.name
  target_id = "SecurityHubToSNS"
  arn       = aws_sns_topic.security_alerts.arn
}

# ---------------------------------------------------------------
# 6. CloudWatch Dashboard
# ---------------------------------------------------------------

locals {
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

resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "account-security"
  dashboard_body = local.dashboard_body
}
