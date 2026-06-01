output "sns_topic_arn" {
  description = "ARN of the security-alerts SNS topic"
  value       = aws_sns_topic.security_alerts.arn
}

output "sns_topic_name" {
  description = "Name of the security-alerts SNS topic"
  value       = aws_sns_topic.security_alerts.name
}

output "dashboard_name" {
  description = "Name of the CloudWatch dashboard"
  value       = aws_cloudwatch_dashboard.main.dashboard_name
}

output "monthly_budget_name" {
  description = "Name of the monthly AWS budget"
  value       = aws_budgets_budget.monthly.name
}

output "lambda_function_arn" {
  description = "ARN of the alert formatter Lambda function"
  value       = aws_lambda_function.alerts_formatter.arn
}

output "lambda_function_name" {
  description = "Name of the alert formatter Lambda function"
  value       = aws_lambda_function.alerts_formatter.function_name
}
