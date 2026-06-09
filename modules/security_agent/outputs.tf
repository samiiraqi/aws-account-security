output "lambda_function_arn" {
  description = "ARN of the security agent Lambda function"
  value       = aws_lambda_function.security_agent.arn
}

output "lambda_function_name" {
  description = "Name of the security agent Lambda function"
  value       = aws_lambda_function.security_agent.function_name
}

output "responder_function_name" {
  description = "Name of the responder Lambda function"
  value       = aws_lambda_function.security_agent_responder.function_name
}

output "eventbridge_rule_arn" {
  description = "ARN of the GuardDuty EventBridge rule"
  value       = aws_cloudwatch_event_rule.guardduty.arn
}

output "webhook_url" {
  description = "API Gateway webhook URL — configure this in Twilio as the WhatsApp sandbox webhook"
  value       = "${aws_apigatewayv2_api.webhook.api_endpoint}/webhook"
}

output "dynamodb_table_name" {
  description = "DynamoDB table storing pending human-approval fixes"
  value       = aws_dynamodb_table.pending_fixes.name
}
