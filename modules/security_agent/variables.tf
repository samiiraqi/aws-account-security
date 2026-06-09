variable "aws_region" {
  description = "AWS region"
  type        = string
}

variable "aws_account_id" {
  description = "AWS account ID"
  type        = string
}

variable "project_name" {
  description = "Project name used for naming resources"
  type        = string
}

variable "twilio_secret_arn" {
  description = "ARN of the Secrets Manager secret containing Twilio credentials"
  type        = string
}

variable "twilio_whatsapp_from" {
  description = "Twilio sandbox WhatsApp sender number (without whatsapp: prefix)"
  type        = string
  default     = "+14155238886"
}

variable "twilio_whatsapp_to" {
  description = "Recipient WhatsApp number for security alerts (without whatsapp: prefix)"
  type        = string
}

variable "claude_secret_name" {
  description = "Secrets Manager secret name containing the Claude API key ({\"api_key\": \"sk-ant-...\"})"
  type        = string
  default     = "aws-security-agent-claude-key"
}
