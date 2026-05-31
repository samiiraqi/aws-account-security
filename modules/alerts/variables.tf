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

variable "alert_email" {
  description = "Email address to receive security and billing alerts"
  type        = string
}

variable "billing_alarm_threshold" {
  description = "USD threshold that triggers the billing alarm"
  type        = number
  default     = 20
}
