variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Name of the project, used for tagging and naming resources"
  type        = string
  default     = "aws-account-security"
}

variable "environment" {
  description = "Deployment environment (e.g. production, staging)"
  type        = string
  default     = "production"
}

variable "aws_account_id" {
  description = "AWS account ID where resources will be deployed"
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
