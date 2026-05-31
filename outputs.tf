output "aws_region" {
  description = "AWS region used for deployment"
  value       = var.aws_region
}

output "project_name" {
  description = "Project name"
  value       = var.project_name
}

output "environment" {
  description = "Deployment environment"
  value       = var.environment
}

output "cloudtrail_arn" {
  description = "ARN of the CloudTrail trail"
  value       = module.security_baseline.cloudtrail_arn
}

output "cloudtrail_s3_bucket" {
  description = "S3 bucket storing CloudTrail logs"
  value       = module.security_baseline.cloudtrail_s3_bucket
}

output "cloudtrail_kms_key_arn" {
  description = "KMS key ARN used to encrypt CloudTrail logs"
  value       = module.security_baseline.cloudtrail_kms_key_arn
}
