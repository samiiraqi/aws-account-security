output "cloudtrail_arn" {
  description = "ARN of the CloudTrail trail"
  value       = aws_cloudtrail.main.arn
}

output "cloudtrail_s3_bucket" {
  description = "S3 bucket name storing CloudTrail logs"
  value       = aws_s3_bucket.cloudtrail.bucket
}

output "cloudtrail_kms_key_arn" {
  description = "ARN of the KMS key used to encrypt CloudTrail logs"
  value       = aws_kms_key.cloudtrail.arn
}

output "cloudtrail_kms_key_id" {
  description = "ID of the KMS key used to encrypt CloudTrail logs"
  value       = aws_kms_key.cloudtrail.key_id
}
