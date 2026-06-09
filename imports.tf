import {
  to = module.security_baseline.aws_guardduty_detector.main
  id = "38cf2feb15352114f51da9dba1d557b8"
}

import {
  to = module.security_baseline.aws_securityhub_account.main
  id = "156041402173"
}

import {
  to = module.security_baseline.aws_securityhub_standards_subscription.fsbp
  id = "arn:aws:securityhub:us-east-1:156041402173:subscription/aws-foundational-security-best-practices/v/1.0.0"
}

import {
  to = module.security_baseline.aws_securityhub_standards_subscription.cis
  id = "arn:aws:securityhub:us-east-1:156041402173:subscription/cis-aws-foundations-benchmark/v/1.2.0"
}
