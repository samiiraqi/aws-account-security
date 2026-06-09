terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }

  backend "s3" {}
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

module "security_baseline" {
  source = "./modules/security_baseline"

  aws_region     = var.aws_region
  aws_account_id = var.aws_account_id
  project_name   = var.project_name
  environment    = var.environment
}

module "alerts" {
  source = "./modules/alerts"

  aws_region              = var.aws_region
  aws_account_id          = var.aws_account_id
  project_name            = var.project_name
  alert_email             = var.alert_email
  billing_alarm_threshold = var.billing_alarm_threshold
  twilio_whatsapp_to      = var.twilio_whatsapp_to
}

module "security_agent" {
  source = "./modules/security_agent"

  aws_region         = var.aws_region
  aws_account_id     = var.aws_account_id
  project_name       = var.project_name
  twilio_secret_arn  = module.alerts.twilio_secret_arn
  twilio_whatsapp_to = var.twilio_whatsapp_to
}
