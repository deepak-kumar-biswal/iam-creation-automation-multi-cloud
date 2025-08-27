# AWS IAM Module Variables
# Comprehensive variable definitions for enterprise-grade IAM management

variable "environment" {
  description = "Environment name (dev, staging, production)"
  type        = string
  validation {
    condition     = contains(["dev", "staging", "production"], var.environment)
    error_message = "Environment must be dev, staging, or production."
  }
}

variable "project_name" {
  description = "Name of the project for resource naming"
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.project_name))
    error_message = "Project name must contain only lowercase letters, numbers, and hyphens."
  }
}

variable "common_tags" {
  description = "Common tags to be applied to all resources"
  type        = map(string)
  default     = {}
}

# IAM Users Configuration
variable "iam_users" {
  description = "Map of IAM users to create"
  type = map(object({
    path                    = optional(string, "/")
    force_destroy          = optional(bool, false)
    console_access         = optional(bool, false)
    create_access_key      = optional(bool, false)
    generate_password      = optional(bool, false)
    password_reset_required = optional(bool, true)
    policy_arns            = optional(list(string), [])
    department             = optional(string, "")
    cost_center           = optional(string, "")
    owner                 = optional(string, "")
    access_level          = optional(string, "read-only")
    tags                  = optional(map(string), {})
  }))
  default = {}
  
  validation {
    condition = alltrue([
      for user_name, user_config in var.iam_users :
      can(regex("^[a-zA-Z0-9+=,.@_-]+$", user_name))
    ])
    error_message = "IAM user names must contain only alphanumeric characters and +=,.@_- symbols."
  }
}

# IAM Roles Configuration
variable "iam_roles" {
  description = "Map of IAM roles to create"
  type = map(object({
    path                   = optional(string, "/")
    assume_role_policy    = string
    description           = optional(string, "")
    max_session_duration  = optional(number, 3600)
    policy_arns           = optional(list(string), [])
    custom_policy_names   = optional(list(string), [])
    create_instance_profile = optional(bool, false)
    inline_policies       = optional(map(string), {})
    tags                  = optional(map(string), {})
  }))
  default = {}
}

# IAM Policies Configuration
variable "iam_policies" {
  description = "Map of custom IAM policies to create"
  type = map(object({
    path            = optional(string, "/")
    description     = string
    policy_document = string
    tags           = optional(map(string), {})
  }))
  default = {}
}

# IAM Groups Configuration
variable "iam_groups" {
  description = "Map of IAM groups to create"
  type = map(object({
    path        = optional(string, "/")
    policy_arns = optional(list(string), [])
    users       = optional(list(string), [])
  }))
  default = {}
}

# Service-Linked Roles
variable "service_linked_roles" {
  description = "Map of service-linked roles to create"
  type = map(object({
    aws_service_name = string
    description      = optional(string, "")
    custom_suffix    = optional(string, "")
  }))
  default = {}
}

# OIDC Identity Providers
variable "oidc_providers" {
  description = "Map of OIDC identity providers"
  type = map(object({
    url             = string
    client_id_list  = list(string)
    thumbprint_list = list(string)
    tags           = optional(map(string), {})
  }))
  default = {}
}

# SAML Identity Providers
variable "saml_providers" {
  description = "Map of SAML identity providers"
  type = map(object({
    saml_metadata_document = string
    tags                  = optional(map(string), {})
  }))
  default = {}
}

# Password Policy Configuration
variable "enable_password_policy" {
  description = "Whether to enable IAM password policy"
  type        = bool
  default     = true
}

variable "password_policy" {
  description = "IAM account password policy configuration"
  type = object({
    minimum_length              = optional(number, 14)
    require_lowercase          = optional(bool, true)
    require_numbers           = optional(bool, true)
    require_uppercase         = optional(bool, true)
    require_symbols           = optional(bool, true)
    allow_users_to_change     = optional(bool, true)
    hard_expiry              = optional(bool, false)
    max_age                  = optional(number, 90)
    reuse_prevention         = optional(number, 12)
  })
  default = {}
}

# Account Configuration
variable "account_alias" {
  description = "AWS account alias"
  type        = string
  default     = ""
}

# CloudTrail Configuration
variable "enable_cloudtrail" {
  description = "Whether to enable CloudTrail for IAM audit logging"
  type        = bool
  default     = false
}

variable "cloudtrail_bucket_name" {
  description = "S3 bucket name for CloudTrail logs"
  type        = string
  default     = ""
}

# Access Analyzer Configuration
variable "enable_access_analyzer" {
  description = "Whether to enable IAM Access Analyzer"
  type        = bool
  default     = true
}

# KMS Configuration
variable "kms_key_id" {
  description = "KMS key ID for encrypting sensitive parameters"
  type        = string
  default     = "alias/aws/ssm"
}

# Multi-Account Configuration
variable "cross_account_roles" {
  description = "Cross-account roles configuration for multi-account access"
  type = map(object({
    trusted_account_ids = list(string)
    external_id        = optional(string, "")
    require_mfa        = optional(bool, true)
    session_duration   = optional(number, 3600)
    policy_arns        = list(string)
    conditions         = optional(map(any), {})
  }))
  default = {}
}

# Organization Configuration
variable "organization_config" {
  description = "AWS Organizations configuration"
  type = object({
    management_account_id = optional(string, "")
    organization_units   = optional(map(object({
      name        = string
      parent_id   = string
      policy_arns = optional(list(string), [])
    })), {})
    service_control_policies = optional(map(object({
      name        = string
      description = string
      policy      = string
      targets     = list(string)
    })), {})
  })
  default = {}
}

# Compliance Configuration
variable "compliance_config" {
  description = "Compliance and governance configuration"
  type = object({
    enable_config_rules      = optional(bool, true)
    enable_security_hub      = optional(bool, true)
    enable_guardduty        = optional(bool, true)
    compliance_frameworks   = optional(list(string), ["SOC2", "PCI-DSS"])
    audit_log_retention     = optional(number, 2557) # 7 years
    notification_endpoints  = optional(list(string), [])
  })
  default = {}
}

# Advanced Security Configuration
variable "security_config" {
  description = "Advanced security configuration"
  type = object({
    enable_mfa_enforcement     = optional(bool, true)
    max_session_duration      = optional(number, 3600)
    unused_credentials_days   = optional(number, 90)
    password_max_age         = optional(number, 90)
    enable_access_logging    = optional(bool, true)
    suspicious_activity_detection = optional(bool, true)
    ip_restriction_enabled   = optional(bool, false)
    allowed_ip_ranges        = optional(list(string), [])
  })
  default = {}
}

# Monitoring and Alerting Configuration
variable "monitoring_config" {
  description = "Monitoring and alerting configuration"
  type = object({
    enable_cloudwatch_insights = optional(bool, true)
    metric_filters            = optional(map(object({
      filter_pattern = string
      metric_name   = string
      namespace     = optional(string, "IAM/Security")
      value         = optional(string, "1")
    })), {})
    alarms = optional(map(object({
      metric_name         = string
      threshold           = number
      comparison_operator = string
      evaluation_periods  = number
      alarm_actions      = list(string)
      treat_missing_data = optional(string, "breaching")
    })), {})
  })
  default = {}
}

# Backup and Disaster Recovery
variable "backup_config" {
  description = "Backup and disaster recovery configuration"
  type = object({
    enable_cross_region_replication = optional(bool, true)
    backup_regions                 = optional(list(string), ["us-west-2"])
    enable_point_in_time_recovery  = optional(bool, true)
    backup_retention_days          = optional(number, 90)
    enable_automated_backups       = optional(bool, true)
  })
  default = {}
}

# Cost Management
variable "cost_config" {
  description = "Cost management configuration"
  type = object({
    enable_cost_allocation_tags = optional(bool, true)
    cost_center_tag_key        = optional(string, "CostCenter")
    project_tag_key           = optional(string, "Project")
    owner_tag_key             = optional(string, "Owner")
    enable_budget_alerts      = optional(bool, true)
    monthly_budget_limit      = optional(number, 1000)
    budget_alert_thresholds   = optional(list(number), [50, 80, 100])
  })
  default = {}
}
