# Multi-Cloud IAM Automation - AWS Module
# This module creates and manages IAM resources across AWS accounts at scale

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.1"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.9"
    }
  }
}

# Local variables for common configurations
locals {
  common_tags = merge(var.common_tags, {
    Module      = "aws-iam"
    Environment = var.environment
    ManagedBy   = "terraform"
    Project     = var.project_name
    CreatedAt   = timestamp()
  })
  
  # Generate role names with consistent naming convention
  role_prefix = "${var.project_name}-${var.environment}"
  
  # Policy attachment mappings
  role_policy_attachments = flatten([
    for role_name, role_config in var.iam_roles : [
      for policy_arn in role_config.policy_arns : {
        role_name  = role_name
        policy_arn = policy_arn
      }
    ]
  ])
  
  user_policy_attachments = flatten([
    for user_name, user_config in var.iam_users : [
      for policy_arn in user_config.policy_arns : {
        user_name  = user_name
        policy_arn = policy_arn
      }
    ]
  ])
}

# Random password generation for IAM users
resource "random_password" "user_passwords" {
  for_each = {
    for user_name, user_config in var.iam_users : user_name => user_config
    if user_config.generate_password
  }
  
  length  = 20
  special = true
  
  keepers = {
    user = each.key
  }
}

# IAM Users
resource "aws_iam_user" "users" {
  for_each = var.iam_users
  
  name          = each.key
  path          = each.value.path
  force_destroy = each.value.force_destroy
  
  tags = merge(local.common_tags, each.value.tags, {
    Name        = each.key
    Department  = each.value.department
    CostCenter  = each.value.cost_center
    Owner       = each.value.owner
    AccessLevel = each.value.access_level
  })
}

# IAM User Login Profiles (for console access)
resource "aws_iam_user_login_profile" "user_login" {
  for_each = {
    for user_name, user_config in var.iam_users : user_name => user_config
    if user_config.console_access
  }
  
  user                    = aws_iam_user.users[each.key].name
  password_reset_required = each.value.password_reset_required
  password_length         = 20
  
  lifecycle {
    ignore_changes = [password_reset_required]
  }
}

# IAM Access Keys
resource "aws_iam_access_key" "user_access_keys" {
  for_each = {
    for user_name, user_config in var.iam_users : user_name => user_config
    if user_config.create_access_key
  }
  
  user   = aws_iam_user.users[each.key].name
  status = "Active"
}

# IAM Roles
resource "aws_iam_role" "roles" {
  for_each = var.iam_roles
  
  name               = "${local.role_prefix}-${each.key}"
  path               = each.value.path
  assume_role_policy = each.value.assume_role_policy
  description        = each.value.description
  max_session_duration = each.value.max_session_duration
  
  dynamic "inline_policy" {
    for_each = each.value.inline_policies
    content {
      name   = inline_policy.key
      policy = inline_policy.value
    }
  }
  
  tags = merge(local.common_tags, each.value.tags, {
    Name = "${local.role_prefix}-${each.key}"
    Type = "IAMRole"
  })
}

# Custom IAM Policies
resource "aws_iam_policy" "custom_policies" {
  for_each = var.iam_policies
  
  name        = "${local.role_prefix}-${each.key}"
  path        = each.value.path
  description = each.value.description
  policy      = each.value.policy_document
  
  tags = merge(local.common_tags, each.value.tags, {
    Name = "${local.role_prefix}-${each.key}"
    Type = "IAMPolicy"
  })
}

# IAM Groups
resource "aws_iam_group" "groups" {
  for_each = var.iam_groups
  
  name = each.key
  path = each.value.path
}

# IAM Group Policy Attachments
resource "aws_iam_group_policy_attachment" "group_policy_attachments" {
  for_each = {
    for attachment in flatten([
      for group_name, group_config in var.iam_groups : [
        for policy_arn in group_config.policy_arns : {
          group_name = group_name
          policy_arn = policy_arn
          key        = "${group_name}-${basename(policy_arn)}"
        }
      ]
    ]) : attachment.key => attachment
  }
  
  group      = aws_iam_group.groups[each.value.group_name].name
  policy_arn = each.value.policy_arn
}

# IAM Group Memberships
resource "aws_iam_group_membership" "group_memberships" {
  for_each = var.iam_groups
  
  name  = "${each.key}-membership"
  group = aws_iam_group.groups[each.key].name
  users = each.value.users
  
  depends_on = [aws_iam_user.users]
}

# Role Policy Attachments (AWS Managed Policies)
resource "aws_iam_role_policy_attachment" "role_managed_policy_attachments" {
  for_each = {
    for attachment in local.role_policy_attachments : 
    "${attachment.role_name}-${basename(attachment.policy_arn)}" => attachment
  }
  
  role       = aws_iam_role.roles[each.value.role_name].name
  policy_arn = each.value.policy_arn
}

# User Policy Attachments (AWS Managed Policies)
resource "aws_iam_user_policy_attachment" "user_managed_policy_attachments" {
  for_each = {
    for attachment in local.user_policy_attachments : 
    "${attachment.user_name}-${basename(attachment.policy_arn)}" => attachment
  }
  
  user       = aws_iam_user.users[each.value.user_name].name
  policy_arn = each.value.policy_arn
}

# Custom Policy Attachments to Roles
resource "aws_iam_role_policy_attachment" "role_custom_policy_attachments" {
  for_each = {
    for attachment in flatten([
      for role_name, role_config in var.iam_roles : [
        for policy_name in role_config.custom_policy_names : {
          role_name    = role_name
          policy_name  = policy_name
          key         = "${role_name}-${policy_name}"
        }
      ]
    ]) : attachment.key => attachment
  }
  
  role       = aws_iam_role.roles[each.value.role_name].name
  policy_arn = aws_iam_policy.custom_policies[each.value.policy_name].arn
}

# Instance Profiles for EC2 roles
resource "aws_iam_instance_profile" "instance_profiles" {
  for_each = {
    for role_name, role_config in var.iam_roles : role_name => role_config
    if role_config.create_instance_profile
  }
  
  name = "${local.role_prefix}-${each.key}-instance-profile"
  role = aws_iam_role.roles[each.key].name
  path = each.value.path
  
  tags = merge(local.common_tags, {
    Name = "${local.role_prefix}-${each.key}-instance-profile"
    Type = "InstanceProfile"
  })
}

# Service-linked roles (for specific AWS services)
resource "aws_iam_service_linked_role" "service_linked_roles" {
  for_each = var.service_linked_roles
  
  aws_service_name = each.value.aws_service_name
  description      = each.value.description
  custom_suffix    = each.value.custom_suffix
}

# OIDC Identity Providers (for GitHub Actions, etc.)
resource "aws_iam_openid_connect_provider" "oidc_providers" {
  for_each = var.oidc_providers
  
  url             = each.value.url
  client_id_list  = each.value.client_id_list
  thumbprint_list = each.value.thumbprint_list
  
  tags = merge(local.common_tags, each.value.tags, {
    Name = each.key
    Type = "OIDCProvider"
  })
}

# SAML Identity Providers
resource "aws_iam_saml_provider" "saml_providers" {
  for_each = var.saml_providers
  
  name                   = each.key
  saml_metadata_document = each.value.saml_metadata_document
  
  tags = merge(local.common_tags, each.value.tags, {
    Name = each.key
    Type = "SAMLProvider"
  })
}

# Password Policy
resource "aws_iam_account_password_policy" "password_policy" {
  count = var.enable_password_policy ? 1 : 0
  
  minimum_password_length        = var.password_policy.minimum_length
  require_lowercase_characters   = var.password_policy.require_lowercase
  require_numbers               = var.password_policy.require_numbers
  require_uppercase_characters   = var.password_policy.require_uppercase
  require_symbols               = var.password_policy.require_symbols
  allow_users_to_change_password = var.password_policy.allow_users_to_change
  hard_expiry                   = var.password_policy.hard_expiry
  max_password_age              = var.password_policy.max_age
  password_reuse_prevention     = var.password_policy.reuse_prevention
}

# Account Alias
resource "aws_iam_account_alias" "account_alias" {
  count = var.account_alias != "" ? 1 : 0
  
  account_alias = var.account_alias
}

# CloudTrail for IAM API calls (if enabled)
resource "aws_cloudtrail" "iam_audit_trail" {
  count = var.enable_cloudtrail ? 1 : 0
  
  name                         = "${var.project_name}-${var.environment}-iam-audit"
  s3_bucket_name              = var.cloudtrail_bucket_name
  s3_key_prefix               = "iam-audit/"
  include_global_service_events = true
  is_multi_region_trail       = true
  enable_logging              = true
  enable_log_file_validation  = true
  
  event_selector {
    read_write_type                 = "All"
    include_management_events       = true
    exclude_management_event_sources = []
    
    data_resource {
      type   = "AWS::IAM::Role"
      values = ["arn:aws:iam::*:role/*"]
    }
    
    data_resource {
      type   = "AWS::IAM::User"
      values = ["arn:aws:iam::*:user/*"]
    }
    
    data_resource {
      type   = "AWS::IAM::Policy"
      values = ["arn:aws:iam::*:policy/*"]
    }
  }
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-${var.environment}-iam-audit"
    Type = "CloudTrail"
  })
}

# IAM Access Analyzer
resource "aws_accessanalyzer_analyzer" "iam_analyzer" {
  count = var.enable_access_analyzer ? 1 : 0
  
  analyzer_name = "${var.project_name}-${var.environment}-iam-analyzer"
  type         = "ACCOUNT"
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-${var.environment}-iam-analyzer"
    Type = "AccessAnalyzer"
  })
}

# Store sensitive outputs in AWS Systems Manager Parameter Store
resource "aws_ssm_parameter" "user_passwords" {
  for_each = random_password.user_passwords
  
  name        = "/iam/${var.environment}/users/${each.key}/password"
  description = "Password for IAM user ${each.key}"
  type        = "SecureString"
  value       = each.value.result
  key_id      = var.kms_key_id
  
  tags = merge(local.common_tags, {
    Name     = "/iam/${var.environment}/users/${each.key}/password"
    UserName = each.key
    Type     = "UserPassword"
  })
}

resource "aws_ssm_parameter" "access_keys" {
  for_each = aws_iam_access_key.user_access_keys
  
  name        = "/iam/${var.environment}/users/${each.key}/access_key"
  description = "Access key for IAM user ${each.key}"
  type        = "SecureString"
  value = jsonencode({
    access_key_id     = each.value.id
    secret_access_key = each.value.secret
  })
  key_id = var.kms_key_id
  
  tags = merge(local.common_tags, {
    Name     = "/iam/${var.environment}/users/${each.key}/access_key"
    UserName = each.key
    Type     = "AccessKey"
  })
}
