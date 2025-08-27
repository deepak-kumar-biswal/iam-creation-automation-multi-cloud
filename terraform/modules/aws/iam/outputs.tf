# AWS IAM Module Outputs
# Comprehensive outputs for created IAM resources

# IAM Users Outputs
output "iam_users" {
  description = "Map of created IAM users"
  value = {
    for user_name, user in aws_iam_user.users : user_name => {
      arn              = user.arn
      name             = user.name
      path             = user.path
      unique_id        = user.unique_id
      console_access   = contains(keys(aws_iam_user_login_profile.user_login), user_name)
      access_key_id    = try(aws_iam_access_key.user_access_keys[user_name].id, null)
      tags             = user.tags
    }
  }
  sensitive = false
}

# IAM User Access Keys (ARNs only for security)
output "iam_user_access_keys" {
  description = "Map of IAM user access key metadata (sensitive values stored in SSM)"
  value = {
    for user_name, access_key in aws_iam_access_key.user_access_keys : user_name => {
      access_key_id     = access_key.id
      user              = access_key.user
      status            = access_key.status
      create_date       = access_key.create_date
      ssm_parameter_arn = aws_ssm_parameter.access_keys[user_name].arn
    }
  }
  sensitive = true
}

# IAM Roles Outputs
output "iam_roles" {
  description = "Map of created IAM roles"
  value = {
    for role_name, role in aws_iam_role.roles : role_name => {
      arn                  = role.arn
      name                 = role.name
      path                 = role.path
      unique_id           = role.unique_id
      description         = role.description
      max_session_duration = role.max_session_duration
      instance_profile_arn = try(aws_iam_instance_profile.instance_profiles[role_name].arn, null)
      tags                = role.tags
    }
  }
}

# IAM Policies Outputs
output "iam_policies" {
  description = "Map of created custom IAM policies"
  value = {
    for policy_name, policy in aws_iam_policy.custom_policies : policy_name => {
      arn         = policy.arn
      name        = policy.name
      path        = policy.path
      policy_id   = policy.policy_id
      description = policy.description
      tags        = policy.tags
    }
  }
}

# IAM Groups Outputs
output "iam_groups" {
  description = "Map of created IAM groups"
  value = {
    for group_name, group in aws_iam_group.groups : group_name => {
      arn       = group.arn
      name      = group.name
      path      = group.path
      unique_id = group.unique_id
      members   = try(aws_iam_group_membership.group_memberships[group_name].users, [])
    }
  }
}

# Instance Profiles Outputs
output "iam_instance_profiles" {
  description = "Map of created IAM instance profiles"
  value = {
    for profile_name, profile in aws_iam_instance_profile.instance_profiles : profile_name => {
      arn         = profile.arn
      name        = profile.name
      path        = profile.path
      unique_id   = profile.unique_id
      create_date = profile.create_date
      role        = profile.role
    }
  }
}

# Service-Linked Roles Outputs
output "service_linked_roles" {
  description = "Map of created service-linked roles"
  value = {
    for role_name, role in aws_iam_service_linked_role.service_linked_roles : role_name => {
      arn              = role.arn
      name             = role.name
      path             = role.path
      unique_id        = role.unique_id
      aws_service_name = role.aws_service_name
      description      = role.description
      custom_suffix    = role.custom_suffix
    }
  }
}

# OIDC Identity Providers Outputs
output "oidc_providers" {
  description = "Map of created OIDC identity providers"
  value = {
    for provider_name, provider in aws_iam_openid_connect_provider.oidc_providers : provider_name => {
      arn             = provider.arn
      url             = provider.url
      client_id_list  = provider.client_id_list
      thumbprint_list = provider.thumbprint_list
      tags           = provider.tags
    }
  }
}

# SAML Identity Providers Outputs
output "saml_providers" {
  description = "Map of created SAML identity providers"
  value = {
    for provider_name, provider in aws_iam_saml_provider.saml_providers : provider_name => {
      arn        = provider.arn
      name       = provider.name
      valid_until = provider.valid_until
      tags       = provider.tags
    }
  }
}

# Password Policy Output
output "password_policy" {
  description = "IAM account password policy configuration"
  value = var.enable_password_policy ? {
    minimum_password_length        = one(aws_iam_account_password_policy.password_policy[*].minimum_password_length)
    require_lowercase_characters   = one(aws_iam_account_password_policy.password_policy[*].require_lowercase_characters)
    require_numbers               = one(aws_iam_account_password_policy.password_policy[*].require_numbers)
    require_uppercase_characters   = one(aws_iam_account_password_policy.password_policy[*].require_uppercase_characters)
    require_symbols               = one(aws_iam_account_password_policy.password_policy[*].require_symbols)
    allow_users_to_change_password = one(aws_iam_account_password_policy.password_policy[*].allow_users_to_change_password)
    hard_expiry                   = one(aws_iam_account_password_policy.password_policy[*].hard_expiry)
    max_password_age              = one(aws_iam_account_password_policy.password_policy[*].max_password_age)
    password_reuse_prevention     = one(aws_iam_account_password_policy.password_policy[*].password_reuse_prevention)
  } : null
}

# Account Alias Output
output "account_alias" {
  description = "AWS account alias"
  value       = var.account_alias != "" ? one(aws_iam_account_alias.account_alias[*].account_alias) : null
}

# CloudTrail Output
output "cloudtrail" {
  description = "CloudTrail configuration for IAM audit logging"
  value = var.enable_cloudtrail ? {
    arn                    = one(aws_cloudtrail.iam_audit_trail[*].arn)
    name                   = one(aws_cloudtrail.iam_audit_trail[*].name)
    s3_bucket_name         = one(aws_cloudtrail.iam_audit_trail[*].s3_bucket_name)
    home_region           = one(aws_cloudtrail.iam_audit_trail[*].home_region)
    is_multi_region_trail = one(aws_cloudtrail.iam_audit_trail[*].is_multi_region_trail)
  } : null
}

# Access Analyzer Output
output "access_analyzer" {
  description = "IAM Access Analyzer configuration"
  value = var.enable_access_analyzer ? {
    arn           = one(aws_accessanalyzer_analyzer.iam_analyzer[*].arn)
    analyzer_name = one(aws_accessanalyzer_analyzer.iam_analyzer[*].analyzer_name)
    type         = one(aws_accessanalyzer_analyzer.iam_analyzer[*].type)
  } : null
}

# SSM Parameters for Sensitive Data
output "ssm_parameters" {
  description = "SSM parameter store paths for sensitive IAM data"
  value = {
    user_passwords = {
      for user_name, param in aws_ssm_parameter.user_passwords : user_name => {
        name = param.name
        arn  = param.arn
        type = param.type
      }
    }
    access_keys = {
      for user_name, param in aws_ssm_parameter.access_keys : user_name => {
        name = param.name
        arn  = param.arn
        type = param.type
      }
    }
  }
  sensitive = true
}

# Summary Statistics
output "resource_summary" {
  description = "Summary of created IAM resources"
  value = {
    users_created                = length(aws_iam_user.users)
    roles_created               = length(aws_iam_role.roles)
    policies_created            = length(aws_iam_policy.custom_policies)
    groups_created              = length(aws_iam_group.groups)
    instance_profiles_created   = length(aws_iam_instance_profile.instance_profiles)
    service_linked_roles_created = length(aws_iam_service_linked_role.service_linked_roles)
    oidc_providers_created      = length(aws_iam_openid_connect_provider.oidc_providers)
    saml_providers_created      = length(aws_iam_saml_provider.saml_providers)
    password_policy_enabled     = var.enable_password_policy
    cloudtrail_enabled         = var.enable_cloudtrail
    access_analyzer_enabled    = var.enable_access_analyzer
    account_alias_set          = var.account_alias != ""
  }
}

# Role ARNs for Cross-Account Access
output "role_arns" {
  description = "Map of role names to ARNs for cross-account access configuration"
  value = {
    for role_name, role in aws_iam_role.roles : role_name => role.arn
  }
}

# Policy ARNs for Reference
output "policy_arns" {
  description = "Map of custom policy names to ARNs"
  value = {
    for policy_name, policy in aws_iam_policy.custom_policies : policy_name => policy.arn
  }
}

# Cross-Account Trust Relationships
output "cross_account_trust_policies" {
  description = "Cross-account trust policies for roles"
  value = {
    for role_name, role_config in var.iam_roles : role_name => {
      assume_role_policy = role_config.assume_role_policy
      role_arn          = aws_iam_role.roles[role_name].arn
    }
  }
  sensitive = true
}

# Compliance and Audit Information
output "compliance_info" {
  description = "Compliance and audit information"
  value = {
    created_resources = {
      timestamp = timestamp()
      environment = var.environment
      project_name = var.project_name
      created_by = "terraform"
    }
    audit_trails = var.enable_cloudtrail ? {
      cloudtrail_arn = one(aws_cloudtrail.iam_audit_trail[*].arn)
      s3_bucket = one(aws_cloudtrail.iam_audit_trail[*].s3_bucket_name)
    } : null
    access_analyzer = var.enable_access_analyzer ? {
      analyzer_arn = one(aws_accessanalyzer_analyzer.iam_analyzer[*].arn)
    } : null
    password_policy_compliant = var.enable_password_policy
  }
}

# Deployment Metadata
output "deployment_metadata" {
  description = "Deployment metadata for tracking and monitoring"
  value = {
    module_version = "1.0.0"
    deployment_timestamp = timestamp()
    environment = var.environment
    project_name = var.project_name
    terraform_version = "~> 1.5.0"
    provider_versions = {
      aws = "~> 5.0"
      random = "~> 3.1"
      time = "~> 0.9"
    }
    resource_counts = {
      users = length(aws_iam_user.users)
      roles = length(aws_iam_role.roles)
      policies = length(aws_iam_policy.custom_policies)
      groups = length(aws_iam_group.groups)
    }
    tags_applied = local.common_tags
  }
}
