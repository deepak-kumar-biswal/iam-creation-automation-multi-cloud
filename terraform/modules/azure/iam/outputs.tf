# Azure IAM Module Outputs
# Production-grade outputs for Azure Active Directory and RBAC resources

# Azure AD Users Outputs
output "azure_ad_users" {
  description = "Information about created Azure AD users"
  value = {
    for user_key, user in azuread_user.users : user_key => {
      id                    = user.id
      object_id            = user.object_id
      user_principal_name  = user.user_principal_name
      display_name         = user.display_name
      mail                 = user.mail
      account_enabled      = user.account_enabled
      creation_type        = user.creation_type
      external_user_state  = user.external_user_state
      onpremises_sam_account_name = user.onpremises_sam_account_name
      onpremises_user_principal_name = user.onpremises_user_principal_name
      proxy_addresses      = user.proxy_addresses
    }
  }
  sensitive = false
}

output "azure_ad_user_ids" {
  description = "Map of user keys to their Azure AD object IDs"
  value = {
    for user_key, user in azuread_user.users : user_key => user.object_id
  }
  sensitive = false
}

output "azure_ad_user_upns" {
  description = "Map of user keys to their User Principal Names"
  value = {
    for user_key, user in azuread_user.users : user_key => user.user_principal_name
  }
  sensitive = false
}

# Azure AD Groups Outputs
output "azure_ad_groups" {
  description = "Information about created Azure AD groups"
  value = {
    for group_key, group in azuread_group.groups : group_key => {
      id                   = group.id
      object_id           = group.object_id
      display_name        = group.display_name
      description         = group.description
      mail_enabled        = group.mail_enabled
      security_enabled    = group.security_enabled
      mail_nickname       = group.mail_nickname
      mail                = group.mail
      assignable_to_role  = group.assignable_to_role
      onpremises_group_type = group.onpremises_group_type
      onpremises_sam_account_name = group.onpremises_sam_account_name
      proxy_addresses     = group.proxy_addresses
      visibility          = group.visibility
    }
  }
  sensitive = false
}

output "azure_ad_group_ids" {
  description = "Map of group keys to their Azure AD object IDs"
  value = {
    for group_key, group in azuread_group.groups : group_key => group.object_id
  }
  sensitive = false
}

output "azure_ad_group_names" {
  description = "Map of group keys to their display names"
  value = {
    for group_key, group in azuread_group.groups : group_key => group.display_name
  }
  sensitive = false
}

# Service Principals Outputs
output "service_principals" {
  description = "Information about created service principals"
  value = {
    for sp_key, sp in azuread_service_principal.service_principals : sp_key => {
      id                    = sp.id
      object_id            = sp.object_id
      application_id       = sp.application_id
      display_name         = sp.display_name
      alternative_names    = sp.alternative_names
      application_tenant_id = sp.application_tenant_id
      app_role_assignment_required = sp.app_role_assignment_required
      homepage_url         = sp.homepage_url
      login_url           = sp.login_url
      logout_url          = sp.logout_url
      notes               = sp.notes
      notification_email_addresses = sp.notification_email_addresses
      preferred_single_sign_on_mode = sp.preferred_single_sign_on_mode
      sign_in_audience    = sp.sign_in_audience
      type                = sp.type
    }
  }
  sensitive = false
}

output "service_principal_ids" {
  description = "Map of service principal keys to their object IDs"
  value = {
    for sp_key, sp in azuread_service_principal.service_principals : sp_key => sp.object_id
  }
  sensitive = false
}

output "service_principal_application_ids" {
  description = "Map of service principal keys to their application IDs"
  value = {
    for sp_key, sp in azuread_service_principal.service_principals : sp_key => sp.application_id
  }
  sensitive = false
}

# Application Registrations Outputs
output "application_registrations" {
  description = "Information about created application registrations"
  value = {
    for app_key, app in azuread_application.applications : app_key => {
      id               = app.id
      object_id       = app.object_id
      application_id  = app.application_id
      display_name    = app.display_name
      description     = app.description
      sign_in_audience = app.sign_in_audience
      identifier_uris = app.identifier_uris
      publisher_domain = app.publisher_domain
      disabled_by_microsoft = app.disabled_by_microsoft
    }
  }
  sensitive = false
}

output "application_ids" {
  description = "Map of application keys to their application IDs"
  value = {
    for app_key, app in azuread_application.applications : app_key => app.application_id
  }
  sensitive = false
}

# Custom Roles Outputs
output "custom_roles" {
  description = "Information about created custom RBAC roles"
  value = {
    for role_key, role in azurerm_role_definition.custom_roles : role_key => {
      id                = role.id
      role_definition_id = role.role_definition_id
      name              = role.name
      description       = role.description
      scope             = role.scope
      assignable_scopes = role.assignable_scopes
      permissions       = role.permissions
    }
  }
  sensitive = false
}

output "custom_role_ids" {
  description = "Map of custom role keys to their role definition IDs"
  value = {
    for role_key, role in azurerm_role_definition.custom_roles : role_key => role.role_definition_id
  }
  sensitive = false
}

# Role Assignments Outputs
output "role_assignments" {
  description = "Information about created role assignments"
  value = {
    for assignment_key, assignment in azurerm_role_assignment.role_assignments : assignment_key => {
      id                   = assignment.id
      scope               = assignment.scope
      role_definition_id  = assignment.role_definition_id
      role_definition_name = assignment.role_definition_name
      principal_id        = assignment.principal_id
      principal_type      = assignment.principal_type
      condition           = assignment.condition
      condition_version   = assignment.condition_version
    }
  }
  sensitive = false
}

output "role_assignment_ids" {
  description = "Map of role assignment keys to their IDs"
  value = {
    for assignment_key, assignment in azurerm_role_assignment.role_assignments : assignment_key => assignment.id
  }
  sensitive = false
}

# Administrative Units Outputs
output "administrative_units" {
  description = "Information about created administrative units"
  value = {
    for au_key, au in azuread_administrative_unit.admin_units : au_key => {
      id           = au.id
      object_id    = au.object_id
      display_name = au.display_name
      description  = au.description
      visibility   = au.visibility
    }
  }
  sensitive = false
}

output "administrative_unit_ids" {
  description = "Map of administrative unit keys to their object IDs"
  value = {
    for au_key, au in azuread_administrative_unit.admin_units : au_key => au.object_id
  }
  sensitive = false
}

# Conditional Access Policies Outputs
output "conditional_access_policies" {
  description = "Information about created conditional access policies"
  value = {
    for policy_key, policy in azuread_conditional_access_policy.policies : policy_key => {
      id           = policy.id
      object_id    = policy.object_id
      display_name = policy.display_name
      state        = policy.state
    }
  }
  sensitive = false
}

output "conditional_access_policy_ids" {
  description = "Map of conditional access policy keys to their object IDs"
  value = {
    for policy_key, policy in azuread_conditional_access_policy.policies : policy_key => policy.object_id
  }
  sensitive = false
}

# PIM Eligible Assignments Outputs
output "pim_eligible_assignments" {
  description = "Information about created PIM eligible role assignments"
  value = {
    for assignment_key, assignment in azurerm_pim_eligible_role_assignment.pim_assignments : assignment_key => {
      id                 = assignment.id
      scope             = assignment.scope
      role_definition_id = assignment.role_definition_id
      principal_id      = assignment.principal_id
    }
  }
  sensitive = false
}

output "pim_eligible_assignment_ids" {
  description = "Map of PIM eligible assignment keys to their IDs"
  value = {
    for assignment_key, assignment in azurerm_pim_eligible_role_assignment.pim_assignments : assignment_key => assignment.id
  }
  sensitive = false
}

# Azure Policy Outputs
output "azure_policies" {
  description = "Information about created Azure Policy assignments"
  value = {
    for policy_key, policy in azurerm_policy_assignment.policies : policy_key => {
      id                   = policy.id
      name                = policy.name
      display_name        = policy.display_name
      description         = policy.description
      policy_definition_id = policy.policy_definition_id
      scope               = policy.scope
      enforcement_mode    = policy.enforcement_mode
      location            = policy.location
    }
  }
  sensitive = false
}

output "azure_policy_ids" {
  description = "Map of Azure Policy keys to their assignment IDs"
  value = {
    for policy_key, policy in azurerm_policy_assignment.policies : policy_key => policy.id
  }
  sensitive = false
}

# Security and Compliance Outputs
output "security_configuration" {
  description = "Summary of security configuration applied"
  value = {
    security_defaults_enabled        = var.security_defaults_enabled
    conditional_access_enabled       = var.enable_conditional_access
    pim_enabled                     = var.enable_privileged_identity_management
    identity_protection_enabled     = var.enable_identity_protection
    audit_logs_enabled              = var.enable_audit_logs
    password_policy_configured      = var.password_policy != null
    compliance_frameworks           = var.compliance_frameworks
    data_classification            = var.data_classification
  }
  sensitive = false
}

# Resource Counts
output "resource_counts" {
  description = "Count of created resources by type"
  value = {
    azure_ad_users               = length(azuread_user.users)
    azure_ad_groups             = length(azuread_group.groups)
    service_principals          = length(azuread_service_principal.service_principals)
    application_registrations   = length(azuread_application.applications)
    custom_roles               = length(azurerm_role_definition.custom_roles)
    role_assignments           = length(azurerm_role_assignment.role_assignments)
    administrative_units       = length(azuread_administrative_unit.admin_units)
    conditional_access_policies = length(azuread_conditional_access_policy.policies)
    pim_eligible_assignments   = length(azurerm_pim_eligible_role_assignment.pim_assignments)
    azure_policy_assignments  = length(azurerm_policy_assignment.policies)
  }
  sensitive = false
}

# Tenant Information
output "tenant_information" {
  description = "Azure AD tenant information"
  value = {
    tenant_id = var.tenant_id
    region    = var.region
    environment = var.environment
    subscription_count = length(var.subscription_ids)
  }
  sensitive = false
}

# Group Memberships Summary
output "group_memberships" {
  description = "Summary of group memberships"
  value = {
    for group_key, group in azuread_group.groups : group_key => {
      display_name = group.display_name
      member_count = length(data.azuread_group.existing_groups[group_key].members)
      owner_count  = length(data.azuread_group.existing_groups[group_key].owners)
    }
  }
  sensitive = false
}

# Service Principal Credentials Summary (Non-sensitive)
output "service_principal_credentials_summary" {
  description = "Summary of service principal credentials (non-sensitive)"
  value = {
    for sp_key, sp_config in var.service_principals : sp_key => {
      display_name            = sp_config.display_name
      certificate_count       = length(sp_config.certificate_credentials)
      password_count         = length(sp_config.password_credentials)
      has_api_permissions    = length(sp_config.required_resource_accesses) > 0
    }
  }
  sensitive = false
}

# Role Assignment Summary
output "role_assignment_summary" {
  description = "Summary of role assignments by principal type and role"
  value = {
    by_principal_type = {
      for assignment_key, assignment in var.role_assignments : assignment.principal_type => length([
        for k, v in var.role_assignments : k if v.principal_type == assignment.principal_type
      ])...
    }
    by_scope = {
      for assignment_key, assignment in var.role_assignments : assignment.scope => length([
        for k, v in var.role_assignments : k if v.scope == assignment.scope
      ])...
    }
  }
  sensitive = false
}

# Compliance Status
output "compliance_status" {
  description = "Compliance status and configuration"
  value = {
    enabled_frameworks = var.compliance_frameworks
    data_residency = {
      allowed_regions    = var.data_residency_requirements.allowed_regions
      data_sovereignty   = var.data_residency_requirements.data_sovereignty
    }
    backup_enabled = var.backup_configuration.enabled
    audit_retention_days = var.diagnostic_settings.retention_days
    password_policy_strength = {
      minimum_length = var.password_policy.minimum_length
      complexity_requirements = var.password_policy.require_uppercase && var.password_policy.require_lowercase && var.password_policy.require_numbers && var.password_policy.require_special_characters
      history_count = var.password_policy.password_history_count
      max_age_days = var.password_policy.password_age_days
    }
  }
  sensitive = false
}

# Feature Flags Status
output "feature_flags" {
  description = "Status of enabled feature flags"
  value = {
    privileged_identity_management = var.enable_privileged_identity_management
    conditional_access            = var.enable_conditional_access
    identity_protection           = var.enable_identity_protection
    application_proxy            = var.enable_application_proxy
    audit_logs                   = var.enable_audit_logs
  }
  sensitive = false
}

# Diagnostic Information
output "diagnostic_configuration" {
  description = "Diagnostic and monitoring configuration"
  value = {
    log_analytics_enabled = var.log_analytics_workspace_id != null
    diagnostic_settings = {
      name = var.diagnostic_settings.name
      enabled_log_categories = var.diagnostic_settings.enabled_log_categories
      metric_categories = var.diagnostic_settings.metric_categories
      retention_days = var.diagnostic_settings.retention_days
    }
  }
  sensitive = false
}

# Cost and Resource Management
output "resource_tagging" {
  description = "Applied resource tagging configuration"
  value = {
    default_tags = var.default_tags
    cost_center = var.cost_center
    data_classification = var.data_classification
    environment = var.environment
  }
  sensitive = false
}

# Security Recommendations
output "security_recommendations" {
  description = "Security recommendations based on current configuration"
  value = {
    missing_configurations = [
      for item in [
        var.enable_conditional_access ? null : "Enable Conditional Access",
        var.enable_privileged_identity_management ? null : "Enable PIM",
        var.enable_identity_protection ? null : "Enable Identity Protection",
        var.log_analytics_workspace_id != null ? null : "Configure Log Analytics",
        length(var.compliance_frameworks) > 0 ? null : "Define Compliance Frameworks"
      ] : item if item != null
    ]
    
    security_score = (
      (var.enable_conditional_access ? 20 : 0) +
      (var.enable_privileged_identity_management ? 20 : 0) +
      (var.enable_identity_protection ? 20 : 0) +
      (var.security_defaults_enabled ? 15 : 0) +
      (var.enable_audit_logs ? 15 : 0) +
      (var.log_analytics_workspace_id != null ? 10 : 0)
    )
  }
  sensitive = false
}

# Export for External Systems
output "terraform_state_summary" {
  description = "Summary for external systems and state management"
  value = {
    module_version = "1.0.0"
    last_applied = timestamp()
    resource_types = [
      "azuread_user",
      "azuread_group", 
      "azuread_service_principal",
      "azuread_application",
      "azurerm_role_definition",
      "azurerm_role_assignment",
      "azuread_administrative_unit",
      "azuread_conditional_access_policy",
      "azurerm_pim_eligible_role_assignment",
      "azurerm_policy_assignment"
    ]
    total_resources = (
      length(azuread_user.users) +
      length(azuread_group.groups) +
      length(azuread_service_principal.service_principals) +
      length(azuread_application.applications) +
      length(azurerm_role_definition.custom_roles) +
      length(azurerm_role_assignment.role_assignments) +
      length(azuread_administrative_unit.admin_units) +
      length(azuread_conditional_access_policy.policies) +
      length(azurerm_pim_eligible_role_assignment.pim_assignments) +
      length(azurerm_policy_assignment.policies)
    )
  }
  sensitive = false
}
