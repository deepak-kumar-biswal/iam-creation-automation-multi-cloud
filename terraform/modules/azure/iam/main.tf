# Multi-Cloud IAM Automation - Azure Module
# This module creates and manages IAM resources across Azure subscriptions at scale

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.80"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.44"
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

# Get current client configuration
data "azurerm_client_config" "current" {}

# Get current Azure AD directory
data "azuread_client_config" "current" {}

# Local variables for common configurations
locals {
  common_tags = merge(var.common_tags, {
    Module      = "azure-iam"
    Environment = var.environment
    ManagedBy   = "terraform"
    Project     = var.project_name
    CreatedAt   = formatdate("YYYY-MM-DD", timestamp())
  })
  
  # Naming convention
  resource_prefix = "${var.project_name}-${var.environment}"
  
  # Flatten role assignments
  subscription_role_assignments = flatten([
    for subscription_id, assignments in var.subscription_role_assignments : [
      for assignment in assignments : {
        subscription_id = subscription_id
        principal_id    = assignment.principal_id
        role_definition_name = assignment.role_definition_name
        scope          = "/subscriptions/${subscription_id}"
        key            = "${subscription_id}-${assignment.principal_id}-${assignment.role_definition_name}"
      }
    ]
  ])
  
  resource_group_role_assignments = flatten([
    for rg_id, assignments in var.resource_group_role_assignments : [
      for assignment in assignments : {
        resource_group_id = rg_id
        principal_id      = assignment.principal_id
        role_definition_name = assignment.role_definition_name
        scope            = rg_id
        key              = "${rg_id}-${assignment.principal_id}-${assignment.role_definition_name}"
      }
    ]
  ])
  
  management_group_role_assignments = flatten([
    for mg_id, assignments in var.management_group_role_assignments : [
      for assignment in assignments : {
        management_group_id = mg_id
        principal_id        = assignment.principal_id
        role_definition_name = assignment.role_definition_name
        scope              = mg_id
        key                = "${mg_id}-${assignment.principal_id}-${assignment.role_definition_name}"
      }
    ]
  ])
}

# Azure AD Users
resource "azuread_user" "users" {
  for_each = var.azure_ad_users
  
  user_principal_name = each.value.user_principal_name
  display_name        = each.value.display_name
  password           = each.value.password
  force_password_change = each.value.force_password_change
  
  given_name      = each.value.given_name
  surname         = each.value.surname
  job_title       = each.value.job_title
  department      = each.value.department
  company_name    = each.value.company_name
  office_location = each.value.office_location
  street_address  = each.value.street_address
  city           = each.value.city
  state          = each.value.state
  country        = each.value.country
  postal_code    = each.value.postal_code
  mobile_phone   = each.value.mobile_phone
  mail_nickname  = each.value.mail_nickname
  
  usage_location = each.value.usage_location
  
  lifecycle {
    ignore_changes = [password]
  }
}

# Azure AD Groups
resource "azuread_group" "groups" {
  for_each = var.azure_ad_groups
  
  display_name            = each.value.display_name
  description            = each.value.description
  security_enabled       = each.value.security_enabled
  mail_enabled           = each.value.mail_enabled
  mail_nickname          = each.value.mail_nickname
  assignable_to_role     = each.value.assignable_to_role
  prevent_duplicate_names = true
  
  dynamic "owners" {
    for_each = each.value.owners
    content {
      object_ids = owners.value
    }
  }
  
  dynamic "members" {
    for_each = each.value.members
    content {
      object_ids = members.value
    }
  }
}

# Service Principals (Applications)
resource "azuread_application" "applications" {
  for_each = var.service_principals
  
  display_name            = "${local.resource_prefix}-${each.key}"
  description            = each.value.description
  sign_in_audience       = each.value.sign_in_audience
  owners                 = each.value.owners
  prevent_duplicate_names = true
  
  dynamic "web" {
    for_each = each.value.web != null ? [each.value.web] : []
    content {
      homepage_url  = web.value.homepage_url
      logout_url    = web.value.logout_url
      redirect_uris = web.value.redirect_uris
      
      dynamic "implicit_grant" {
        for_each = web.value.implicit_grant != null ? [web.value.implicit_grant] : []
        content {
          access_token_issuance_enabled = implicit_grant.value.access_token_issuance_enabled
          id_token_issuance_enabled     = implicit_grant.value.id_token_issuance_enabled
        }
      }
    }
  }
  
  dynamic "api" {
    for_each = each.value.api != null ? [each.value.api] : []
    content {
      mapped_claims_enabled          = api.value.mapped_claims_enabled
      requested_access_token_version = api.value.requested_access_token_version
      known_client_applications      = api.value.known_client_applications
      
      dynamic "oauth2_permission_scope" {
        for_each = api.value.oauth2_permission_scopes
        content {
          admin_consent_description  = oauth2_permission_scope.value.admin_consent_description
          admin_consent_display_name = oauth2_permission_scope.value.admin_consent_display_name
          enabled                   = oauth2_permission_scope.value.enabled
          id                        = oauth2_permission_scope.value.id
          type                      = oauth2_permission_scope.value.type
          user_consent_description  = oauth2_permission_scope.value.user_consent_description
          user_consent_display_name = oauth2_permission_scope.value.user_consent_display_name
          value                     = oauth2_permission_scope.value.value
        }
      }
    }
  }
  
  dynamic "app_role" {
    for_each = each.value.app_roles
    content {
      allowed_member_types = app_role.value.allowed_member_types
      description         = app_role.value.description
      display_name        = app_role.value.display_name
      enabled            = app_role.value.enabled
      id                 = app_role.value.id
      value              = app_role.value.value
    }
  }
  
  dynamic "required_resource_access" {
    for_each = each.value.required_resource_access
    content {
      resource_app_id = required_resource_access.value.resource_app_id
      
      dynamic "resource_access" {
        for_each = required_resource_access.value.resource_access
        content {
          id   = resource_access.value.id
          type = resource_access.value.type
        }
      }
    }
  }
  
  tags = [for k, v in local.common_tags : "${k}:${v}"]
}

resource "azuread_service_principal" "service_principals" {
  for_each = var.service_principals
  
  application_id               = azuread_application.applications[each.key].application_id
  app_role_assignment_required = each.value.app_role_assignment_required
  owners                      = each.value.owners
  
  dynamic "saml_single_sign_on" {
    for_each = each.value.saml_single_sign_on != null ? [each.value.saml_single_sign_on] : []
    content {
      relay_state = saml_single_sign_on.value.relay_state
    }
  }
  
  tags = [for k, v in local.common_tags : "${k}:${v}"]
}

# Service Principal Passwords
resource "azuread_service_principal_password" "sp_passwords" {
  for_each = {
    for sp_name, sp_config in var.service_principals : sp_name => sp_config
    if sp_config.create_password
  }
  
  service_principal_id = azuread_service_principal.service_principals[each.key].object_id
  display_name         = "terraform-managed"
  
  lifecycle {
    create_before_destroy = true
  }
}

# Service Principal Certificates
resource "azuread_service_principal_certificate" "sp_certificates" {
  for_each = {
    for sp_name, sp_config in var.service_principals : sp_name => sp_config
    if sp_config.certificate_value != null
  }
  
  service_principal_id = azuread_service_principal.service_principals[each.key].object_id
  type                = each.value.certificate_type
  value               = each.value.certificate_value
  end_date            = each.value.certificate_end_date
}

# Custom Role Definitions
resource "azurerm_role_definition" "custom_roles" {
  for_each = var.custom_roles
  
  name        = "${local.resource_prefix}-${each.key}"
  scope       = each.value.scope
  description = each.value.description
  
  permissions {
    actions          = each.value.permissions.actions
    not_actions      = each.value.permissions.not_actions
    data_actions     = each.value.permissions.data_actions
    not_data_actions = each.value.permissions.not_data_actions
  }
  
  assignable_scopes = each.value.assignable_scopes
}

# Subscription Role Assignments
resource "azurerm_role_assignment" "subscription_assignments" {
  for_each = {
    for assignment in local.subscription_role_assignments : assignment.key => assignment
  }
  
  scope                = each.value.scope
  role_definition_name = each.value.role_definition_name
  principal_id         = each.value.principal_id
}

# Resource Group Role Assignments
resource "azurerm_role_assignment" "resource_group_assignments" {
  for_each = {
    for assignment in local.resource_group_role_assignments : assignment.key => assignment
  }
  
  scope                = each.value.scope
  role_definition_name = each.value.role_definition_name
  principal_id         = each.value.principal_id
}

# Management Group Role Assignments
resource "azurerm_role_assignment" "management_group_assignments" {
  for_each = {
    for assignment in local.management_group_role_assignments : assignment.key => assignment
  }
  
  scope                = each.value.scope
  role_definition_name = each.value.role_definition_name
  principal_id         = each.value.principal_id
}

# Key Vault for storing secrets
resource "azurerm_resource_group" "kv_rg" {
  count = var.enable_key_vault ? 1 : 0
  
  name     = "${local.resource_prefix}-keyvault-rg"
  location = var.key_vault_location
  tags     = local.common_tags
}

resource "azurerm_key_vault" "main" {
  count = var.enable_key_vault ? 1 : 0
  
  name                = "${replace(local.resource_prefix, "-", "")}kv${random_string.kv_suffix[0].result}"
  location            = azurerm_resource_group.kv_rg[0].location
  resource_group_name = azurerm_resource_group.kv_rg[0].name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  
  sku_name = "standard"
  
  enabled_for_deployment          = true
  enabled_for_disk_encryption     = true
  enabled_for_template_deployment = true
  purge_protection_enabled        = var.enable_purge_protection
  soft_delete_retention_days      = var.soft_delete_retention_days
  
  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id
    
    secret_permissions = [
      "Get", "List", "Set", "Delete", "Purge", "Recover"
    ]
  }
  
  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
    ip_rules       = var.key_vault_ip_rules
    virtual_network_subnet_ids = var.key_vault_subnet_ids
  }
  
  tags = local.common_tags
}

resource "random_string" "kv_suffix" {
  count = var.enable_key_vault ? 1 : 0
  
  length  = 4
  special = false
  upper   = false
}

# Store Service Principal secrets in Key Vault
resource "azurerm_key_vault_secret" "sp_passwords" {
  for_each = {
    for sp_name, password in azuread_service_principal_password.sp_passwords : sp_name => password
    if var.enable_key_vault
  }
  
  name         = "${each.key}-password"
  value        = each.value.value
  key_vault_id = azurerm_key_vault.main[0].id
  
  tags = merge(local.common_tags, {
    ServicePrincipal = each.key
    SecretType      = "Password"
  })
  
  depends_on = [azurerm_key_vault.main]
}

# Managed Identity
resource "azurerm_user_assigned_identity" "managed_identities" {
  for_each = var.managed_identities
  
  name                = "${local.resource_prefix}-${each.key}"
  resource_group_name = each.value.resource_group_name
  location           = each.value.location
  
  tags = merge(local.common_tags, each.value.tags)
}

# Conditional Access Policies
resource "azuread_conditional_access_policy" "conditional_access_policies" {
  for_each = var.conditional_access_policies
  
  display_name = "${local.resource_prefix}-${each.key}"
  state       = each.value.state
  
  conditions {
    client_app_types    = each.value.conditions.client_app_types
    sign_in_risk_levels = each.value.conditions.sign_in_risk_levels
    user_risk_levels    = each.value.conditions.user_risk_levels
    
    applications {
      included_applications = each.value.conditions.applications.included_applications
      excluded_applications = each.value.conditions.applications.excluded_applications
    }
    
    users {
      included_users  = each.value.conditions.users.included_users
      excluded_users  = each.value.conditions.users.excluded_users
      included_groups = each.value.conditions.users.included_groups
      excluded_groups = each.value.conditions.users.excluded_groups
      included_roles  = each.value.conditions.users.included_roles
      excluded_roles  = each.value.conditions.users.excluded_roles
    }
    
    dynamic "locations" {
      for_each = each.value.conditions.locations != null ? [each.value.conditions.locations] : []
      content {
        included_locations = locations.value.included_locations
        excluded_locations = locations.value.excluded_locations
      }
    }
    
    dynamic "platforms" {
      for_each = each.value.conditions.platforms != null ? [each.value.conditions.platforms] : []
      content {
        included_platforms = platforms.value.included_platforms
        excluded_platforms = platforms.value.excluded_platforms
      }
    }
  }
  
  grant_controls {
    operator          = each.value.grant_controls.operator
    built_in_controls = each.value.grant_controls.built_in_controls
    
    dynamic "authentication_strength" {
      for_each = each.value.grant_controls.authentication_strength != null ? [each.value.grant_controls.authentication_strength] : []
      content {
        id = authentication_strength.value.id
      }
    }
  }
  
  dynamic "session_controls" {
    for_each = each.value.session_controls != null ? [each.value.session_controls] : []
    content {
      application_enforced_restrictions_enabled = session_controls.value.application_enforced_restrictions_enabled
      cloud_app_security_policy               = session_controls.value.cloud_app_security_policy
      sign_in_frequency                       = session_controls.value.sign_in_frequency
      sign_in_frequency_period               = session_controls.value.sign_in_frequency_period
      sign_in_frequency_authentication_type   = session_controls.value.sign_in_frequency_authentication_type
      persistent_browser_mode                = session_controls.value.persistent_browser_mode
    }
  }
}

# Named Locations for Conditional Access
resource "azuread_named_location" "named_locations" {
  for_each = var.named_locations
  
  display_name = "${local.resource_prefix}-${each.key}"
  
  dynamic "ip" {
    for_each = each.value.ip != null ? [each.value.ip] : []
    content {
      ip_ranges = ip.value.ip_ranges
      trusted   = ip.value.trusted
    }
  }
  
  dynamic "country" {
    for_each = each.value.country != null ? [each.value.country] : []
    content {
      countries_and_regions                 = country.value.countries_and_regions
      include_unknown_countries_and_regions = country.value.include_unknown_countries_and_regions
    }
  }
}

# Identity Protection Risk Policies
resource "azuread_identity_protection_policy" "user_risk_policy" {
  count = var.enable_identity_protection ? 1 : 0
  
  type  = "userRiskPolicy"
  state = var.identity_protection_config.user_risk_policy_state
  
  user_risk_levels = var.identity_protection_config.user_risk_levels
  
  grant_controls {
    operator          = "OR"
    built_in_controls = ["passwordChange"]
  }
  
  users {
    included_users  = []
    excluded_users  = var.identity_protection_config.excluded_users
    included_groups = []
    excluded_groups = var.identity_protection_config.excluded_groups
    included_roles  = []
    excluded_roles  = []
  }
}

resource "azuread_identity_protection_policy" "sign_in_risk_policy" {
  count = var.enable_identity_protection ? 1 : 0
  
  type  = "signInRiskPolicy"
  state = var.identity_protection_config.sign_in_risk_policy_state
  
  sign_in_risk_levels = var.identity_protection_config.sign_in_risk_levels
  
  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
  }
  
  users {
    included_users  = []
    excluded_users  = var.identity_protection_config.excluded_users
    included_groups = []
    excluded_groups = var.identity_protection_config.excluded_groups
    included_roles  = []
    excluded_roles  = []
  }
}

# Privileged Identity Management (PIM) Settings
resource "azuread_privileged_access_group_assignment_schedule" "pim_assignments" {
  for_each = var.pim_assignments
  
  assignment_type         = each.value.assignment_type
  group_id               = each.value.group_id
  principal_id           = each.value.principal_id
  start_date             = each.value.start_date
  expiration_date        = each.value.expiration_date
  permanent_assignment   = each.value.permanent_assignment
  
  dynamic "ticket" {
    for_each = each.value.ticket != null ? [each.value.ticket] : []
    content {
      number = ticket.value.number
      system = ticket.value.system
    }
  }
  
  justification = each.value.justification
}

# Azure Policy Assignments
resource "azurerm_policy_assignment" "policy_assignments" {
  for_each = var.policy_assignments
  
  name                 = "${local.resource_prefix}-${each.key}"
  scope               = each.value.scope
  policy_definition_id = each.value.policy_definition_id
  description         = each.value.description
  display_name        = each.value.display_name
  location            = each.value.location
  identity            = each.value.identity
  
  dynamic "non_compliance_message" {
    for_each = each.value.non_compliance_messages
    content {
      content                        = non_compliance_message.value.content
      policy_definition_reference_id = non_compliance_message.value.policy_definition_reference_id
    }
  }
  
  parameters = jsonencode(each.value.parameters)
  
  metadata = jsonencode(merge(local.common_tags, {
    category = "Security"
  }))
}

# Monitor Activity Log Alerts
resource "azurerm_monitor_activity_log_alert" "activity_log_alerts" {
  for_each = var.activity_log_alerts
  
  name                = "${local.resource_prefix}-${each.key}"
  resource_group_name = each.value.resource_group_name
  scopes             = each.value.scopes
  description        = each.value.description
  enabled            = each.value.enabled
  
  criteria {
    category    = each.value.criteria.category
    operation_name = each.value.criteria.operation_name
    resource_provider = each.value.criteria.resource_provider
    resource_type = each.value.criteria.resource_type
    resource_group = each.value.criteria.resource_group
    resource_id = each.value.criteria.resource_id
    caller = each.value.criteria.caller
    level = each.value.criteria.level
    status = each.value.criteria.status
    sub_status = each.value.criteria.sub_status
  }
  
  dynamic "action" {
    for_each = each.value.actions
    content {
      action_group_id    = action.value.action_group_id
      webhook_properties = action.value.webhook_properties
    }
  }
  
  tags = local.common_tags
}
