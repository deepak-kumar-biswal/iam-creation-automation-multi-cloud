# Azure IAM Module Variables
# Production-grade variable definitions for Azure Active Directory and RBAC

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.0"
    }
  }
}

# Subscription and Tenant Configuration
variable "tenant_id" {
  description = "Azure AD tenant ID"
  type        = string
  validation {
    condition     = can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", var.tenant_id))
    error_message = "Tenant ID must be a valid GUID format."
  }
}

variable "subscription_ids" {
  description = "List of Azure subscription IDs to manage"
  type        = list(string)
  default     = []
  validation {
    condition = alltrue([
      for id in var.subscription_ids : can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", id))
    ])
    error_message = "All subscription IDs must be valid GUID format."
  }
}

variable "management_group_id" {
  description = "Azure Management Group ID for organizational structure"
  type        = string
  default     = null
}

# Azure AD Users Configuration
variable "azure_ad_users" {
  description = "Configuration for Azure AD users"
  type = map(object({
    user_principal_name = string
    display_name        = string
    mail_nickname      = optional(string)
    password           = optional(string)
    force_password_change = optional(bool, true)
    
    # User attributes
    given_name          = optional(string)
    surname            = optional(string)
    job_title          = optional(string)
    department         = optional(string)
    company_name       = optional(string)
    office_location    = optional(string)
    mobile_phone       = optional(string)
    business_phones    = optional(list(string), [])
    
    # Security settings
    account_enabled                = optional(bool, true)
    password_never_expires         = optional(bool, false)
    password_expire_days          = optional(number, 90)
    show_in_address_list          = optional(bool, true)
    disable_password_expiration   = optional(bool, false)
    disable_strong_password       = optional(bool, false)
    
    # MFA settings
    mfa_enabled                   = optional(bool, true)
    privileged_authentication    = optional(bool, false)
    
    # Assignment settings
    groups                        = optional(list(string), [])
    roles                        = optional(list(string), [])
    administrative_units         = optional(list(string), [])
    
    # License assignments
    licenses                     = optional(list(string), [])
    
    tags = optional(map(string), {})
  }))
  default = {}
  
  validation {
    condition = alltrue([
      for user_key, user in var.azure_ad_users : 
      can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", user.user_principal_name))
    ])
    error_message = "All user_principal_name values must be valid email addresses."
  }
}

# Azure AD Groups Configuration
variable "azure_ad_groups" {
  description = "Configuration for Azure AD groups"
  type = map(object({
    display_name      = string
    description       = optional(string)
    mail_enabled      = optional(bool, false)
    security_enabled  = optional(bool, true)
    mail_nickname     = optional(string)
    
    # Group types
    group_types       = optional(list(string), [])
    
    # Membership settings
    members           = optional(list(string), [])
    owners            = optional(list(string), [])
    
    # Dynamic membership
    dynamic_membership = optional(object({
      enabled = bool
      rule    = string
    }))
    
    # Assignment settings
    assignable_to_role = optional(bool, false)
    roles             = optional(list(string), [])
    
    # Lifecycle settings
    expiration_policy = optional(object({
      alternate_notification_emails = optional(list(string), [])
      group_lifetime_in_days        = optional(number, 365)
      notification_before_expiry    = optional(number, 30)
    }))
    
    tags = optional(map(string), {})
  }))
  default = {}
}

# Service Principals Configuration
variable "service_principals" {
  description = "Configuration for Azure AD service principals (applications)"
  type = map(object({
    display_name    = string
    description     = optional(string)
    
    # Application settings
    sign_in_audience           = optional(string, "AzureADMyOrg")
    identifier_uris           = optional(list(string), [])
    homepage_url              = optional(string)
    logout_url                = optional(string)
    privacy_statement_url     = optional(string)
    support_url               = optional(string)
    terms_of_service_url      = optional(string)
    
    # Authentication settings
    certificate_credentials = optional(list(object({
      display_name  = string
      type         = string
      value        = string
      end_date     = optional(string)
      start_date   = optional(string)
    })), [])
    
    password_credentials = optional(list(object({
      display_name = string
      end_date     = optional(string)
      start_date   = optional(string)
    })), [])
    
    # API permissions
    required_resource_accesses = optional(list(object({
      resource_app_id = string
      resource_accesses = list(object({
        id   = string
        type = string
      }))
    })), [])
    
    # OAuth2 settings
    oauth2_permissions = optional(list(object({
      admin_consent_description  = string
      admin_consent_display_name = string
      is_enabled                = bool
      type                      = string
      user_consent_description  = optional(string)
      user_consent_display_name = optional(string)
      value                     = string
    })), [])
    
    # Role assignments
    roles = optional(list(string), [])
    
    # Security settings
    account_enabled = optional(bool, true)
    
    tags = optional(map(string), {})
  }))
  default = {}
}

# Custom Role Definitions
variable "custom_roles" {
  description = "Configuration for custom Azure RBAC roles"
  type = map(object({
    name              = string
    description       = optional(string)
    scope             = string
    
    permissions = list(object({
      actions           = list(string)
      not_actions      = optional(list(string), [])
      data_actions     = optional(list(string), [])
      not_data_actions = optional(list(string), [])
    }))
    
    assignable_scopes = list(string)
    
    tags = optional(map(string), {})
  }))
  default = {}
}

# Role Assignments Configuration
variable "role_assignments" {
  description = "Configuration for Azure RBAC role assignments"
  type = map(object({
    scope              = string
    role_definition_id = optional(string)
    role_definition_name = optional(string)
    principal_id       = string
    principal_type     = optional(string, "User")
    
    # Conditional access
    condition          = optional(string)
    condition_version  = optional(string, "2.0")
    
    # Delegation settings
    delegated_managed_identity_resource_id = optional(string)
    
    tags = optional(map(string), {})
  }))
  default = {}
  
  validation {
    condition = alltrue([
      for assignment_key, assignment in var.role_assignments : 
      (assignment.role_definition_id != null) != (assignment.role_definition_name != null)
    ])
    error_message = "Either role_definition_id or role_definition_name must be specified, but not both."
  }
}

# Administrative Units Configuration
variable "administrative_units" {
  description = "Configuration for Azure AD administrative units"
  type = map(object({
    display_name   = string
    description    = optional(string)
    visibility     = optional(string, "Public")
    
    # Membership settings
    members        = optional(list(string), [])
    scoped_members = optional(list(object({
      id   = string
      type = string
      role = string
    })), [])
    
    tags = optional(map(string), {})
  }))
  default = {}
}

# Conditional Access Policies
variable "conditional_access_policies" {
  description = "Configuration for Azure AD conditional access policies"
  type = map(object({
    display_name = string
    state        = optional(string, "enabled")
    
    conditions = object({
      client_app_types    = optional(list(string), ["all"])
      sign_in_risk_levels = optional(list(string), [])
      user_risk_levels    = optional(list(string), [])
      
      applications = optional(object({
        included_applications = optional(list(string), ["All"])
        excluded_applications = optional(list(string), [])
        included_user_actions = optional(list(string), [])
      }))
      
      users = optional(object({
        included_users  = optional(list(string), [])
        excluded_users  = optional(list(string), [])
        included_groups = optional(list(string), [])
        excluded_groups = optional(list(string), [])
        included_roles  = optional(list(string), [])
        excluded_roles  = optional(list(string), [])
      }))
      
      platforms = optional(object({
        included_platforms = optional(list(string), [])
        excluded_platforms = optional(list(string), [])
      }))
      
      locations = optional(object({
        included_locations = optional(list(string), [])
        excluded_locations = optional(list(string), [])
      }))
      
      devices = optional(object({
        included_devices = optional(list(string), [])
        excluded_devices = optional(list(string), [])
      }))
    })
    
    grant_controls = optional(object({
      operator                     = optional(string, "OR")
      built_in_controls           = optional(list(string), [])
      custom_authentication_factors = optional(list(string), [])
      terms_of_use                = optional(list(string), [])
    }))
    
    session_controls = optional(object({
      application_enforced_restrictions = optional(object({
        is_enabled = bool
      }))
      cloud_app_security = optional(object({
        cloud_app_security_type = string
        is_enabled             = bool
      }))
      persistent_browser = optional(object({
        is_enabled = bool
        mode       = optional(string)
      }))
      sign_in_frequency = optional(object({
        is_enabled = bool
        type       = optional(string)
        value      = optional(number)
      }))
    }))
    
    tags = optional(map(string), {})
  }))
  default = {}
}

# Azure Policy Configuration
variable "azure_policies" {
  description = "Configuration for Azure Policy assignments"
  type = map(object({
    name                 = string
    policy_definition_id = string
    scope               = string
    description         = optional(string)
    display_name        = optional(string)
    
    enforcement_mode = optional(string, "Default")
    not_scopes      = optional(list(string), [])
    
    parameters = optional(string)
    
    identity = optional(object({
      type = string
      identity_ids = optional(list(string))
    }))
    
    location = optional(string)
    
    non_compliance_message = optional(list(object({
      content                        = string
      policy_definition_reference_id = optional(string)
    })), [])
    
    tags = optional(map(string), {})
  }))
  default = {}
}

# Privileged Identity Management (PIM) Configuration
variable "pim_eligible_assignments" {
  description = "Configuration for PIM eligible role assignments"
  type = map(object({
    principal_id         = string
    role_definition_id   = string
    scope               = string
    
    schedule = optional(object({
      start_date_time = optional(string)
      expiration = optional(object({
        duration_days     = optional(number)
        duration_hours    = optional(number)
        end_date_time    = optional(string)
        type             = optional(string, "AfterDuration")
      }))
    }))
    
    justification = optional(string)
    ticket_info = optional(object({
      ticket_number = string
      ticket_system = string
    }))
    
    tags = optional(map(string), {})
  }))
  default = {}
}

# Application Registrations
variable "application_registrations" {
  description = "Configuration for Azure AD application registrations"
  type = map(object({
    display_name     = string
    description      = optional(string)
    sign_in_audience = optional(string, "AzureADMyOrg")
    
    # Web application settings
    web = optional(object({
      homepage_url                = optional(string)
      logout_url                 = optional(string)
      redirect_uris              = optional(list(string), [])
      implicit_grant = optional(object({
        access_token_issuance_enabled = optional(bool, false)
        id_token_issuance_enabled    = optional(bool, false)
      }))
    }))
    
    # Single page application settings
    single_page_application = optional(object({
      redirect_uris = optional(list(string), [])
    }))
    
    # Public client settings
    public_client = optional(object({
      redirect_uris = optional(list(string), [])
    }))
    
    # API settings
    api = optional(object({
      known_client_applications      = optional(list(string), [])
      mapped_claims_enabled         = optional(bool, false)
      requested_access_token_version = optional(number, 2)
      
      oauth2_permission_scopes = optional(list(object({
        admin_consent_description  = string
        admin_consent_display_name = string
        enabled                   = bool
        id                        = string
        type                      = string
        user_consent_description  = optional(string)
        user_consent_display_name = optional(string)
        value                     = string
      })), [])
    }))
    
    # App roles
    app_roles = optional(list(object({
      allowed_member_types = list(string)
      description         = string
      display_name        = string
      enabled            = bool
      id                 = string
      value              = string
    })), [])
    
    # Required resource access
    required_resource_access = optional(list(object({
      resource_app_id = string
      resource_access = list(object({
        id   = string
        type = string
      }))
    })), [])
    
    tags = optional(map(string), {})
  }))
  default = {}
}

# Security Settings
variable "security_defaults_enabled" {
  description = "Enable Azure AD security defaults"
  type        = bool
  default     = true
}

variable "password_policy" {
  description = "Password policy configuration"
  type = object({
    minimum_length              = optional(number, 8)
    require_uppercase          = optional(bool, true)
    require_lowercase          = optional(bool, true)
    require_numbers            = optional(bool, true)
    require_special_characters = optional(bool, true)
    password_history_count     = optional(number, 24)
    password_age_days         = optional(number, 90)
    lockout_threshold         = optional(number, 5)
    lockout_duration_minutes  = optional(number, 30)
  })
  default = {}
}

# Monitoring and Logging
variable "enable_audit_logs" {
  description = "Enable Azure AD audit logging"
  type        = bool
  default     = true
}

variable "log_analytics_workspace_id" {
  description = "Log Analytics workspace ID for centralized logging"
  type        = string
  default     = null
}

variable "diagnostic_settings" {
  description = "Diagnostic settings configuration for Azure AD"
  type = object({
    name                           = optional(string, "azure-ad-diagnostics")
    log_analytics_workspace_id     = optional(string)
    storage_account_id            = optional(string)
    eventhub_authorization_rule_id = optional(string)
    eventhub_name                 = optional(string)
    
    enabled_log_categories = optional(list(string), [
      "AuditLogs",
      "SignInLogs",
      "RiskyUsers",
      "UserRiskEvents"
    ])
    
    metric_categories = optional(list(string), ["AllMetrics"])
    retention_days   = optional(number, 90)
  })
  default = {}
}

# Resource Tagging
variable "default_tags" {
  description = "Default tags to apply to all resources"
  type        = map(string)
  default = {
    ManagedBy   = "Terraform"
    Environment = "production"
    Project     = "iam-automation"
  }
}

variable "cost_center" {
  description = "Cost center for resource allocation and billing"
  type        = string
  default     = null
}

variable "data_classification" {
  description = "Data classification level (public, internal, confidential, restricted)"
  type        = string
  default     = "internal"
  
  validation {
    condition     = contains(["public", "internal", "confidential", "restricted"], var.data_classification)
    error_message = "Data classification must be one of: public, internal, confidential, restricted."
  }
}

# Environment Configuration
variable "environment" {
  description = "Environment name (dev, staging, production)"
  type        = string
  default     = "production"
  
  validation {
    condition     = contains(["dev", "staging", "production"], var.environment)
    error_message = "Environment must be one of: dev, staging, production."
  }
}

variable "region" {
  description = "Primary Azure region"
  type        = string
  default     = "East US"
}

# Feature Flags
variable "enable_privileged_identity_management" {
  description = "Enable Privileged Identity Management (PIM) features"
  type        = bool
  default     = true
}

variable "enable_conditional_access" {
  description = "Enable conditional access policies"
  type        = bool
  default     = true
}

variable "enable_identity_protection" {
  description = "Enable Azure AD Identity Protection"
  type        = bool
  default     = true
}

variable "enable_application_proxy" {
  description = "Enable Azure AD Application Proxy"
  type        = bool
  default     = false
}

# Compliance and Governance
variable "compliance_frameworks" {
  description = "List of compliance frameworks to adhere to"
  type        = list(string)
  default     = ["SOC2", "ISO27001"]
}

variable "data_residency_requirements" {
  description = "Data residency requirements"
  type = object({
    allowed_regions = optional(list(string), ["East US", "West US 2"])
    data_sovereignty = optional(bool, false)
  })
  default = {}
}

# Backup and Recovery
variable "backup_configuration" {
  description = "Backup configuration for Azure AD"
  type = object({
    enabled                = optional(bool, true)
    retention_days        = optional(number, 90)
    backup_frequency      = optional(string, "daily")
    cross_region_backup   = optional(bool, true)
  })
  default = {}
}
