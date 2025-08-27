# Multi-Cloud IAM Automation - GCP Module
# This module creates and manages IAM resources across GCP projects at scale

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 4.84"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 4.84"
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
  common_labels = merge(var.common_labels, {
    module      = "gcp-iam"
    environment = var.environment
    managed_by  = "terraform"
    project     = var.project_name
    created_at  = formatdate("YYYY-MM-DD", timestamp())
  })
  
  # Service account naming convention
  sa_prefix = "${var.project_name}-${var.environment}"
  
  # Project bindings flattened
  project_bindings = flatten([
    for project_id, bindings in var.project_iam_bindings : [
      for role, members in bindings : {
        project_id = project_id
        role       = role
        members    = members
        key        = "${project_id}-${replace(role, "/", "-")}"
      }
    ]
  ])
  
  # Organization bindings flattened
  org_bindings = flatten([
    for role, members in var.organization_iam_bindings : {
      role    = role
      members = members
      key     = replace(role, "/", "-")
    }
  ])
  
  # Folder bindings flattened
  folder_bindings = flatten([
    for folder_id, bindings in var.folder_iam_bindings : [
      for role, members in bindings : {
        folder_id = folder_id
        role      = role
        members   = members
        key       = "${folder_id}-${replace(role, "/", "-")}"
      }
    ]
  ])
}

# Service Accounts
resource "google_service_account" "service_accounts" {
  for_each = var.service_accounts
  
  project      = each.value.project_id
  account_id   = "${local.sa_prefix}-${each.key}"
  display_name = each.value.display_name != "" ? each.value.display_name : "${local.sa_prefix}-${each.key}"
  description  = each.value.description
  disabled     = each.value.disabled
}

# Service Account Keys
resource "google_service_account_key" "service_account_keys" {
  for_each = {
    for sa_name, sa_config in var.service_accounts : sa_name => sa_config
    if sa_config.create_key
  }
  
  service_account_id = google_service_account.service_accounts[each.key].name
  key_algorithm      = each.value.key_algorithm
  public_key_type    = each.value.public_key_type
  private_key_type   = each.value.private_key_type
  
  keepers = {
    rotation_time = each.value.key_rotation_days > 0 ? 
      formatdate("YYYY-MM-DD", timeadd(timestamp(), "${each.value.key_rotation_days * 24}h")) : 
      timestamp()
  }
}

# Custom IAM Roles
resource "google_project_iam_custom_role" "custom_roles" {
  for_each = var.custom_roles
  
  project     = each.value.project_id
  role_id     = "${replace(local.sa_prefix, "-", "_")}_${each.key}"
  title       = each.value.title
  description = each.value.description
  stage       = each.value.stage
  permissions = each.value.permissions
  deleted     = each.value.deleted
}

# Organization Custom Roles
resource "google_organization_iam_custom_role" "organization_custom_roles" {
  for_each = var.organization_custom_roles
  
  org_id      = var.organization_id
  role_id     = "${replace(local.sa_prefix, "-", "_")}_${each.key}"
  title       = each.value.title
  description = each.value.description
  stage       = each.value.stage
  permissions = each.value.permissions
  deleted     = each.value.deleted
}

# Project IAM Bindings
resource "google_project_iam_binding" "project_bindings" {
  for_each = {
    for binding in local.project_bindings : binding.key => binding
  }
  
  project = each.value.project_id
  role    = each.value.role
  members = each.value.members
  
  dynamic "condition" {
    for_each = var.iam_conditions[each.value.role] != null ? [var.iam_conditions[each.value.role]] : []
    content {
      title       = condition.value.title
      description = condition.value.description
      expression  = condition.value.expression
    }
  }
}

# Organization IAM Bindings
resource "google_organization_iam_binding" "organization_bindings" {
  for_each = {
    for binding in local.org_bindings : binding.key => binding
  }
  
  org_id  = var.organization_id
  role    = each.value.role
  members = each.value.members
  
  dynamic "condition" {
    for_each = var.iam_conditions[each.value.role] != null ? [var.iam_conditions[each.value.role]] : []
    content {
      title       = condition.value.title
      description = condition.value.description
      expression  = condition.value.expression
    }
  }
}

# Folder IAM Bindings
resource "google_folder_iam_binding" "folder_bindings" {
  for_each = {
    for binding in local.folder_bindings : binding.key => binding
  }
  
  folder  = each.value.folder_id
  role    = each.value.role
  members = each.value.members
  
  dynamic "condition" {
    for_each = var.iam_conditions[each.value.role] != null ? [var.iam_conditions[each.value.role]] : []
    content {
      title       = condition.value.title
      description = condition.value.description
      expression  = condition.value.expression
    }
  }
}

# Service Account IAM Bindings
resource "google_service_account_iam_binding" "service_account_bindings" {
  for_each = {
    for sa_name, sa_config in var.service_accounts : sa_name => sa_config
    if length(sa_config.iam_bindings) > 0
  }
  
  service_account_id = google_service_account.service_accounts[each.key].name
  role               = "roles/iam.serviceAccountUser"
  members           = each.value.iam_bindings
}

# Workload Identity Bindings
resource "google_service_account_iam_binding" "workload_identity_bindings" {
  for_each = {
    for sa_name, sa_config in var.service_accounts : sa_name => sa_config
    if sa_config.workload_identity_pool != null
  }
  
  service_account_id = google_service_account.service_accounts[each.key].name
  role               = "roles/iam.workloadIdentityUser"
  members = [
    "principalSet://iam.googleapis.com/${each.value.workload_identity_pool}/attribute.repository/${each.value.github_repository}"
  ]
}

# IAM Deny Policies (Beta)
resource "google_iam_deny_policy" "deny_policies" {
  provider = google-beta
  for_each = var.iam_deny_policies
  
  parent       = each.value.parent
  name         = "${local.sa_prefix}-${each.key}"
  display_name = each.value.display_name
  
  rules {
    description = each.value.rule.description
    
    deny_rule {
      denied_permissions   = each.value.rule.denied_permissions
      denied_principals   = each.value.rule.denied_principals
      exception_principals = each.value.rule.exception_principals
      
      dynamic "denial_condition" {
        for_each = each.value.rule.denial_condition != null ? [each.value.rule.denial_condition] : []
        content {
          title      = denial_condition.value.title
          expression = denial_condition.value.expression
        }
      }
    }
  }
}

# Organization Policies
resource "google_org_policy_policy" "organization_policies" {
  provider = google-beta
  for_each = var.organization_policies
  
  parent = "organizations/${var.organization_id}"
  name   = "organizations/${var.organization_id}/policies/${each.key}"
  
  spec {
    inherit_from_parent = each.value.inherit_from_parent
    reset              = each.value.reset
    
    dynamic "rules" {
      for_each = each.value.rules
      content {
        allow_all  = rules.value.allow_all
        deny_all   = rules.value.deny_all
        enforce    = rules.value.enforce
        
        dynamic "values" {
          for_each = rules.value.values != null ? [rules.value.values] : []
          content {
            allowed_values = values.value.allowed_values
            denied_values  = values.value.denied_values
          }
        }
        
        dynamic "condition" {
          for_each = rules.value.condition != null ? [rules.value.condition] : []
          content {
            title      = condition.value.title
            expression = condition.value.expression
          }
        }
      }
    }
  }
}

# Secret Manager Secrets for Service Account Keys
resource "google_secret_manager_secret" "sa_key_secrets" {
  for_each = {
    for sa_name, sa_config in var.service_accounts : sa_name => sa_config
    if sa_config.create_key && sa_config.store_key_in_secret_manager
  }
  
  project   = each.value.project_id
  secret_id = "${local.sa_prefix}-${each.key}-key"
  
  labels = local.common_labels
  
  replication {
    automatic = true
  }
  
  depends_on = [google_service_account_key.service_account_keys]
}

resource "google_secret_manager_secret_version" "sa_key_versions" {
  for_each = {
    for sa_name, sa_config in var.service_accounts : sa_name => sa_config
    if sa_config.create_key && sa_config.store_key_in_secret_manager
  }
  
  secret = google_secret_manager_secret.sa_key_secrets[each.key].id
  secret_data = base64decode(google_service_account_key.service_account_keys[each.key].private_key)
}

# Cloud Audit Logs Configuration
resource "google_logging_project_sink" "audit_sink" {
  for_each = var.audit_log_sinks
  
  project     = each.value.project_id
  name        = "${local.sa_prefix}-${each.key}-audit-sink"
  destination = each.value.destination
  
  filter = each.value.filter != "" ? each.value.filter : <<-EOF
    protoPayload.serviceName="iam.googleapis.com" OR
    protoPayload.serviceName="cloudresourcemanager.googleapis.com" OR
    protoPayload.serviceName="serviceusage.googleapis.com"
  EOF
  
  unique_writer_identity = true
  
  dynamic "exclusions" {
    for_each = each.value.exclusions
    content {
      name        = exclusions.value.name
      description = exclusions.value.description
      filter      = exclusions.value.filter
      disabled    = exclusions.value.disabled
    }
  }
}

# Cloud Asset Inventory (for compliance and auditing)
resource "google_cloud_asset_organization_feed" "iam_asset_feed" {
  for_each = var.asset_feeds
  
  billing_project  = each.value.billing_project
  org_id          = var.organization_id
  feed_id         = "${local.sa_prefix}-${each.key}"
  content_type    = each.value.content_type
  asset_types     = each.value.asset_types
  
  feed_output_config {
    pubsub_destination {
      topic = each.value.pubsub_topic
    }
  }
  
  dynamic "condition" {
    for_each = each.value.condition != null ? [each.value.condition] : []
    content {
      expression  = condition.value.expression
      title      = condition.value.title
      description = condition.value.description
      location   = condition.value.location
    }
  }
}

# Identity-Aware Proxy (IAP) Settings
resource "google_iap_brand" "iap_brand" {
  for_each = var.iap_brands
  
  project          = each.value.project_id
  support_email    = each.value.support_email
  application_title = each.value.application_title
}

resource "google_iap_client" "iap_clients" {
  for_each = var.iap_clients
  
  display_name = each.value.display_name
  brand       = google_iap_brand.iap_brand[each.value.brand_key].name
}

# Security Command Center Notifications
resource "google_scc_notification_config" "scc_notifications" {
  provider = google-beta
  for_each = var.scc_notification_configs
  
  config_id    = "${local.sa_prefix}-${each.key}"
  organization = var.organization_id
  description  = each.value.description
  pubsub_topic = each.value.pubsub_topic
  
  streaming_config {
    filter = each.value.filter
  }
}

# Binary Authorization Policies
resource "google_binary_authorization_policy" "binary_auth_policies" {
  provider = google-beta
  for_each = var.binary_authorization_policies
  
  project = each.value.project_id
  
  default_admission_rule {
    evaluation_mode  = each.value.default_admission_rule.evaluation_mode
    enforcement_mode = each.value.default_admission_rule.enforcement_mode
    
    dynamic "require_attestations_by" {
      for_each = each.value.default_admission_rule.require_attestations_by
      content {
        attestor = require_attestations_by.value
      }
    }
  }
  
  dynamic "admission_whitelist_patterns" {
    for_each = each.value.admission_whitelist_patterns
    content {
      name_pattern = admission_whitelist_patterns.value
    }
  }
}
