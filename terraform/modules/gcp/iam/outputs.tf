# GCP IAM Module Outputs
# Comprehensive outputs for created GCP IAM resources

# Service Accounts Outputs
output "service_accounts" {
  description = "Map of created service accounts"
  value = {
    for sa_name, sa in google_service_account.service_accounts : sa_name => {
      name         = sa.name
      email        = sa.email
      unique_id    = sa.unique_id
      display_name = sa.display_name
      description  = sa.description
      project      = sa.project
      disabled     = sa.disabled
      member       = "serviceAccount:${sa.email}"
    }
  }
}

# Service Account Keys Outputs (metadata only)
output "service_account_keys" {
  description = "Map of service account keys metadata (keys stored in Secret Manager)"
  value = {
    for sa_name, key in google_service_account_key.service_account_keys : sa_name => {
      name               = key.name
      key_algorithm      = key.key_algorithm
      public_key_type    = key.public_key_type
      private_key_type   = key.private_key_type
      valid_after        = key.valid_after
      valid_before       = key.valid_before
      secret_manager_secret = try(google_secret_manager_secret.sa_key_secrets[sa_name].name, null)
    }
  }
  sensitive = true
}

# Custom Roles Outputs
output "custom_roles" {
  description = "Map of created custom IAM roles"
  value = {
    for role_name, role in google_project_iam_custom_role.custom_roles : role_name => {
      name        = role.name
      role_id     = role.role_id
      title       = role.title
      description = role.description
      stage       = role.stage
      permissions = role.permissions
      project     = role.project
      deleted     = role.deleted
    }
  }
}

# Organization Custom Roles Outputs
output "organization_custom_roles" {
  description = "Map of created organization custom IAM roles"
  value = {
    for role_name, role in google_organization_iam_custom_role.organization_custom_roles : role_name => {
      name        = role.name
      role_id     = role.role_id
      title       = role.title
      description = role.description
      stage       = role.stage
      permissions = role.permissions
      org_id      = role.org_id
      deleted     = role.deleted
    }
  }
}

# Project IAM Bindings Outputs
output "project_iam_bindings" {
  description = "Map of created project IAM bindings"
  value = {
    for binding_key, binding in google_project_iam_binding.project_bindings : binding_key => {
      project = binding.project
      role    = binding.role
      members = binding.members
      etag    = binding.etag
    }
  }
}

# Organization IAM Bindings Outputs
output "organization_iam_bindings" {
  description = "Map of created organization IAM bindings"
  value = {
    for binding_key, binding in google_organization_iam_binding.organization_bindings : binding_key => {
      org_id  = binding.org_id
      role    = binding.role
      members = binding.members
      etag    = binding.etag
    }
  }
}

# Folder IAM Bindings Outputs
output "folder_iam_bindings" {
  description = "Map of created folder IAM bindings"
  value = {
    for binding_key, binding in google_folder_iam_binding.folder_bindings : binding_key => {
      folder  = binding.folder
      role    = binding.role
      members = binding.members
      etag    = binding.etag
    }
  }
}

# Service Account IAM Bindings Outputs
output "service_account_iam_bindings" {
  description = "Map of service account IAM bindings"
  value = {
    for sa_name, binding in google_service_account_iam_binding.service_account_bindings : sa_name => {
      service_account_id = binding.service_account_id
      role              = binding.role
      members           = binding.members
      etag              = binding.etag
    }
  }
}

# Workload Identity Bindings Outputs
output "workload_identity_bindings" {
  description = "Map of workload identity bindings"
  value = {
    for sa_name, binding in google_service_account_iam_binding.workload_identity_bindings : sa_name => {
      service_account_id = binding.service_account_id
      role              = binding.role
      members           = binding.members
      etag              = binding.etag
    }
  }
}

# IAM Deny Policies Outputs
output "iam_deny_policies" {
  description = "Map of created IAM deny policies"
  value = {
    for policy_name, policy in google_iam_deny_policy.deny_policies : policy_name => {
      name         = policy.name
      parent       = policy.parent
      display_name = policy.display_name
      etag         = policy.etag
    }
  }
}

# Organization Policies Outputs
output "organization_policies" {
  description = "Map of created organization policies"
  value = {
    for policy_name, policy in google_org_policy_policy.organization_policies : policy_name => {
      name   = policy.name
      parent = policy.parent
      etag   = policy.etag
    }
  }
}

# Audit Log Sinks Outputs
output "audit_log_sinks" {
  description = "Map of created audit log sinks"
  value = {
    for sink_name, sink in google_logging_project_sink.audit_sink : sink_name => {
      name                   = sink.name
      project               = sink.project
      destination           = sink.destination
      filter                = sink.filter
      unique_writer_identity = sink.unique_writer_identity
      writer_identity       = sink.writer_identity
    }
  }
}

# Cloud Asset Inventory Feeds Outputs
output "asset_feeds" {
  description = "Map of created Cloud Asset Inventory feeds"
  value = {
    for feed_name, feed in google_cloud_asset_organization_feed.iam_asset_feed : feed_name => {
      name            = feed.name
      billing_project = feed.billing_project
      org_id         = feed.org_id
      feed_id        = feed.feed_id
      content_type   = feed.content_type
      asset_types    = feed.asset_types
    }
  }
}

# IAP Brands Outputs
output "iap_brands" {
  description = "Map of created IAP brands"
  value = {
    for brand_name, brand in google_iap_brand.iap_brand : brand_name => {
      name              = brand.name
      project           = brand.project
      support_email     = brand.support_email
      application_title = brand.application_title
      org_internal_only = brand.org_internal_only
    }
  }
}

# IAP Clients Outputs
output "iap_clients" {
  description = "Map of created IAP clients"
  value = {
    for client_name, client in google_iap_client.iap_clients : client_name => {
      client_id    = client.client_id
      display_name = client.display_name
      brand        = client.brand
      secret       = client.secret
    }
  }
  sensitive = true
}

# Security Command Center Notifications Outputs
output "scc_notification_configs" {
  description = "Map of created SCC notification configurations"
  value = {
    for config_name, config in google_scc_notification_config.scc_notifications : config_name => {
      name         = config.name
      config_id    = config.config_id
      organization = config.organization
      description  = config.description
      pubsub_topic = config.pubsub_topic
    }
  }
}

# Binary Authorization Policies Outputs
output "binary_authorization_policies" {
  description = "Map of created Binary Authorization policies"
  value = {
    for policy_name, policy in google_binary_authorization_policy.binary_auth_policies : policy_name => {
      project = policy.project
      etag    = policy.etag
    }
  }
}

# Secret Manager Secrets Outputs
output "secret_manager_secrets" {
  description = "Map of Secret Manager secrets for service account keys"
  value = {
    for secret_name, secret in google_secret_manager_secret.sa_key_secrets : secret_name => {
      name      = secret.name
      secret_id = secret.secret_id
      project   = secret.project
      labels    = secret.labels
    }
  }
}

# Summary Statistics
output "resource_summary" {
  description = "Summary of created GCP IAM resources"
  value = {
    service_accounts_created           = length(google_service_account.service_accounts)
    service_account_keys_created       = length(google_service_account_key.service_account_keys)
    custom_roles_created              = length(google_project_iam_custom_role.custom_roles)
    organization_custom_roles_created = length(google_organization_iam_custom_role.organization_custom_roles)
    project_bindings_created          = length(google_project_iam_binding.project_bindings)
    organization_bindings_created     = length(google_organization_iam_binding.organization_bindings)
    folder_bindings_created           = length(google_folder_iam_binding.folder_bindings)
    deny_policies_created             = length(google_iam_deny_policy.deny_policies)
    organization_policies_created     = length(google_org_policy_policy.organization_policies)
    audit_sinks_created               = length(google_logging_project_sink.audit_sink)
    asset_feeds_created               = length(google_cloud_asset_organization_feed.iam_asset_feed)
    iap_brands_created               = length(google_iap_brand.iap_brand)
    iap_clients_created              = length(google_iap_client.iap_clients)
    scc_notifications_created        = length(google_scc_notification_config.scc_notifications)
    secret_manager_secrets_created   = length(google_secret_manager_secret.sa_key_secrets)
  }
}

# Service Account Emails for Reference
output "service_account_emails" {
  description = "Map of service account names to emails"
  value = {
    for sa_name, sa in google_service_account.service_accounts : sa_name => sa.email
  }
}

# Custom Role Names for Reference
output "custom_role_names" {
  description = "Map of custom role keys to role names"
  value = {
    for role_name, role in google_project_iam_custom_role.custom_roles : role_name => role.name
  }
}

# Organization Custom Role Names for Reference
output "organization_custom_role_names" {
  description = "Map of organization custom role keys to role names"
  value = {
    for role_name, role in google_organization_iam_custom_role.organization_custom_roles : role_name => role.name
  }
}

# IAM Policy Bindings Summary
output "iam_bindings_summary" {
  description = "Summary of IAM policy bindings by type"
  value = {
    project_bindings = {
      for project_id in distinct([for binding in local.project_bindings : binding.project_id]) :
      project_id => length([for binding in local.project_bindings : binding if binding.project_id == project_id])
    }
    organization_bindings = length(local.org_bindings)
    folder_bindings = {
      for folder_id in distinct([for binding in local.folder_bindings : binding.folder_id]) :
      folder_id => length([for binding in local.folder_bindings : binding if binding.folder_id == folder_id])
    }
  }
}

# Compliance and Audit Information
output "compliance_info" {
  description = "Compliance and audit information"
  value = {
    created_resources = {
      timestamp    = timestamp()
      environment  = var.environment
      project_name = var.project_name
      created_by   = "terraform"
    }
    audit_configuration = {
      audit_sinks_enabled = length(google_logging_project_sink.audit_sink) > 0
      asset_feeds_enabled = length(google_cloud_asset_organization_feed.iam_asset_feed) > 0
      scc_notifications_enabled = length(google_scc_notification_config.scc_notifications) > 0
    }
    security_features = {
      deny_policies_enabled = length(google_iam_deny_policy.deny_policies) > 0
      organization_policies_enabled = length(google_org_policy_policy.organization_policies) > 0
      binary_authorization_enabled = length(google_binary_authorization_policy.binary_auth_policies) > 0
      iap_enabled = length(google_iap_brand.iap_brand) > 0
    }
    secret_management = {
      secret_manager_integration = length(google_secret_manager_secret.sa_key_secrets) > 0
    }
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
    organization_id = var.organization_id
    terraform_version = "~> 1.5.0"
    provider_versions = {
      google = "~> 4.84"
      google-beta = "~> 4.84"
      random = "~> 3.1"
      time = "~> 0.9"
    }
    resource_counts = {
      service_accounts = length(google_service_account.service_accounts)
      custom_roles = length(google_project_iam_custom_role.custom_roles)
      organization_custom_roles = length(google_organization_iam_custom_role.organization_custom_roles)
      iam_bindings = length(google_project_iam_binding.project_bindings) + length(google_organization_iam_binding.organization_bindings) + length(google_folder_iam_binding.folder_bindings)
    }
    labels_applied = local.common_labels
  }
}

# Cross-Cloud Integration Data
output "cross_cloud_integration" {
  description = "Data for cross-cloud IAM integration"
  value = {
    workload_identity_pools = var.workload_identity_pools
    service_account_for_cross_cloud = {
      for sa_name, sa_config in var.service_accounts : sa_name => {
        email = google_service_account.service_accounts[sa_name].email
        unique_id = google_service_account.service_accounts[sa_name].unique_id
        member = "serviceAccount:${google_service_account.service_accounts[sa_name].email}"
      }
      if sa_config.workload_identity_pool != null
    }
  }
}
