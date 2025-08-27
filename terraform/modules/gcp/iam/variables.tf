# GCP IAM Module Variables
# Comprehensive variable definitions for enterprise-grade GCP IAM management

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

variable "organization_id" {
  description = "GCP Organization ID"
  type        = string
  default     = ""
}

variable "common_labels" {
  description = "Common labels to be applied to all resources"
  type        = map(string)
  default     = {}
}

# Service Accounts Configuration
variable "service_accounts" {
  description = "Map of service accounts to create"
  type = map(object({
    project_id                   = string
    display_name                 = optional(string, "")
    description                  = optional(string, "")
    disabled                     = optional(bool, false)
    create_key                   = optional(bool, false)
    store_key_in_secret_manager  = optional(bool, true)
    key_algorithm               = optional(string, "KEY_ALG_RSA_2048")
    public_key_type             = optional(string, "TYPE_X509_PEM_FILE")
    private_key_type            = optional(string, "TYPE_GOOGLE_CREDENTIALS_FILE")
    key_rotation_days           = optional(number, 90)
    iam_bindings               = optional(list(string), [])
    workload_identity_pool     = optional(string, null)
    github_repository          = optional(string, null)
  }))
  default = {}
}

# Custom Roles Configuration
variable "custom_roles" {
  description = "Map of custom IAM roles to create at project level"
  type = map(object({
    project_id  = string
    title       = string
    description = string
    stage       = optional(string, "GA")
    permissions = list(string)
    deleted     = optional(bool, false)
  }))
  default = {}
}

# Organization Custom Roles Configuration
variable "organization_custom_roles" {
  description = "Map of custom IAM roles to create at organization level"
  type = map(object({
    title       = string
    description = string
    stage       = optional(string, "GA")
    permissions = list(string)
    deleted     = optional(bool, false)
  }))
  default = {}
}

# Project IAM Bindings
variable "project_iam_bindings" {
  description = "IAM bindings for projects"
  type        = map(map(list(string)))
  default     = {}
  
  # Example:
  # {
  #   "my-project" = {
  #     "roles/viewer" = ["user:alice@example.com", "serviceAccount:sa@project.iam.gserviceaccount.com"]
  #     "roles/editor" = ["user:bob@example.com"]
  #   }
  # }
}

# Organization IAM Bindings
variable "organization_iam_bindings" {
  description = "IAM bindings for organization"
  type        = map(list(string))
  default     = {}
}

# Folder IAM Bindings
variable "folder_iam_bindings" {
  description = "IAM bindings for folders"
  type        = map(map(list(string)))
  default     = {}
}

# IAM Conditions
variable "iam_conditions" {
  description = "IAM conditions for conditional bindings"
  type = map(object({
    title       = string
    description = string
    expression  = string
  }))
  default = {}
}

# IAM Deny Policies
variable "iam_deny_policies" {
  description = "IAM deny policies configuration"
  type = map(object({
    parent       = string
    display_name = string
    rule = object({
      description          = string
      denied_permissions   = list(string)
      denied_principals    = list(string)
      exception_principals = optional(list(string), [])
      denial_condition = optional(object({
        title      = string
        expression = string
      }), null)
    })
  }))
  default = {}
}

# Organization Policies
variable "organization_policies" {
  description = "Organization policies configuration"
  type = map(object({
    inherit_from_parent = optional(bool, false)
    reset              = optional(bool, false)
    rules = list(object({
      allow_all = optional(bool, null)
      deny_all  = optional(bool, null)
      enforce   = optional(bool, null)
      values = optional(object({
        allowed_values = optional(list(string), [])
        denied_values  = optional(list(string), [])
      }), null)
      condition = optional(object({
        title      = string
        expression = string
      }), null)
    }))
  }))
  default = {}
}

# Audit Log Sinks
variable "audit_log_sinks" {
  description = "Audit log sinks configuration"
  type = map(object({
    project_id  = string
    destination = string
    filter      = optional(string, "")
    exclusions = optional(list(object({
      name        = string
      description = string
      filter      = string
      disabled    = optional(bool, false)
    })), [])
  }))
  default = {}
}

# Cloud Asset Inventory Feeds
variable "asset_feeds" {
  description = "Cloud Asset Inventory feeds configuration"
  type = map(object({
    billing_project = string
    content_type   = optional(string, "RESOURCE")
    asset_types    = list(string)
    pubsub_topic   = string
    condition = optional(object({
      expression  = string
      title       = string
      description = optional(string, "")
      location    = optional(string, "")
    }), null)
  }))
  default = {}
}

# Identity-Aware Proxy Configuration
variable "iap_brands" {
  description = "IAP brands configuration"
  type = map(object({
    project_id        = string
    support_email     = string
    application_title = string
  }))
  default = {}
}

variable "iap_clients" {
  description = "IAP clients configuration"
  type = map(object({
    display_name = string
    brand_key    = string
  }))
  default = {}
}

# Security Command Center Notifications
variable "scc_notification_configs" {
  description = "Security Command Center notification configurations"
  type = map(object({
    description  = string
    pubsub_topic = string
    filter       = string
  }))
  default = {}
}

# Binary Authorization Policies
variable "binary_authorization_policies" {
  description = "Binary Authorization policies configuration"
  type = map(object({
    project_id = string
    default_admission_rule = object({
      evaluation_mode         = string
      enforcement_mode        = string
      require_attestations_by = list(string)
    })
    admission_whitelist_patterns = optional(list(string), [])
  }))
  default = {}
}

# Workload Identity Configuration
variable "workload_identity_pools" {
  description = "Workload Identity pools configuration"
  type = map(object({
    project_id    = string
    display_name  = optional(string, "")
    description   = optional(string, "")
    disabled      = optional(bool, false)
    attribute_mapping = optional(map(string), {})
    attribute_condition = optional(string, "")
    providers = optional(map(object({
      display_name = optional(string, "")
      description  = optional(string, "")
      disabled     = optional(bool, false)
      issuer_uri   = string
      allowed_audiences = optional(list(string), [])
      attribute_mapping = optional(map(string), {})
      attribute_condition = optional(string, "")
    })), {})
  }))
  default = {}
}

# VPC Service Controls
variable "access_policies" {
  description = "VPC Service Controls access policies"
  type = map(object({
    parent = string
    title  = string
    scopes = list(string)
  }))
  default = {}
}

variable "service_perimeters" {
  description = "VPC Service Controls service perimeters"
  type = map(object({
    parent        = string
    title         = string
    description   = optional(string, "")
    perimeter_type = optional(string, "PERIMETER_TYPE_REGULAR")
    status = object({
      resources          = list(string)
      restricted_services = list(string)
      access_levels      = optional(list(string), [])
      vpc_accessible_services = optional(object({
        enable_restriction = bool
        allowed_services   = list(string)
      }), null)
      ingress_policies = optional(list(object({
        ingress_from = object({
          sources = list(object({
            access_level = optional(string, "")
            resource     = optional(string, "")
          }))
          identity_type = optional(string, "")
          identities    = optional(list(string), [])
        })
        ingress_to = object({
          resources = list(string)
          operations = list(object({
            service_name = string
            method_selectors = optional(list(object({
              method     = optional(string, "")
              permission = optional(string, "")
            })), [])
          }))
        })
      })), [])
      egress_policies = optional(list(object({
        egress_from = object({
          identity_type = optional(string, "")
          identities    = optional(list(string), [])
        })
        egress_to = object({
          resources = list(string)
          operations = list(object({
            service_name = string
            method_selectors = optional(list(object({
              method     = optional(string, "")
              permission = optional(string, "")
            })), [])
          }))
          external_resources = optional(list(string), [])
        })
      })), [])
    })
  }))
  default = {}
}

# Certificate Authority Service
variable "certificate_authorities" {
  description = "Certificate Authority Service configuration"
  type = map(object({
    project_id = string
    location   = string
    pool       = string
    certificate_authority_id = string
    type       = optional(string, "SELF_SIGNED")
    config = object({
      subject_config = object({
        subject = object({
          organization        = string
          organizational_unit = optional(string, "")
        })
        subject_alt_name = optional(object({
          dns_names       = optional(list(string), [])
          uris           = optional(list(string), [])
          email_addresses = optional(list(string), [])
          ip_addresses   = optional(list(string), [])
        }), null)
      })
      x509_config = object({
        key_usage = object({
          base_key_usage = object({
            digital_signature  = optional(bool, true)
            content_commitment = optional(bool, false)
            key_encipherment  = optional(bool, false)
            data_encipherment = optional(bool, false)
            key_agreement     = optional(bool, false)
            cert_sign         = optional(bool, true)
            crl_sign          = optional(bool, true)
            decipher_only     = optional(bool, false)
          })
          extended_key_usage = optional(object({
            server_auth      = optional(bool, true)
            client_auth      = optional(bool, false)
            email_protection = optional(bool, false)
            code_signing     = optional(bool, false)
            time_stamping    = optional(bool, false)
          }), null)
        })
        ca_options = object({
          is_ca                = bool
          max_issuer_path_length = optional(number, 0)
        })
      })
    })
    lifetime = optional(string, "315360000s") # 10 years
    key_spec = object({
      algorithm = optional(string, "RSA_PKCS1_2048_SHA256")
    })
  }))
  default = {}
}

# Cloud KMS Configuration
variable "kms_key_rings" {
  description = "Cloud KMS key rings configuration"
  type = map(object({
    project_id = string
    location   = string
    keys = optional(map(object({
      rotation_period    = optional(string, "2592000s") # 30 days
      algorithm         = optional(string, "GOOGLE_SYMMETRIC_ENCRYPTION")
      protection_level  = optional(string, "SOFTWARE")
      purpose          = optional(string, "ENCRYPT_DECRYPT")
    })), {})
  }))
  default = {}
}

# Resource Manager Liens
variable "resource_liens" {
  description = "Resource Manager liens for protecting resources"
  type = map(object({
    parent       = string
    restrictions = list(string)
    origin      = string
    reason      = string
  }))
  default = {}
}

# Compute Security Policies
variable "compute_security_policies" {
  description = "Compute Engine security policies"
  type = map(object({
    project_id  = string
    description = optional(string, "")
    type       = optional(string, "CLOUD_ARMOR")
    rules = list(object({
      action   = string
      priority = number
      match = object({
        versioned_expr = optional(string, "")
        config = optional(object({
          src_ip_ranges = list(string)
        }), null)
      })
      description = optional(string, "")
    }))
  }))
  default = {}
}

# Monitoring Notification Channels
variable "monitoring_notification_channels" {
  description = "Cloud Monitoring notification channels"
  type = map(object({
    project_id   = string
    type        = string
    display_name = string
    description = optional(string, "")
    labels      = map(string)
    enabled     = optional(bool, true)
    user_labels = optional(map(string), {})
  }))
  default = {}
}

# Alerting Policies
variable "monitoring_alert_policies" {
  description = "Cloud Monitoring alert policies"
  type = map(object({
    project_id              = string
    display_name           = string
    documentation         = optional(string, "")
    enabled               = optional(bool, true)
    notification_channels = list(string)
    conditions = list(object({
      display_name = string
      condition_threshold = object({
        filter          = string
        duration        = string
        comparison      = string
        threshold_value = number
        aggregations = list(object({
          alignment_period   = string
          per_series_aligner = string
          cross_series_reducer = optional(string, "")
          group_by_fields    = optional(list(string), [])
        }))
      })
    }))
    combiner = optional(string, "OR")
  }))
  default = {}
}
