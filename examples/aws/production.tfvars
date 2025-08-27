# Example Terraform Variables for AWS Production Environment
# This file demonstrates how to use the AWS IAM module with production-scale configurations

# AWS Provider Configuration
aws_region = "us-east-1"
aws_additional_regions = ["us-west-2", "eu-west-1"]

# Account Configuration
aws_account_ids = [
  "111111111111", # Management Account
  "222222222222", # Production Account 1
  "333333333333", # Production Account 2
  "444444444444", # Production Account 3
  # ... Add up to 1000+ accounts
]

organization_id = "o-1234567890"
management_account_id = "111111111111"

# Cross-account role for assumed role access
cross_account_role_name = "OrganizationAccountAccessRole"
deployment_role_name = "IAMAutomationDeploymentRole"

# IAM Users Configuration
iam_users = {
  "admin-user-001" = {
    name = "admin-user-001"
    path = "/admins/"
    permissions_boundary_arn = "arn:aws:iam::111111111111:policy/AdminPermissionsBoundary"
    force_destroy = false
    
    groups = ["administrators", "security-team"]
    policies = ["AdminAccess", "SecurityAuditAccess"]
    
    access_keys = [
      {
        status = "Active"
        pgp_key = "keybase:admin-user-001"
      }
    ]
    
    tags = {
      Department = "IT"
      Team = "Infrastructure"
      Role = "Administrator"
      CostCenter = "IT-001"
      DataClassification = "confidential"
    }
  }
  
  "developer-user-001" = {
    name = "developer-user-001"
    path = "/developers/"
    permissions_boundary_arn = "arn:aws:iam::111111111111:policy/DeveloperPermissionsBoundary"
    force_destroy = true
    
    groups = ["developers", "application-team"]
    policies = ["DeveloperAccess"]
    
    login_profile = {
      create_login_profile = true
      pgp_key = "keybase:developer-user-001"
      password_reset_required = true
      password_length = 16
    }
    
    tags = {
      Department = "Engineering"
      Team = "Application Development"
      Role = "Developer"
      CostCenter = "ENG-001"
      DataClassification = "internal"
    }
  }
  
  "service-account-001" = {
    name = "service-account-001"
    path = "/service-accounts/"
    permissions_boundary_arn = "arn:aws:iam::111111111111:policy/ServiceAccountPermissionsBoundary"
    force_destroy = false
    
    policies = ["ServiceAccountAccess"]
    
    access_keys = [
      {
        status = "Active"
      }
    ]
    
    tags = {
      Type = "ServiceAccount"
      Application = "DataPipeline"
      Environment = "Production"
      CostCenter = "DATA-001"
      DataClassification = "internal"
    }
  }
}

# IAM Groups Configuration
iam_groups = {
  "administrators" = {
    name = "administrators"
    path = "/admin-groups/"
    
    policies = [
      "arn:aws:iam::aws:policy/AdministratorAccess"
    ]
    
    inline_policies = [
      {
        name = "AdminMFARequired"
        policy = jsonencode({
          Version = "2012-10-17"
          Statement = [
            {
              Effect = "Deny"
              NotAction = [
                "iam:CreateVirtualMFADevice",
                "iam:EnableMFADevice",
                "iam:GetUser",
                "iam:ListMFADevices",
                "iam:ListVirtualMFADevices",
                "iam:ResyncMFADevice",
                "sts:GetSessionToken"
              ]
              Resource = "*"
              Condition = {
                BoolIfExists = {
                  "aws:MultiFactorAuthPresent" = "false"
                }
              }
            }
          ]
        })
      }
    ]
    
    tags = {
      GroupType = "Administrative"
      AccessLevel = "Full"
      RequiresMFA = "true"
    }
  }
  
  "developers" = {
    name = "developers"
    path = "/dev-groups/"
    
    policies = [
      "arn:aws:iam::aws:policy/PowerUserAccess"
    ]
    
    inline_policies = [
      {
        name = "DeveloperRestrictions"
        policy = jsonencode({
          Version = "2012-10-17"
          Statement = [
            {
              Effect = "Deny"
              Action = [
                "iam:*",
                "organizations:*",
                "account:*"
              ]
              Resource = "*"
            }
          ]
        })
      }
    ]
    
    tags = {
      GroupType = "Development"
      AccessLevel = "PowerUser"
      Environment = "NonProduction"
    }
  }
  
  "security-team" = {
    name = "security-team"
    path = "/security-groups/"
    
    policies = [
      "arn:aws:iam::aws:policy/SecurityAudit",
      "arn:aws:iam::aws:policy/ReadOnlyAccess"
    ]
    
    tags = {
      GroupType = "Security"
      AccessLevel = "ReadOnly"
      Function = "Audit"
    }
  }
}

# IAM Roles Configuration
iam_roles = {
  "application-role-001" = {
    name = "application-role-001"
    path = "/application-roles/"
    description = "Role for production application workloads"
    max_session_duration = 3600
    permissions_boundary_arn = "arn:aws:iam::111111111111:policy/ApplicationPermissionsBoundary"
    
    assume_role_policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Action = "sts:AssumeRole"
          Effect = "Allow"
          Principal = {
            Service = "ec2.amazonaws.com"
          }
        },
        {
          Action = "sts:AssumeRole"
          Effect = "Allow"
          Principal = {
            Service = "lambda.amazonaws.com"
          }
        }
      ]
    })
    
    policies = ["ApplicationAccess"]
    
    tags = {
      RoleType = "Application"
      Environment = "Production"
      Workload = "WebApplication"
    }
  }
  
  "cross-account-role-001" = {
    name = "cross-account-role-001"
    path = "/cross-account-roles/"
    description = "Role for cross-account access"
    max_session_duration = 1800
    
    assume_role_policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Action = "sts:AssumeRole"
          Effect = "Allow"
          Principal = {
            AWS = [
              "arn:aws:iam::222222222222:root",
              "arn:aws:iam::333333333333:root"
            ]
          }
          Condition = {
            StringEquals = {
              "sts:ExternalId" = "unique-external-id-123"
            }
            Bool = {
              "aws:MultiFactorAuthPresent" = "true"
            }
          }
        }
      ]
    })
    
    policies = ["CrossAccountAccess"]
    
    tags = {
      RoleType = "CrossAccount"
      AccessType = "Federated"
      SecurityLevel = "High"
    }
  }
  
  "emergency-access-role" = {
    name = "emergency-access-role"
    path = "/emergency-roles/"
    description = "Emergency break-glass access role"
    max_session_duration = 1800
    
    assume_role_policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Action = "sts:AssumeRole"
          Effect = "Allow"
          Principal = {
            AWS = "arn:aws:iam::111111111111:user/emergency-user"
          }
          Condition = {
            Bool = {
              "aws:MultiFactorAuthPresent" = "true"
            }
            IpAddress = {
              "aws:SourceIp" = ["203.0.113.0/24"]
            }
          }
        }
      ]
    })
    
    policies = [
      "arn:aws:iam::aws:policy/AdministratorAccess"
    ]
    
    tags = {
      RoleType = "Emergency"
      AccessLevel = "Administrative"
      Usage = "BreakGlass"
    }
  }
}

# IAM Policies Configuration
iam_policies = {
  "ApplicationAccess" = {
    name = "ApplicationAccess"
    path = "/application-policies/"
    description = "Policy for application workloads"
    
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Effect = "Allow"
          Action = [
            "s3:GetObject",
            "s3:PutObject",
            "s3:DeleteObject"
          ]
          Resource = [
            "arn:aws:s3:::production-app-bucket/*"
          ]
        },
        {
          Effect = "Allow"
          Action = [
            "dynamodb:GetItem",
            "dynamodb:PutItem",
            "dynamodb:UpdateItem",
            "dynamodb:DeleteItem",
            "dynamodb:Query",
            "dynamodb:Scan"
          ]
          Resource = [
            "arn:aws:dynamodb:*:*:table/production-*"
          ]
        },
        {
          Effect = "Allow"
          Action = [
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents"
          ]
          Resource = "*"
        }
      ]
    })
    
    tags = {
      PolicyType = "Application"
      Environment = "Production"
      AccessLevel = "Limited"
    }
  }
  
  "DeveloperAccess" = {
    name = "DeveloperAccess"  
    path = "/developer-policies/"
    description = "Policy for developer access"
    
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Effect = "Allow"
          Action = [
            "ec2:*",
            "s3:*",
            "lambda:*",
            "dynamodb:*",
            "cloudformation:*",
            "cloudwatch:*",
            "logs:*"
          ]
          Resource = "*"
          Condition = {
            StringLike = {
              "aws:RequestedRegion" = ["us-east-1", "us-west-2"]
            }
          }
        },
        {
          Effect = "Deny"
          Action = [
            "ec2:TerminateInstances"
          ]
          Resource = "*"
          Condition = {
            StringEquals = {
              "ec2:ResourceTag/Environment" = "Production"
            }
          }
        }
      ]
    })
    
    tags = {
      PolicyType = "Developer"
      Environment = "Development"
      AccessLevel = "PowerUser"
    }
  }
  
  "SecurityAuditAccess" = {
    name = "SecurityAuditAccess"
    path = "/security-policies/"
    description = "Policy for security audit access"
    
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Effect = "Allow"
          Action = [
            "access-analyzer:*",
            "config:*",
            "cloudtrail:*",
            "guardduty:*",
            "inspector:*",
            "securityhub:*",
            "trustedadvisor:*"
          ]
          Resource = "*"
        },
        {
          Effect = "Allow"
          Action = [
            "iam:GenerateCredentialReport",
            "iam:GetCredentialReport",
            "iam:ListUsers",
            "iam:ListRoles",
            "iam:ListPolicies",
            "iam:GetAccountSummary"
          ]
          Resource = "*"
        }
      ]
    })
    
    tags = {
      PolicyType = "Security"
      Function = "Audit"
      AccessLevel = "ReadOnly"
    }
  }
}

# Instance Profiles Configuration
instance_profiles = {
  "application-instance-profile" = {
    name = "application-instance-profile"
    path = "/instance-profiles/"
    role = "application-role-001"
    
    tags = {
      ProfileType = "Application"
      Environment = "Production"
    }
  }
}

# SAML Identity Providers
saml_identity_providers = {
  "corporate-idp" = {
    name = "corporate-idp"
    saml_metadata_document = file("${path.module}/idp-metadata.xml")
    
    tags = {
      IdentityProvider = "Corporate"
      Type = "SAML"
    }
  }
}

# Security Configuration
security_config = {
  account_password_policy = {
    minimum_password_length        = 14
    require_lowercase_characters   = true
    require_numbers               = true
    require_uppercase_characters  = true
    require_symbols              = true
    allow_users_to_change_password = true
    hard_expiry                  = false
    max_password_age             = 90
    password_reuse_prevention    = 24
  }
  
  mfa_enforcement = true
  root_access_keys_disabled = true
  unused_credentials_disabled = true
  
  access_analyzer = {
    enabled = true
    name = "production-access-analyzer"
    type = "ACCOUNT"
  }
}

# Monitoring and Compliance
monitoring_config = {
  cloudtrail = {
    enabled = true
    name = "production-cloudtrail"
    s3_bucket_name = "production-cloudtrail-logs"
    include_global_service_events = true
    is_multi_region_trail = true
    enable_log_file_validation = true
  }
  
  config = {
    enabled = true
    configuration_recorder_name = "production-config-recorder"
    delivery_channel_name = "production-config-delivery"
    s3_bucket_name = "production-config-logs"
  }
  
  guardduty = {
    enabled = true
    finding_publishing_frequency = "FIFTEEN_MINUTES"
  }
}

# Cost Management
cost_management = {
  budgets = [
    {
      name = "production-monthly-budget"
      budget_type = "COST"
      limit_amount = "10000"
      limit_unit = "USD"
      time_unit = "MONTHLY"
      
      cost_filters = {
        Service = ["Amazon Elastic Compute Cloud - Compute"]
      }
      
      notifications = [
        {
          comparison_operator = "GREATER_THAN"
          threshold = 80
          threshold_type = "PERCENTAGE"
          notification_type = "ACTUAL"
          subscriber_email_addresses = ["admin@company.com"]
        }
      ]
    }
  ]
}

# Backup and Disaster Recovery
backup_config = {
  backup_vault_name = "production-backup-vault"
  backup_plan_name = "production-backup-plan"
  
  backup_rules = [
    {
      rule_name = "daily_backup"
      target_backup_vault = "production-backup-vault"
      schedule = "cron(0 2 ? * * *)"
      
      lifecycle = {
        cold_storage_after = 30
        delete_after = 365
      }
      
      recovery_point_tags = {
        BackupType = "Daily"
        Environment = "Production"
      }
    }
  ]
}

# Tags
default_tags = {
  ManagedBy = "Terraform"
  Environment = "Production"
  Project = "IAM-Automation"
  Team = "Infrastructure"
  CostCenter = "IT-001"
  Compliance = "SOC2"
  DataClassification = "Confidential"
}
