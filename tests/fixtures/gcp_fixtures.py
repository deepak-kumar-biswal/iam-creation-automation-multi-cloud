"""
GCP Test Fixtures for IAM Automation Testing
Provides mock GCP resources and credentials for testing
"""

import pytest
from unittest.mock import Mock, patch
from google.oauth2 import service_account


@pytest.fixture
def gcp_credentials():
    """Mock GCP credentials for testing"""
    import os
    os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = '/tmp/fake-service-account.json'
    os.environ['GOOGLE_CLOUD_PROJECT'] = 'test-project-123'
    
    # Mock the service account credentials
    with patch('google.oauth2.service_account.Credentials.from_service_account_file') as mock_creds:
        mock_creds.return_value = Mock()
        yield mock_creds


@pytest.fixture
def sample_gcp_service_account():
    """Sample GCP service account configuration"""
    return {
        'account_id': 'test-service-account',
        'display_name': 'Test Service Account',
        'description': 'Test service account for automation',
        'project': 'test-project-123',
        'keys': [
            {
                'key_algorithm': 'KEY_ALG_RSA_2048',
                'private_key_type': 'TYPE_GOOGLE_CREDENTIALS_FILE'
            }
        ],
        'iam_bindings': [
            {
                'role': 'roles/storage.objectViewer',
                'members': ['serviceAccount:test-service-account@test-project-123.iam.gserviceaccount.com']
            }
        ],
        'labels': {
            'environment': 'test',
            'team': 'automation',
            'managed-by': 'terraform'
        }
    }


@pytest.fixture
def sample_gcp_custom_role():
    """Sample GCP custom role configuration"""
    return {
        'role_id': 'testCustomRole',
        'title': 'Test Custom Role',
        'description': 'Custom role for testing IAM automation',
        'stage': 'GA',
        'included_permissions': [
            'storage.objects.get',
            'storage.objects.list',
            'storage.objects.create',
            'storage.objects.delete',
            'logging.logEntries.create',
            'monitoring.metricDescriptors.get',
            'monitoring.metricDescriptors.list'
        ],
        'excluded_permissions': [
            'storage.buckets.delete',
            'storage.buckets.setIamPolicy'
        ],
        'project': 'test-project-123'
    }


@pytest.fixture
def sample_gcp_organization_custom_role():
    """Sample GCP organization-level custom role"""
    return {
        'role_id': 'testOrgCustomRole',
        'title': 'Test Organization Custom Role',
        'description': 'Organization-level custom role for testing',
        'stage': 'GA',
        'included_permissions': [
            'resourcemanager.projects.get',
            'resourcemanager.projects.list',
            'resourcemanager.folders.get',
            'resourcemanager.folders.list',
            'billing.accounts.get',
            'billing.accounts.list'
        ],
        'organization_id': '123456789012'
    }


@pytest.fixture
def sample_gcp_iam_bindings():
    """Sample GCP IAM policy bindings"""
    return {
        'project_bindings': [
            {
                'role': 'roles/storage.admin',
                'members': [
                    'serviceAccount:storage-admin@test-project-123.iam.gserviceaccount.com',
                    'user:admin@company.com'
                ],
                'condition': None
            },
            {
                'role': 'roles/storage.objectViewer',
                'members': [
                    'serviceAccount:readonly@test-project-123.iam.gserviceaccount.com',
                    'group:developers@company.com'
                ],
                'condition': {
                    'title': 'Time-based access',
                    'description': 'Access only during business hours',
                    'expression': 'request.time.getHours() >= 9 && request.time.getHours() <= 17'
                }
            }
        ],
        'organization_bindings': [
            {
                'role': 'roles/resourcemanager.organizationViewer',
                'members': [
                    'group:security-team@company.com',
                    'user:security-admin@company.com'
                ]
            }
        ],
        'folder_bindings': [
            {
                'role': 'roles/resourcemanager.folderViewer',
                'members': [
                    'group:project-managers@company.com'
                ]
            }
        ]
    }


@pytest.fixture
def sample_gcp_organization_policies():
    """Sample GCP organization policies"""
    return {
        'compute_disable_serial_port_access': {
            'constraint': 'constraints/compute.disableSerialPortAccess',
            'boolean_policy': {
                'enforced': True
            }
        },
        'compute_require_os_login': {
            'constraint': 'constraints/compute.requireOsLogin',
            'boolean_policy': {
                'enforced': True
            }
        },
        'storage_uniform_bucket_level_access': {
            'constraint': 'constraints/storage.uniformBucketLevelAccess',
            'boolean_policy': {
                'enforced': True
            }
        },
        'iam_allowed_policy_member_domains': {
            'constraint': 'constraints/iam.allowedPolicyMemberDomains',
            'list_policy': {
                'allowed_values': [
                    'company.com',
                    'contractors.company.com'
                ]
            }
        },
        'compute_allowed_regions': {
            'constraint': 'constraints/compute.allowedRegions',
            'list_policy': {
                'allowed_values': [
                    'us-central1',
                    'us-east1',
                    'us-west1',
                    'europe-west1'
                ]
            }
        }
    }


@pytest.fixture
def gcp_project_structure():
    """Sample GCP project structure for testing"""
    return {
        'organization_id': '123456789012',
        'billing_account': '000000-111111-222222',
        'folders': [
            {
                'name': 'Production',
                'display_name': 'Production Environment',
                'projects': [
                    {'id': 'prod-app-001', 'name': 'Production App 001'},
                    {'id': 'prod-app-002', 'name': 'Production App 002'},
                    {'id': 'prod-data-001', 'name': 'Production Data 001'}
                ]
            },
            {
                'name': 'Staging',
                'display_name': 'Staging Environment',
                'projects': [
                    {'id': 'staging-app-001', 'name': 'Staging App 001'},
                    {'id': 'staging-data-001', 'name': 'Staging Data 001'}
                ]
            },
            {
                'name': 'Development',
                'display_name': 'Development Environment',
                'projects': [
                    {'id': 'dev-app-001', 'name': 'Development App 001'},
                    {'id': 'dev-app-002', 'name': 'Development App 002'},
                    {'id': 'dev-playground', 'name': 'Development Playground'}
                ]
            }
        ]
    }


@pytest.fixture
def gcp_security_config():
    """Sample GCP security configuration for testing"""
    return {
        'audit_logging': {
            'enabled': True,
            'log_types': [
                'ADMIN_READ',
                'DATA_READ',
                'DATA_WRITE'
            ],
            'exempted_members': []
        },
        'binary_authorization': {
            'enabled': True,
            'evaluation_mode': 'REQUIRE_ATTESTATION',
            'default_admission_rule': {
                'require_attestations_by': [
                    'projects/test-project-123/attestors/prod-attestor'
                ]
            }
        },
        'vpc_service_controls': {
            'enabled': True,
            'restricted_services': [
                'storage.googleapis.com',
                'bigquery.googleapis.com',
                'pubsub.googleapis.com'
            ]
        },
        'security_center_settings': {
            'enabled': True,
            'findings_notification': True,
            'asset_discovery': True
        }
    }


@pytest.fixture
def gcp_monitoring_config():
    """Sample GCP monitoring configuration for testing"""
    return {
        'cloud_logging': {
            'enabled': True,
            'retention_days': 365,
            'log_sinks': [
                {
                    'name': 'audit-logs-sink',
                    'destination': 'storage.googleapis.com/audit-logs-bucket',
                    'filter': 'protoPayload.serviceName="cloudresourcemanager.googleapis.com"'
                },
                {
                    'name': 'security-logs-sink',
                    'destination': 'bigquery.googleapis.com/projects/test-project-123/datasets/security_logs',
                    'filter': 'protoPayload.serviceName="iam.googleapis.com" OR protoPayload.serviceName="iap.googleapis.com"'
                }
            ]
        },
        'cloud_monitoring': {
            'enabled': True,
            'notification_channels': [
                {
                    'type': 'email',
                    'display_name': 'Security Team Email',
                    'labels': {
                        'email_address': 'security-team@company.com'
                    }
                },
                {
                    'type': 'slack',
                    'display_name': 'Operations Slack',
                    'labels': {
                        'channel_name': '#ops-alerts',
                        'url': 'https://hooks.slack.com/services/...'
                    }
                }
            ],
            'alert_policies': [
                {
                    'display_name': 'High IAM Activity',
                    'conditions': [
                        {
                            'display_name': 'IAM policy changes',
                            'condition_threshold': {
                                'filter': 'resource.type="project" AND protoPayload.serviceName="cloudresourcemanager.googleapis.com"',
                                'comparison': 'COMPARISON_GREATER_THAN',
                                'threshold_value': 10,
                                'duration': '300s'
                            }
                        }
                    ]
                }
            ]
        }
    }


@pytest.fixture
def mock_gcp_iam_client():
    """Mock GCP IAM client for testing"""
    with patch('google.cloud.iam.Client') as mock_client:
        # Mock service account operations
        mock_service_account = Mock()
        mock_service_account.name = 'projects/test-project-123/serviceAccounts/test-sa@test-project-123.iam.gserviceaccount.com'
        mock_service_account.email = 'test-sa@test-project-123.iam.gserviceaccount.com'
        mock_service_account.display_name = 'Test Service Account'
        
        mock_client.return_value.create_service_account.return_value = mock_service_account
        mock_client.return_value.get_service_account.return_value = mock_service_account
        mock_client.return_value.list_service_accounts.return_value = [mock_service_account]
        
        # Mock custom role operations
        mock_role = Mock()
        mock_role.name = 'projects/test-project-123/roles/testCustomRole'
        mock_role.title = 'Test Custom Role'
        mock_role.included_permissions = ['storage.objects.get', 'storage.objects.list']
        
        mock_client.return_value.create_role.return_value = mock_role
        mock_client.return_value.get_role.return_value = mock_role
        mock_client.return_value.list_roles.return_value = [mock_role]
        
        yield mock_client


@pytest.fixture
def mock_gcp_resource_manager_client():
    """Mock GCP Resource Manager client for testing"""
    with patch('google.cloud.resource_manager.Client') as mock_client:
        # Mock project operations
        mock_project = Mock()
        mock_project.project_id = 'test-project-123'
        mock_project.name = 'Test Project 123'
        mock_project.lifecycle_state = 'ACTIVE'
        
        mock_client.return_value.list_projects.return_value = [mock_project]
        mock_client.return_value.fetch_project.return_value = mock_project
        
        # Mock IAM policy operations
        mock_policy = Mock()
        mock_policy.bindings = [
            {
                'role': 'roles/storage.admin',
                'members': ['serviceAccount:test-sa@test-project-123.iam.gserviceaccount.com']
            }
        ]
        
        mock_client.return_value.get_iam_policy.return_value = mock_policy
        mock_client.return_value.set_iam_policy.return_value = mock_policy
        
        yield mock_client


@pytest.fixture
def populated_gcp_environment(mock_gcp_iam_client, mock_gcp_resource_manager_client, 
                             sample_gcp_service_account, sample_gcp_custom_role, 
                             sample_gcp_iam_bindings):
    """Create a populated GCP environment for integration testing"""
    return {
        'service_account': sample_gcp_service_account,
        'custom_role': sample_gcp_custom_role,
        'iam_bindings': sample_gcp_iam_bindings,
        'project_id': 'test-project-123',
        'organization_id': '123456789012'
    }
