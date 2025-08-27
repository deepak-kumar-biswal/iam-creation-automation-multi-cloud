"""
Azure Test Fixtures for IAM Automation Testing
Provides mock Azure resources and credentials for testing
"""

import pytest
from unittest.mock import Mock, patch
from datetime import datetime, timedelta


@pytest.fixture
def azure_credentials():
    """Mock Azure credentials for testing"""
    import os
    os.environ['AZURE_CLIENT_ID'] = 'test-client-id'
    os.environ['AZURE_CLIENT_SECRET'] = 'test-client-secret'
    os.environ['AZURE_TENANT_ID'] = 'test-tenant-id'
    os.environ['AZURE_SUBSCRIPTION_ID'] = 'test-subscription-id'


@pytest.fixture
def sample_azure_ad_user():
    """Sample Azure AD user configuration"""
    return {
        'user_principal_name': 'testuser@contoso.com',
        'display_name': 'Test User',
        'mail_nickname': 'testuser',
        'password': 'TempPassword123!',
        'force_password_change': True,
        'given_name': 'Test',
        'surname': 'User',
        'job_title': 'Software Engineer',
        'department': 'Engineering',
        'company_name': 'Contoso Corporation',
        'office_location': 'Seattle',
        'mobile_phone': '+1-555-0123',
        'business_phones': ['+1-555-0124'],
        'account_enabled': True,
        'password_never_expires': False,
        'password_expire_days': 90,
        'show_in_address_list': True,
        'mfa_enabled': True,
        'privileged_authentication': False,
        'groups': ['Engineers', 'All-Employees'],
        'roles': ['User'],
        'administrative_units': [],
        'licenses': ['Microsoft 365 E5'],
        'tags': {
            'Department': 'Engineering',
            'CostCenter': 'ENG-001',
            'Manager': 'manager@contoso.com'
        }
    }


@pytest.fixture
def sample_azure_ad_group():
    """Sample Azure AD group configuration"""
    return {
        'display_name': 'Test Engineers Group',
        'description': 'Group for test engineers',
        'mail_enabled': False,
        'security_enabled': True,
        'mail_nickname': 'test-engineers',
        'group_types': [],
        'members': ['testuser@contoso.com', 'engineer1@contoso.com'],
        'owners': ['manager@contoso.com'],
        'assignable_to_role': False,
        'roles': [],
        'expiration_policy': {
            'alternate_notification_emails': ['admin@contoso.com'],
            'group_lifetime_in_days': 365,
            'notification_before_expiry': 30
        },
        'tags': {
            'GroupType': 'Engineering',
            'Purpose': 'Testing'
        }
    }


@pytest.fixture
def sample_service_principal():
    """Sample Azure AD service principal configuration"""
    return {
        'display_name': 'Test Application Service Principal',
        'description': 'Service principal for test application',
        'sign_in_audience': 'AzureADMyOrg',
        'identifier_uris': ['https://contoso.com/test-app'],
        'homepage_url': 'https://contoso.com',
        'logout_url': 'https://contoso.com/logout',
        'privacy_statement_url': 'https://contoso.com/privacy',
        'support_url': 'https://contoso.com/support',
        'terms_of_service_url': 'https://contoso.com/terms',
        'certificate_credentials': [
            {
                'display_name': 'Test Certificate',
                'type': 'AsymmetricX509Cert',
                'value': 'base64-encoded-certificate',
                'end_date': (datetime.now() + timedelta(days=365)).isoformat(),
                'start_date': datetime.now().isoformat()
            }
        ],
        'password_credentials': [
            {
                'display_name': 'Test Secret',
                'end_date': (datetime.now() + timedelta(days=90)).isoformat(),
                'start_date': datetime.now().isoformat()
            }
        ],
        'required_resource_accesses': [
            {
                'resource_app_id': '00000003-0000-0000-c000-000000000000',  # Microsoft Graph
                'resource_accesses': [
                    {
                        'id': '37f7f235-527c-4136-accd-4a02d197296e',  # User.Read.All
                        'type': 'Scope'
                    }
                ]
            }
        ],
        'roles': ['Contributor'],
        'account_enabled': True,
        'tags': {
            'ApplicationType': 'WebApi',
            'Environment': 'Test'
        }
    }


@pytest.fixture
def sample_custom_role():
    """Sample Azure custom RBAC role configuration"""
    return {
        'name': 'Test Custom Role',
        'description': 'Custom role for testing IAM automation',
        'scope': '/subscriptions/12345678-1234-1234-1234-123456789012',
        'permissions': [
            {
                'actions': [
                    'Microsoft.Storage/storageAccounts/read',
                    'Microsoft.Storage/storageAccounts/blobServices/containers/read',
                    'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read'
                ],
                'not_actions': [
                    'Microsoft.Storage/storageAccounts/delete'
                ],
                'data_actions': [
                    'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read'
                ],
                'not_data_actions': []
            }
        ],
        'assignable_scopes': [
            '/subscriptions/12345678-1234-1234-1234-123456789012',
            '/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/test-rg'
        ],
        'tags': {
            'RoleType': 'Custom',
            'Department': 'IT'
        }
    }


@pytest.fixture
def sample_role_assignments():
    """Sample Azure RBAC role assignments"""
    return [
        {
            'scope': '/subscriptions/12345678-1234-1234-1234-123456789012',
            'role_definition_name': 'Reader',
            'principal_id': 'user-object-id-123',
            'principal_type': 'User',
            'condition': None,
            'condition_version': '2.0',
            'tags': {
                'AssignmentType': 'Permanent',
                'Justification': 'Standard read access'
            }
        },
        {
            'scope': '/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/test-rg',
            'role_definition_name': 'Contributor',
            'principal_id': 'sp-object-id-456',
            'principal_type': 'ServicePrincipal',
            'condition': 'request.time.getHours() >= 9 && request.time.getHours() <= 17',
            'condition_version': '2.0',
            'tags': {
                'AssignmentType': 'Conditional',
                'Justification': 'Business hours only access'
            }
        }
    ]


@pytest.fixture
def sample_administrative_unit():
    """Sample Azure AD administrative unit configuration"""
    return {
        'display_name': 'Test Administrative Unit',
        'description': 'Administrative unit for testing',
        'visibility': 'Public',
        'members': ['testuser@contoso.com'],
        'scoped_members': [
            {
                'id': 'user-object-id-123',
                'type': 'User',
                'role': 'User Administrator'
            }
        ],
        'tags': {
            'UnitType': 'Testing',
            'Department': 'IT'
        }
    }


@pytest.fixture
def sample_conditional_access_policy():
    """Sample Azure AD conditional access policy"""
    return {
        'display_name': 'Test Conditional Access Policy',
        'state': 'enabled',
        'conditions': {
            'client_app_types': ['all'],
            'sign_in_risk_levels': ['high', 'medium'],
            'user_risk_levels': ['high'],
            'applications': {
                'included_applications': ['All'],
                'excluded_applications': [],
                'included_user_actions': []
            },
            'users': {
                'included_users': ['All'],
                'excluded_users': ['emergency-access@contoso.com'],
                'included_groups': [],
                'excluded_groups': ['Emergency Access Group'],
                'included_roles': [],
                'excluded_roles': ['Global Administrator']
            },
            'platforms': {
                'included_platforms': ['all'],
                'excluded_platforms': []
            },
            'locations': {
                'included_locations': ['All'],
                'excluded_locations': ['Trusted Network Locations']
            },
            'devices': {
                'included_devices': ['All'],
                'excluded_devices': []
            }
        },
        'grant_controls': {
            'operator': 'OR',
            'built_in_controls': ['mfa', 'compliantDevice'],
            'custom_authentication_factors': [],
            'terms_of_use': []
        },
        'session_controls': {
            'application_enforced_restrictions': {
                'is_enabled': True
            },
            'cloud_app_security': {
                'cloud_app_security_type': 'MonitorOnly',
                'is_enabled': True
            },
            'sign_in_frequency': {
                'is_enabled': True,
                'type': 'Hours',
                'value': 8
            }
        },
        'tags': {
            'PolicyType': 'Security',
            'Environment': 'Production'
        }
    }


@pytest.fixture
def sample_azure_policies():
    """Sample Azure Policy assignments"""
    return [
        {
            'name': 'test-storage-encryption-policy',
            'policy_definition_id': '/providers/Microsoft.Authorization/policyDefinitions/404c3081-a854-4457-ae30-26a93ef643f9',
            'scope': '/subscriptions/12345678-1234-1234-1234-123456789012',
            'description': 'Ensure storage accounts use encryption',
            'display_name': 'Storage Account Encryption Required',
            'enforcement_mode': 'Default',
            'not_scopes': [],
            'parameters': '{"requiredEncryption": {"value": "AES256"}}',
            'location': 'East US',
            'non_compliance_message': [
                {
                    'content': 'Storage account must use AES256 encryption',
                    'policy_definition_reference_id': None
                }
            ],
            'tags': {
                'PolicyCategory': 'Security',
                'Compliance': 'Required'
            }
        }
    ]


@pytest.fixture
def sample_pim_eligible_assignments():
    """Sample PIM eligible role assignments"""
    return [
        {
            'principal_id': 'user-object-id-123',
            'role_definition_id': '/subscriptions/.../providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635',
            'scope': '/subscriptions/12345678-1234-1234-1234-123456789012',
            'schedule': {
                'start_date_time': datetime.now().isoformat(),
                'expiration': {
                    'duration_hours': 8,
                    'type': 'AfterDuration'
                }
            },
            'justification': 'Elevated access for maintenance',
            'ticket_info': {
                'ticket_number': 'INC-001234',
                'ticket_system': 'ServiceNow'
            },
            'tags': {
                'AccessType': 'JustInTime',
                'Purpose': 'Maintenance'
            }
        }
    ]


@pytest.fixture
def azure_tenant_structure():
    """Sample Azure tenant structure for testing"""
    return {
        'tenant_id': '12345678-1234-1234-1234-123456789012',
        'management_groups': [
            {
                'name': 'Production',
                'subscriptions': [
                    {'id': '11111111-1111-1111-1111-111111111111', 'name': 'Prod Subscription 1'},
                    {'id': '11111111-1111-1111-1111-111111111112', 'name': 'Prod Subscription 2'}
                ]
            },
            {
                'name': 'Staging',
                'subscriptions': [
                    {'id': '22222222-2222-2222-2222-222222222221', 'name': 'Staging Subscription 1'}
                ]
            },
            {
                'name': 'Development',
                'subscriptions': [
                    {'id': '33333333-3333-3333-3333-333333333331', 'name': 'Dev Subscription 1'},
                    {'id': '33333333-3333-3333-3333-333333333332', 'name': 'Dev Subscription 2'}
                ]
            }
        ]
    }


@pytest.fixture
def azure_security_config():
    """Sample Azure security configuration"""
    return {
        'security_defaults_enabled': True,
        'password_policy': {
            'minimum_length': 12,
            'require_uppercase': True,
            'require_lowercase': True,
            'require_numbers': True,
            'require_special_characters': True,
            'password_history_count': 24,
            'password_age_days': 90,
            'lockout_threshold': 5,
            'lockout_duration_minutes': 30
        },
        'mfa_enforcement': True,
        'conditional_access_enabled': True,
        'identity_protection_enabled': True,
        'privileged_identity_management_enabled': True
    }


@pytest.fixture
def mock_azure_ad_client():
    """Mock Azure AD client for testing"""
    with patch('azure.identity.DefaultAzureCredential'), \
         patch('azure.mgmt.authorization.AuthorizationManagementClient') as mock_auth_client:
        
        # Mock user creation
        mock_user = Mock()
        mock_user.object_id = 'user-object-id-123'
        mock_user.user_principal_name = 'testuser@contoso.com'
        mock_user.display_name = 'Test User'
        
        # Mock service principal creation
        mock_sp = Mock()
        mock_sp.object_id = 'sp-object-id-456'
        mock_sp.application_id = 'app-id-789'
        mock_sp.display_name = 'Test Service Principal'
        
        # Mock role assignment
        mock_role_assignment = Mock()
        mock_role_assignment.id = 'role-assignment-id-123'
        mock_role_assignment.scope = '/subscriptions/12345678-1234-1234-1234-123456789012'
        
        mock_auth_client.return_value.role_assignments.create.return_value = mock_role_assignment
        
        yield {
            'auth_client': mock_auth_client,
            'mock_user': mock_user,
            'mock_sp': mock_sp,
            'mock_role_assignment': mock_role_assignment
        }


@pytest.fixture
def populated_azure_environment(mock_azure_ad_client, sample_azure_ad_user, 
                               sample_service_principal, sample_role_assignments):
    """Create a populated Azure environment for integration testing"""
    return {
        'user': sample_azure_ad_user,
        'service_principal': sample_service_principal,
        'role_assignments': sample_role_assignments,
        'tenant_id': '12345678-1234-1234-1234-123456789012',
        'subscription_id': '12345678-1234-1234-1234-123456789012'
    }
