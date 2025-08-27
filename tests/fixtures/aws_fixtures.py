"""
AWS Test Fixtures for IAM Automation Testing
Provides mock AWS resources and credentials for testing
"""

import boto3
import pytest
from moto import mock_iam, mock_organizations, mock_sts, mock_s3
from unittest.mock import patch, Mock


@pytest.fixture
def aws_credentials():
    """Mocked AWS Credentials for testing"""
    import os
    os.environ['AWS_ACCESS_KEY_ID'] = 'testing'
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'testing'
    os.environ['AWS_SECURITY_TOKEN'] = 'testing'
    os.environ['AWS_SESSION_TOKEN'] = 'testing'
    os.environ['AWS_DEFAULT_REGION'] = 'us-east-1'


@pytest.fixture
@mock_iam
def iam_client(aws_credentials):
    """Mock IAM client for testing"""
    return boto3.client('iam', region_name='us-east-1')


@pytest.fixture
@mock_organizations
def organizations_client(aws_credentials):
    """Mock Organizations client for testing"""
    return boto3.client('organizations', region_name='us-east-1')


@pytest.fixture
@mock_sts
def sts_client(aws_credentials):
    """Mock STS client for testing"""
    return boto3.client('sts', region_name='us-east-1')


@pytest.fixture
def sample_aws_user():
    """Sample AWS IAM user configuration"""
    return {
        'name': 'test-user-001',
        'path': '/test-users/',
        'permissions_boundary_arn': 'arn:aws:iam::123456789012:policy/TestPermissionsBoundary',
        'force_destroy': True,
        'groups': ['developers', 'test-group'],
        'policies': ['TestPolicy'],
        'tags': {
            'Environment': 'test',
            'Team': 'automation',
            'ManagedBy': 'terraform',
            'CostCenter': 'TEST-001'
        },
        'access_keys': [
            {
                'status': 'Active',
                'pgp_key': None
            }
        ],
        'login_profile': {
            'create_login_profile': True,
            'password_reset_required': True,
            'password_length': 16
        }
    }


@pytest.fixture
def sample_aws_role():
    """Sample AWS IAM role configuration"""
    return {
        'name': 'test-application-role',
        'path': '/test-roles/',
        'description': 'Test role for application workloads',
        'max_session_duration': 3600,
        'permissions_boundary_arn': 'arn:aws:iam::123456789012:policy/TestPermissionsBoundary',
        'assume_role_policy': {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                },
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }
            ]
        },
        'policies': ['TestApplicationPolicy'],
        'tags': {
            'RoleType': 'Application',
            'Environment': 'test',
            'Workload': 'WebApplication'
        }
    }


@pytest.fixture
def sample_aws_policy():
    """Sample AWS IAM policy configuration"""
    return {
        'name': 'TestApplicationPolicy',
        'path': '/test-policies/',
        'description': 'Test policy for application access',
        'policy_document': {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:PutObject",
                        "s3:DeleteObject"
                    ],
                    "Resource": [
                        "arn:aws:s3:::test-bucket/*"
                    ]
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "dynamodb:GetItem",
                        "dynamodb:PutItem",
                        "dynamodb:UpdateItem",
                        "dynamodb:DeleteItem",
                        "dynamodb:Query",
                        "dynamodb:Scan"
                    ],
                    "Resource": [
                        "arn:aws:dynamodb:*:*:table/test-*"
                    ]
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents"
                    ],
                    "Resource": "*"
                }
            ]
        },
        'tags': {
            'PolicyType': 'Application',
            'Environment': 'test',
            'AccessLevel': 'Limited'
        }
    }


@pytest.fixture
def sample_aws_group():
    """Sample AWS IAM group configuration"""
    return {
        'name': 'test-developers',
        'path': '/test-groups/',
        'policies': [
            'arn:aws:iam::aws:policy/PowerUserAccess'
        ],
        'inline_policies': [
            {
                'name': 'TestDeveloperRestrictions',
                'policy': {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Deny",
                            "Action": [
                                "iam:*",
                                "organizations:*",
                                "account:*"
                            ],
                            "Resource": "*"
                        }
                    ]
                }
            }
        ],
        'tags': {
            'GroupType': 'Development',
            'AccessLevel': 'PowerUser',
            'Environment': 'test'
        }
    }


@pytest.fixture
def sample_cross_account_role():
    """Sample cross-account IAM role configuration"""
    return {
        'name': 'test-cross-account-role',
        'path': '/cross-account-roles/',
        'description': 'Test role for cross-account access',
        'max_session_duration': 1800,
        'assume_role_policy': {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": [
                            "arn:aws:iam::111111111111:root",
                            "arn:aws:iam::222222222222:root"
                        ]
                    },
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringEquals": {"sts:ExternalId": "test-external-id-123"},
                        "Bool": {"aws:MultiFactorAuthPresent": "true"}
                    }
                }
            ]
        },
        'policies': ['TestCrossAccountPolicy'],
        'tags': {
            'RoleType': 'CrossAccount',
            'AccessType': 'Federated',
            'SecurityLevel': 'High'
        }
    }


@pytest.fixture
def aws_organization_structure():
    """Sample AWS Organizations structure for testing"""
    return {
        'management_account_id': '123456789012',
        'organization_id': 'o-1234567890',
        'organizational_units': [
            {
                'name': 'Production',
                'accounts': [
                    {'id': '111111111111', 'name': 'prod-account-001', 'email': 'prod-001@company.com'},
                    {'id': '111111111112', 'name': 'prod-account-002', 'email': 'prod-002@company.com'}
                ]
            },
            {
                'name': 'Staging',
                'accounts': [
                    {'id': '222222222221', 'name': 'staging-account-001', 'email': 'staging-001@company.com'},
                    {'id': '222222222222', 'name': 'staging-account-002', 'email': 'staging-002@company.com'}
                ]
            },
            {
                'name': 'Development',
                'accounts': [
                    {'id': '333333333331', 'name': 'dev-account-001', 'email': 'dev-001@company.com'},
                    {'id': '333333333332', 'name': 'dev-account-002', 'email': 'dev-002@company.com'}
                ]
            }
        ]
    }


@pytest.fixture
def aws_security_config():
    """Sample AWS security configuration for testing"""
    return {
        'account_password_policy': {
            'minimum_password_length': 14,
            'require_lowercase_characters': True,
            'require_numbers': True,
            'require_uppercase_characters': True,
            'require_symbols': True,
            'allow_users_to_change_password': True,
            'hard_expiry': False,
            'max_password_age': 90,
            'password_reuse_prevention': 24
        },
        'mfa_enforcement': True,
        'root_access_keys_disabled': True,
        'unused_credentials_disabled': True,
        'access_analyzer': {
            'enabled': True,
            'name': 'test-access-analyzer',
            'type': 'ACCOUNT'
        }
    }


@pytest.fixture
def aws_monitoring_config():
    """Sample AWS monitoring configuration for testing"""
    return {
        'cloudtrail': {
            'enabled': True,
            'name': 'test-cloudtrail',
            's3_bucket_name': 'test-cloudtrail-logs',
            'include_global_service_events': True,
            'is_multi_region_trail': True,
            'enable_log_file_validation': True
        },
        'config': {
            'enabled': True,
            'configuration_recorder_name': 'test-config-recorder',
            'delivery_channel_name': 'test-config-delivery',
            's3_bucket_name': 'test-config-logs'
        },
        'guardduty': {
            'enabled': True,
            'finding_publishing_frequency': 'FIFTEEN_MINUTES'
        }
    }


@pytest.fixture
@mock_iam
def populated_iam_environment(iam_client, sample_aws_user, sample_aws_role, sample_aws_policy, sample_aws_group):
    """Create a populated IAM environment for integration testing"""
    # Create user
    iam_client.create_user(
        UserName=sample_aws_user['name'],
        Path=sample_aws_user['path'],
        Tags=[{'Key': k, 'Value': v} for k, v in sample_aws_user['tags'].items()]
    )
    
    # Create role
    import json
    iam_client.create_role(
        RoleName=sample_aws_role['name'],
        Path=sample_aws_role['path'],
        AssumeRolePolicyDocument=json.dumps(sample_aws_role['assume_role_policy']),
        Description=sample_aws_role['description'],
        MaxSessionDuration=sample_aws_role['max_session_duration'],
        Tags=[{'Key': k, 'Value': v} for k, v in sample_aws_role['tags'].items()]
    )
    
    # Create policy
    policy_response = iam_client.create_policy(
        PolicyName=sample_aws_policy['name'],
        Path=sample_aws_policy['path'],
        PolicyDocument=json.dumps(sample_aws_policy['policy_document']),
        Description=sample_aws_policy['description'],
        Tags=[{'Key': k, 'Value': v} for k, v in sample_aws_policy['tags'].items()]
    )
    
    # Create group
    iam_client.create_group(
        GroupName=sample_aws_group['name'],
        Path=sample_aws_group['path']
    )
    
    # Add user to group
    iam_client.add_user_to_group(
        GroupName=sample_aws_group['name'],
        UserName=sample_aws_user['name']
    )
    
    # Attach policy to user
    iam_client.attach_user_policy(
        UserName=sample_aws_user['name'],
        PolicyArn=policy_response['Policy']['Arn']
    )
    
    return {
        'user': sample_aws_user,
        'role': sample_aws_role,
        'policy': sample_aws_policy,
        'group': sample_aws_group,
        'policy_arn': policy_response['Policy']['Arn']
    }
