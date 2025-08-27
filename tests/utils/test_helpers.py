"""
Test Helper Utilities for IAM Automation Testing
Provides common utilities and helper functions for testing
"""

import asyncio
import json
import os
import tempfile
import time
import yaml
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from unittest.mock import Mock, patch


class TestEnvironmentManager:
    """Manages test environments and cleanup"""
    
    def __init__(self):
        self.created_resources = []
        self.temp_files = []
    
    def add_resource(self, resource_type: str, resource_id: str, cleanup_func=None):
        """Add a resource to track for cleanup"""
        self.created_resources.append({
            'type': resource_type,
            'id': resource_id,
            'cleanup': cleanup_func,
            'created_at': datetime.now()
        })
    
    def cleanup_all(self):
        """Clean up all tracked resources"""
        for resource in reversed(self.created_resources):
            try:
                if resource['cleanup']:
                    resource['cleanup']()
                print(f"Cleaned up {resource['type']}: {resource['id']}")
            except Exception as e:
                print(f"Failed to cleanup {resource['type']} {resource['id']}: {e}")
        
        # Clean up temp files
        for temp_file in self.temp_files:
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
            except Exception as e:
                print(f"Failed to cleanup temp file {temp_file}: {e}")
        
        self.created_resources = []
        self.temp_files = []


class ConfigGenerator:
    """Generates test configuration files and data"""
    
    @staticmethod
    def create_terraform_tfvars(config: Dict[str, Any]) -> str:
        """Create a terraform.tfvars file from configuration"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tfvars', delete=False) as f:
            for key, value in config.items():
                if isinstance(value, str):
                    f.write(f'{key} = "{value}"\n')
                elif isinstance(value, bool):
                    f.write(f'{key} = {str(value).lower()}\n')
                elif isinstance(value, (int, float)):
                    f.write(f'{key} = {value}\n')
                elif isinstance(value, list):
                    f.write(f'{key} = {json.dumps(value)}\n')
                elif isinstance(value, dict):
                    f.write(f'{key} = {json.dumps(value)}\n')
            return f.name
    
    @staticmethod
    def create_yaml_config(config: Dict[str, Any]) -> str:
        """Create a YAML configuration file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(config, f, default_flow_style=False)
            return f.name
    
    @staticmethod
    def create_json_config(config: Dict[str, Any]) -> str:
        """Create a JSON configuration file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config, f, indent=2)
            return f.name


class MockCloudClients:
    """Factory for creating mock cloud clients"""
    
    @staticmethod
    def create_aws_client(service_name: str):
        """Create a mock AWS client"""
        mock_client = Mock()
        
        if service_name == 'iam':
            # Mock IAM operations
            mock_client.create_user.return_value = {
                'User': {
                    'UserName': 'test-user',
                    'UserId': 'AIDACKCEVSQ6C2EXAMPLE',
                    'Arn': 'arn:aws:iam::123456789012:user/test-user',
                    'Path': '/test-users/',
                    'CreateDate': datetime.now()
                }
            }
            
            mock_client.create_role.return_value = {
                'Role': {
                    'RoleName': 'test-role',
                    'RoleId': 'AROA12345678901234567',
                    'Arn': 'arn:aws:iam::123456789012:role/test-role',
                    'Path': '/test-roles/',
                    'CreateDate': datetime.now(),
                    'MaxSessionDuration': 3600
                }
            }
            
            mock_client.create_policy.return_value = {
                'Policy': {
                    'PolicyName': 'test-policy',
                    'PolicyId': 'ANPA12345678901234567',
                    'Arn': 'arn:aws:iam::123456789012:policy/test-policy',
                    'Path': '/test-policies/',
                    'CreateDate': datetime.now()
                }
            }
        
        return mock_client
    
    @staticmethod
    def create_gcp_client(service_name: str):
        """Create a mock GCP client"""
        mock_client = Mock()
        
        if service_name == 'iam':
            # Mock service account operations
            mock_sa = Mock()
            mock_sa.name = 'projects/test-project/serviceAccounts/test-sa@test-project.iam.gserviceaccount.com'
            mock_sa.email = 'test-sa@test-project.iam.gserviceaccount.com'
            mock_sa.display_name = 'Test Service Account'
            
            mock_client.create_service_account.return_value = mock_sa
            mock_client.get_service_account.return_value = mock_sa
            
            # Mock role operations
            mock_role = Mock()
            mock_role.name = 'projects/test-project/roles/testRole'
            mock_role.title = 'Test Role'
            mock_role.included_permissions = ['storage.objects.get']
            
            mock_client.create_role.return_value = mock_role
            mock_client.get_role.return_value = mock_role
        
        return mock_client
    
    @staticmethod
    def create_azure_client(service_name: str):
        """Create a mock Azure client"""
        mock_client = Mock()
        
        if service_name == 'authorization':
            # Mock role assignment operations
            mock_assignment = Mock()
            mock_assignment.id = '/subscriptions/.../roleAssignments/12345678-1234-1234-1234-123456789012'
            mock_assignment.role_definition_id = '/subscriptions/.../roleDefinitions/...'
            mock_assignment.principal_id = 'user-object-id'
            
            mock_client.role_assignments.create.return_value = mock_assignment
        
        return mock_client


class PerformanceMonitor:
    """Monitor performance during tests"""
    
    def __init__(self):
        self.metrics = {}
        self.start_times = {}
    
    def start_timer(self, operation: str):
        """Start timing an operation"""
        self.start_times[operation] = time.time()
    
    def end_timer(self, operation: str) -> float:
        """End timing an operation and return duration"""
        if operation not in self.start_times:
            return 0.0
        
        duration = time.time() - self.start_times[operation]
        
        if operation not in self.metrics:
            self.metrics[operation] = []
        
        self.metrics[operation].append(duration)
        del self.start_times[operation]
        
        return duration
    
    def get_average_time(self, operation: str) -> float:
        """Get average time for an operation"""
        if operation not in self.metrics or not self.metrics[operation]:
            return 0.0
        
        return sum(self.metrics[operation]) / len(self.metrics[operation])
    
    def get_max_time(self, operation: str) -> float:
        """Get maximum time for an operation"""
        if operation not in self.metrics or not self.metrics[operation]:
            return 0.0
        
        return max(self.metrics[operation])
    
    def reset_metrics(self):
        """Reset all metrics"""
        self.metrics = {}
        self.start_times = {}


class ValidationHelper:
    """Helper functions for validation and assertions"""
    
    @staticmethod
    def validate_aws_arn(arn: str) -> bool:
        """Validate AWS ARN format"""
        parts = arn.split(':')
        return (
            len(parts) == 6 and
            parts[0] == 'arn' and
            parts[1] in ['aws', 'aws-cn', 'aws-us-gov'] and
            parts[2] in ['iam', 's3', 'lambda', 'ec2', 'dynamodb'] and
            parts[3] != '' and  # region (can be empty for global services)
            parts[4] != '' and  # account id
            parts[5] != ''      # resource
        )
    
    @staticmethod
    def validate_gcp_resource_name(name: str, resource_type: str) -> bool:
        """Validate GCP resource name format"""
        if resource_type == 'service_account':
            return name.endswith('.iam.gserviceaccount.com')
        elif resource_type == 'project':
            return name.startswith('projects/')
        elif resource_type == 'role':
            return name.startswith('projects/') and '/roles/' in name
        
        return False
    
    @staticmethod
    def validate_azure_guid(guid: str) -> bool:
        """Validate Azure GUID format"""
        import re
        pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        return bool(re.match(pattern, guid.lower()))
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email format"""
        import re
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))


class TerraformTestHelper:
    """Helper functions for Terraform testing"""
    
    @staticmethod
    def validate_terraform_syntax(file_path: str) -> bool:
        """Validate Terraform file syntax (simplified check)"""
        if not os.path.exists(file_path):
            return False
        
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Basic syntax checks
        brace_count = content.count('{') - content.count('}')
        bracket_count = content.count('[') - content.count(']')
        
        return brace_count == 0 and bracket_count == 0
    
    @staticmethod
    def extract_terraform_resources(file_path: str) -> List[Dict[str, str]]:
        """Extract resource definitions from Terraform file"""
        resources = []
        
        if not os.path.exists(file_path):
            return resources
        
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Simple regex to find resource blocks
        import re
        pattern = r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{'
        matches = re.findall(pattern, content)
        
        for match in matches:
            resources.append({
                'type': match[0],
                'name': match[1]
            })
        
        return resources


class SecurityTestHelper:
    """Helper functions for security testing"""
    
    @staticmethod
    def check_password_strength(password: str) -> Dict[str, bool]:
        """Check password strength against common requirements"""
        return {
            'length_ok': len(password) >= 12,
            'has_uppercase': any(c.isupper() for c in password),
            'has_lowercase': any(c.islower() for c in password),
            'has_digits': any(c.isdigit() for c in password),
            'has_special': any(not c.isalnum() for c in password)
        }
    
    @staticmethod
    def validate_policy_document(policy: Dict[str, Any]) -> List[str]:
        """Validate IAM policy document structure"""
        issues = []
        
        if 'Version' not in policy:
            issues.append("Missing 'Version' field")
        elif policy['Version'] not in ['2012-10-17', '2008-10-17']:
            issues.append("Invalid policy version")
        
        if 'Statement' not in policy:
            issues.append("Missing 'Statement' field")
        elif not isinstance(policy['Statement'], list):
            issues.append("'Statement' must be a list")
        
        for i, statement in enumerate(policy.get('Statement', [])):
            if 'Effect' not in statement:
                issues.append(f"Statement {i}: Missing 'Effect' field")
            elif statement['Effect'] not in ['Allow', 'Deny']:
                issues.append(f"Statement {i}: Invalid 'Effect' value")
            
            if 'Action' not in statement and 'NotAction' not in statement:
                issues.append(f"Statement {i}: Missing 'Action' or 'NotAction' field")
        
        return issues
    
    @staticmethod
    def check_dangerous_permissions(permissions: List[str]) -> List[str]:
        """Check for dangerous IAM permissions"""
        dangerous = [
            '*:*',
            'iam:*',
            'iam:CreateRole',
            'iam:AttachRolePolicy',
            'iam:PutRolePolicy',
            'iam:PassRole',
            'sts:AssumeRole'
        ]
        
        found_dangerous = []
        for permission in permissions:
            if permission in dangerous or permission.endswith(':*'):
                found_dangerous.append(permission)
        
        return found_dangerous


class AsyncTestHelper:
    """Helper functions for async testing"""
    
    @staticmethod
    async def run_parallel_tasks(tasks: List, max_concurrent: int = 5) -> List[Any]:
        """Run tasks in parallel with concurrency limit"""
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def run_task(task):
            async with semaphore:
                if callable(task):
                    return await task()
                else:
                    return await task
        
        return await asyncio.gather(*[run_task(task) for task in tasks])
    
    @staticmethod
    async def timeout_task(task, timeout_seconds: float):
        """Run a task with timeout"""
        try:
            return await asyncio.wait_for(task, timeout=timeout_seconds)
        except asyncio.TimeoutError:
            raise TimeoutError(f"Task timed out after {timeout_seconds} seconds")


def generate_test_data(data_type: str, count: int = 1) -> List[Dict[str, Any]]:
    """Generate test data for various resource types"""
    import random
    import string
    
    def random_string(length: int = 8) -> str:
        return ''.join(random.choices(string.ascii_lowercase, k=length))
    
    def random_email() -> str:
        return f"{random_string()}@{random_string()}.com"
    
    data = []
    
    for i in range(count):
        if data_type == 'aws_user':
            data.append({
                'name': f'test-user-{i:03d}',
                'email': random_email(),
                'tags': {'Environment': 'test', 'Index': str(i)}
            })
        elif data_type == 'gcp_service_account':
            data.append({
                'account_id': f'test-sa-{i:03d}',
                'display_name': f'Test Service Account {i:03d}',
                'project': f'test-project-{i:03d}'
            })
        elif data_type == 'azure_user':
            data.append({
                'user_principal_name': f'testuser{i:03d}@contoso.com',
                'display_name': f'Test User {i:03d}',
                'department': 'Engineering'
            })
    
    return data


def create_mock_terraform_state(resources: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Create a mock Terraform state file"""
    return {
        'version': 4,
        'terraform_version': '1.5.7',
        'serial': 1,
        'lineage': f'test-lineage-{int(time.time())}',
        'outputs': {},
        'resources': [
            {
                'mode': 'managed',
                'type': resource['type'],
                'name': resource['name'],
                'provider': f"provider[\"{resource.get('provider', 'hashicorp/aws')}\"]",
                'instances': [
                    {
                        'schema_version': 0,
                        'attributes': resource.get('attributes', {}),
                        'sensitive_attributes': []
                    }
                ]
            }
            for resource in resources
        ]
    }
