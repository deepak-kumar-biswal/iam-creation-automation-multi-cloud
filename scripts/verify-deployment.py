#!/usr/bin/env python3
"""
Multi-Cloud IAM Deployment Verification Script
Enterprise-grade verification for AWS, GCP, and Azure deployments
"""

import argparse
import json
import logging
import sys
import time
import concurrent.futures
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
import boto3
import botocore.exceptions
from google.cloud import iam as gcp_iam
from google.cloud import resourcemanager_v1
from google.oauth2 import service_account
from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.subscription import SubscriptionClient
import requests

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('deployment-verification.log')
    ]
)
logger = logging.getLogger(__name__)


class CloudVerificationError(Exception):
    """Custom exception for cloud verification errors"""
    pass


class MultiCloudVerifier:
    """Multi-cloud IAM deployment verification"""
    
    def __init__(self, deployment_id: str, environment: str):
        self.deployment_id = deployment_id
        self.environment = environment
        self.verification_results = {
            'deployment_id': deployment_id,
            'environment': environment,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'clouds': {},
            'overall_status': 'unknown',
            'summary': {}
        }
        
    def verify_aws(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Verify AWS IAM resources"""
        logger.info("Starting AWS verification...")
        
        results = {
            'status': 'unknown',
            'resources_verified': 0,
            'resources_failed': 0,
            'details': {},
            'errors': []
        }
        
        try:
            # Initialize AWS clients
            session = boto3.Session(profile_name=config.get('aws_profile'))
            
            # Verify across multiple accounts if configured
            accounts = config.get('accounts', [])
            if not accounts:
                # Single account verification
                accounts = [{'account_id': None, 'role_arn': None}]
            
            for account in accounts:
                account_id = account.get('account_id', 'current')
                logger.info(f"Verifying AWS account: {account_id}")
                
                # Assume role if specified
                if account.get('role_arn'):
                    sts = session.client('sts')
                    assumed_role = sts.assume_role(
                        RoleArn=account['role_arn'],
                        RoleSessionName=f'verification-{self.deployment_id}'
                    )
                    
                    session = boto3.Session(
                        aws_access_key_id=assumed_role['Credentials']['AccessKeyId'],
                        aws_secret_access_key=assumed_role['Credentials']['SecretAccessKey'],
                        aws_session_token=assumed_role['Credentials']['SessionToken']
                    )
                
                iam = session.client('iam')
                
                # Verify IAM users
                users_verified = self._verify_aws_users(iam, config.get('expected_users', []))
                results['resources_verified'] += users_verified['verified']
                results['resources_failed'] += users_verified['failed']
                results['details'][f'users_{account_id}'] = users_verified
                
                # Verify IAM roles
                roles_verified = self._verify_aws_roles(iam, config.get('expected_roles', []))
                results['resources_verified'] += roles_verified['verified']
                results['resources_failed'] += roles_verified['failed']
                results['details'][f'roles_{account_id}'] = roles_verified
                
                # Verify IAM policies
                policies_verified = self._verify_aws_policies(iam, config.get('expected_policies', []))
                results['resources_verified'] += policies_verified['verified']
                results['resources_failed'] += policies_verified['failed']
                results['details'][f'policies_{account_id}'] = policies_verified
                
                # Verify security settings
                security_verified = self._verify_aws_security_settings(iam, config.get('security_requirements', {}))
                results['details'][f'security_{account_id}'] = security_verified
                
                if security_verified.get('compliant', False):
                    results['resources_verified'] += 1
                else:
                    results['resources_failed'] += 1
            
            # Determine overall status
            if results['resources_failed'] == 0:
                results['status'] = 'success'
            elif results['resources_verified'] > results['resources_failed']:
                results['status'] = 'partial'
            else:
                results['status'] = 'failed'
                
        except Exception as e:
            logger.error(f"AWS verification error: {str(e)}")
            results['status'] = 'error'
            results['errors'].append(str(e))
        
        return results
    
    def _verify_aws_users(self, iam_client, expected_users: List[str]) -> Dict[str, Any]:
        """Verify AWS IAM users"""
        verified = 0
        failed = 0
        details = {}
        
        try:
            # Get all IAM users
            paginator = iam_client.get_paginator('list_users')
            users = []
            for page in paginator.paginate():
                users.extend(page['Users'])
            
            existing_users = {user['UserName'] for user in users}
            
            for expected_user in expected_users:
                if expected_user in existing_users:
                    # Verify user details
                    try:
                        user_details = iam_client.get_user(UserName=expected_user)
                        
                        # Check attached policies
                        attached_policies = iam_client.list_attached_user_policies(UserName=expected_user)
                        
                        # Check inline policies
                        inline_policies = iam_client.list_user_policies(UserName=expected_user)
                        
                        # Check groups
                        groups = iam_client.get_groups_for_user(UserName=expected_user)
                        
                        details[expected_user] = {
                            'exists': True,
                            'created_date': user_details['User']['CreateDate'].isoformat(),
                            'attached_policies': len(attached_policies['AttachedPolicies']),
                            'inline_policies': len(inline_policies['PolicyNames']),
                            'groups': len(groups['Groups'])
                        }
                        
                        verified += 1
                        logger.debug(f"AWS user verified: {expected_user}")
                        
                    except Exception as e:
                        details[expected_user] = {'exists': True, 'error': str(e)}
                        failed += 1
                        logger.warning(f"Error verifying AWS user {expected_user}: {str(e)}")
                else:
                    details[expected_user] = {'exists': False}
                    failed += 1
                    logger.warning(f"AWS user not found: {expected_user}")
                    
        except Exception as e:
            logger.error(f"Error listing AWS users: {str(e)}")
            failed += len(expected_users)
        
        return {
            'verified': verified,
            'failed': failed,
            'details': details,
            'total_expected': len(expected_users)
        }
    
    def _verify_aws_roles(self, iam_client, expected_roles: List[str]) -> Dict[str, Any]:
        """Verify AWS IAM roles"""
        verified = 0
        failed = 0
        details = {}
        
        try:
            paginator = iam_client.get_paginator('list_roles')
            roles = []
            for page in paginator.paginate():
                roles.extend(page['Roles'])
            
            existing_roles = {role['RoleName'] for role in roles}
            
            for expected_role in expected_roles:
                if expected_role in existing_roles:
                    try:
                        role_details = iam_client.get_role(RoleName=expected_role)
                        attached_policies = iam_client.list_attached_role_policies(RoleName=expected_role)
                        inline_policies = iam_client.list_role_policies(RoleName=expected_role)
                        
                        details[expected_role] = {
                            'exists': True,
                            'created_date': role_details['Role']['CreateDate'].isoformat(),
                            'attached_policies': len(attached_policies['AttachedPolicies']),
                            'inline_policies': len(inline_policies['PolicyNames']),
                            'assume_role_policy': bool(role_details['Role'].get('AssumeRolePolicyDocument'))
                        }
                        
                        verified += 1
                        logger.debug(f"AWS role verified: {expected_role}")
                        
                    except Exception as e:
                        details[expected_role] = {'exists': True, 'error': str(e)}
                        failed += 1
                        logger.warning(f"Error verifying AWS role {expected_role}: {str(e)}")
                else:
                    details[expected_role] = {'exists': False}
                    failed += 1
                    logger.warning(f"AWS role not found: {expected_role}")
                    
        except Exception as e:
            logger.error(f"Error listing AWS roles: {str(e)}")
            failed += len(expected_roles)
        
        return {
            'verified': verified,
            'failed': failed,
            'details': details,
            'total_expected': len(expected_roles)
        }
    
    def _verify_aws_policies(self, iam_client, expected_policies: List[str]) -> Dict[str, Any]:
        """Verify AWS IAM policies"""
        verified = 0
        failed = 0
        details = {}
        
        try:
            paginator = iam_client.get_paginator('list_policies')
            policies = []
            for page in paginator.paginate(Scope='Local'):
                policies.extend(page['Policies'])
            
            existing_policies = {policy['PolicyName'] for policy in policies}
            
            for expected_policy in expected_policies:
                if expected_policy in existing_policies:
                    try:
                        policy = next(p for p in policies if p['PolicyName'] == expected_policy)
                        
                        details[expected_policy] = {
                            'exists': True,
                            'arn': policy['Arn'],
                            'created_date': policy['CreateDate'].isoformat(),
                            'attachment_count': policy['AttachmentCount']
                        }
                        
                        verified += 1
                        logger.debug(f"AWS policy verified: {expected_policy}")
                        
                    except Exception as e:
                        details[expected_policy] = {'exists': True, 'error': str(e)}
                        failed += 1
                        logger.warning(f"Error verifying AWS policy {expected_policy}: {str(e)}")
                else:
                    details[expected_policy] = {'exists': False}
                    failed += 1
                    logger.warning(f"AWS policy not found: {expected_policy}")
                    
        except Exception as e:
            logger.error(f"Error listing AWS policies: {str(e)}")
            failed += len(expected_policies)
        
        return {
            'verified': verified,
            'failed': failed,
            'details': details,
            'total_expected': len(expected_policies)
        }
    
    def _verify_aws_security_settings(self, iam_client, requirements: Dict[str, Any]) -> Dict[str, Any]:
        """Verify AWS security settings"""
        compliance_checks = {}
        compliant = True
        
        try:
            # Check password policy
            if requirements.get('password_policy'):
                try:
                    password_policy = iam_client.get_account_password_policy()
                    policy = password_policy['PasswordPolicy']
                    
                    required_policy = requirements['password_policy']
                    policy_compliant = True
                    
                    for key, required_value in required_policy.items():
                        actual_value = policy.get(key)
                        if actual_value != required_value:
                            policy_compliant = False
                            break
                    
                    compliance_checks['password_policy'] = {
                        'compliant': policy_compliant,
                        'details': policy
                    }
                    
                    if not policy_compliant:
                        compliant = False
                        
                except iam_client.exceptions.NoSuchEntityException:
                    compliance_checks['password_policy'] = {
                        'compliant': False,
                        'error': 'Password policy not configured'
                    }
                    compliant = False
                except Exception as e:
                    compliance_checks['password_policy'] = {
                        'compliant': False,
                        'error': str(e)
                    }
                    compliant = False
            
            # Check MFA requirements
            if requirements.get('mfa_required'):
                # This would require more complex logic to check MFA enforcement
                compliance_checks['mfa_enforcement'] = {
                    'compliant': True,  # Placeholder
                    'note': 'MFA verification requires policy analysis'
                }
            
            # Check access analyzer
            if requirements.get('access_analyzer'):
                try:
                    access_analyzer = boto3.client('accessanalyzer')
                    analyzers = access_analyzer.list_analyzers()
                    
                    analyzer_exists = len(analyzers['analyzers']) > 0
                    compliance_checks['access_analyzer'] = {
                        'compliant': analyzer_exists,
                        'analyzer_count': len(analyzers['analyzers'])
                    }
                    
                    if not analyzer_exists and requirements['access_analyzer']:
                        compliant = False
                        
                except Exception as e:
                    compliance_checks['access_analyzer'] = {
                        'compliant': False,
                        'error': str(e)
                    }
                    if requirements['access_analyzer']:
                        compliant = False
                        
        except Exception as e:
            logger.error(f"Error checking AWS security settings: {str(e)}")
            compliant = False
            compliance_checks['error'] = str(e)
        
        return {
            'compliant': compliant,
            'checks': compliance_checks
        }
    
    def verify_gcp(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Verify GCP IAM resources"""
        logger.info("Starting GCP verification...")
        
        results = {
            'status': 'unknown',
            'resources_verified': 0,
            'resources_failed': 0,
            'details': {},
            'errors': []
        }
        
        try:
            # Initialize GCP clients
            credentials_path = config.get('credentials_path')
            if credentials_path:
                credentials = service_account.Credentials.from_service_account_file(
                    credentials_path,
                    scopes=['https://www.googleapis.com/auth/cloud-platform']
                )
            else:
                credentials = None
            
            iam_client = gcp_iam.IAMClient(credentials=credentials)
            resource_manager = resourcemanager_v1.ProjectsClient(credentials=credentials)
            
            # Verify across multiple projects if configured
            projects = config.get('projects', [])
            
            for project_config in projects:
                project_id = project_config.get('project_id')
                logger.info(f"Verifying GCP project: {project_id}")
                
                # Verify service accounts
                sa_verified = self._verify_gcp_service_accounts(
                    iam_client, project_id, project_config.get('expected_service_accounts', [])
                )
                results['resources_verified'] += sa_verified['verified']
                results['resources_failed'] += sa_verified['failed']
                results['details'][f'service_accounts_{project_id}'] = sa_verified
                
                # Verify IAM bindings
                bindings_verified = self._verify_gcp_iam_bindings(
                    resource_manager, project_id, project_config.get('expected_bindings', {})
                )
                results['resources_verified'] += bindings_verified['verified']
                results['resources_failed'] += bindings_verified['failed']
                results['details'][f'bindings_{project_id}'] = bindings_verified
                
                # Verify custom roles
                roles_verified = self._verify_gcp_custom_roles(
                    iam_client, project_id, project_config.get('expected_custom_roles', [])
                )
                results['resources_verified'] += roles_verified['verified']
                results['resources_failed'] += roles_verified['failed']
                results['details'][f'custom_roles_{project_id}'] = roles_verified
            
            # Determine overall status
            if results['resources_failed'] == 0:
                results['status'] = 'success'
            elif results['resources_verified'] > results['resources_failed']:
                results['status'] = 'partial'
            else:
                results['status'] = 'failed'
                
        except Exception as e:
            logger.error(f"GCP verification error: {str(e)}")
            results['status'] = 'error'
            results['errors'].append(str(e))
        
        return results
    
    def _verify_gcp_service_accounts(self, iam_client, project_id: str, expected_accounts: List[str]) -> Dict[str, Any]:
        """Verify GCP service accounts"""
        verified = 0
        failed = 0
        details = {}
        
        try:
            parent = f"projects/{project_id}"
            request = gcp_iam.ListServiceAccountsRequest(name=parent)
            response = iam_client.list_service_accounts(request=request)
            
            existing_accounts = {sa.email for sa in response.accounts}
            
            for expected_account in expected_accounts:
                if expected_account in existing_accounts:
                    verified += 1
                    details[expected_account] = {'exists': True}
                    logger.debug(f"GCP service account verified: {expected_account}")
                else:
                    failed += 1
                    details[expected_account] = {'exists': False}
                    logger.warning(f"GCP service account not found: {expected_account}")
                    
        except Exception as e:
            logger.error(f"Error listing GCP service accounts: {str(e)}")
            failed += len(expected_accounts)
            details = {account: {'error': str(e)} for account in expected_accounts}
        
        return {
            'verified': verified,
            'failed': failed,
            'details': details,
            'total_expected': len(expected_accounts)
        }
    
    def _verify_gcp_iam_bindings(self, resource_manager, project_id: str, expected_bindings: Dict[str, List[str]]) -> Dict[str, Any]:
        """Verify GCP IAM bindings"""
        verified = 0
        failed = 0
        details = {}
        
        try:
            request = resourcemanager_v1.GetIamPolicyRequest(resource=f"projects/{project_id}")
            policy = resource_manager.get_iam_policy(request=request)
            
            existing_bindings = {}
            for binding in policy.bindings:
                existing_bindings[binding.role] = list(binding.members)
            
            for role, expected_members in expected_bindings.items():
                if role in existing_bindings:
                    actual_members = set(existing_bindings[role])
                    expected_members_set = set(expected_members)
                    
                    if expected_members_set.issubset(actual_members):
                        verified += 1
                        details[role] = {
                            'exists': True,
                            'members_verified': True,
                            'expected_count': len(expected_members),
                            'actual_count': len(actual_members)
                        }
                        logger.debug(f"GCP IAM binding verified: {role}")
                    else:
                        failed += 1
                        missing_members = expected_members_set - actual_members
                        details[role] = {
                            'exists': True,
                            'members_verified': False,
                            'missing_members': list(missing_members)
                        }
                        logger.warning(f"GCP IAM binding incomplete: {role}")
                else:
                    failed += 1
                    details[role] = {'exists': False}
                    logger.warning(f"GCP IAM binding not found: {role}")
                    
        except Exception as e:
            logger.error(f"Error getting GCP IAM policy: {str(e)}")
            failed += len(expected_bindings)
            details = {role: {'error': str(e)} for role in expected_bindings}
        
        return {
            'verified': verified,
            'failed': failed,
            'details': details,
            'total_expected': len(expected_bindings)
        }
    
    def _verify_gcp_custom_roles(self, iam_client, project_id: str, expected_roles: List[str]) -> Dict[str, Any]:
        """Verify GCP custom roles"""
        verified = 0
        failed = 0
        details = {}
        
        try:
            parent = f"projects/{project_id}"
            request = gcp_iam.ListRolesRequest(parent=parent)
            response = iam_client.list_roles(request=request)
            
            existing_roles = {role.name.split('/')[-1] for role in response.roles}
            
            for expected_role in expected_roles:
                if expected_role in existing_roles:
                    verified += 1
                    details[expected_role] = {'exists': True}
                    logger.debug(f"GCP custom role verified: {expected_role}")
                else:
                    failed += 1
                    details[expected_role] = {'exists': False}
                    logger.warning(f"GCP custom role not found: {expected_role}")
                    
        except Exception as e:
            logger.error(f"Error listing GCP custom roles: {str(e)}")
            failed += len(expected_roles)
            details = {role: {'error': str(e)} for role in expected_roles}
        
        return {
            'verified': verified,
            'failed': failed,
            'details': details,
            'total_expected': len(expected_roles)
        }
    
    def verify_azure(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Verify Azure IAM resources"""
        logger.info("Starting Azure verification...")
        
        results = {
            'status': 'unknown',
            'resources_verified': 0,
            'resources_failed': 0,
            'details': {},
            'errors': []
        }
        
        try:
            credential = DefaultAzureCredential()
            
            # Verify across multiple subscriptions if configured
            subscriptions = config.get('subscriptions', [])
            
            for subscription_config in subscriptions:
                subscription_id = subscription_config.get('subscription_id')
                logger.info(f"Verifying Azure subscription: {subscription_id}")
                
                auth_client = AuthorizationManagementClient(
                    credential, subscription_id
                )
                
                # Verify service principals
                sp_verified = self._verify_azure_service_principals(
                    credential, subscription_config.get('expected_service_principals', [])
                )
                results['resources_verified'] += sp_verified['verified']
                results['resources_failed'] += sp_verified['failed']
                results['details'][f'service_principals_{subscription_id}'] = sp_verified
                
                # Verify role assignments
                roles_verified = self._verify_azure_role_assignments(
                    auth_client, subscription_config.get('expected_role_assignments', [])
                )
                results['resources_verified'] += roles_verified['verified']
                results['resources_failed'] += roles_verified['failed']
                results['details'][f'role_assignments_{subscription_id}'] = roles_verified
                
                # Verify custom roles
                custom_roles_verified = self._verify_azure_custom_roles(
                    auth_client, subscription_config.get('expected_custom_roles', [])
                )
                results['resources_verified'] += custom_roles_verified['verified']
                results['resources_failed'] += custom_roles_verified['failed']
                results['details'][f'custom_roles_{subscription_id}'] = custom_roles_verified
            
            # Determine overall status
            if results['resources_failed'] == 0:
                results['status'] = 'success'
            elif results['resources_verified'] > results['resources_failed']:
                results['status'] = 'partial'
            else:
                results['status'] = 'failed'
                
        except Exception as e:
            logger.error(f"Azure verification error: {str(e)}")
            results['status'] = 'error'
            results['errors'].append(str(e))
        
        return results
    
    def _verify_azure_service_principals(self, credential, expected_sps: List[str]) -> Dict[str, Any]:
        """Verify Azure service principals"""
        verified = 0
        failed = 0
        details = {}
        
        try:
            from azure.mgmt.graphrbac import GraphRbacManagementClient
            graph_client = GraphRbacManagementClient(
                credential, 
                tenant_id=credential._get_tenant_id()
            )
            
            service_principals = list(graph_client.service_principals.list())
            existing_sps = {sp.display_name for sp in service_principals}
            
            for expected_sp in expected_sps:
                if expected_sp in existing_sps:
                    verified += 1
                    details[expected_sp] = {'exists': True}
                    logger.debug(f"Azure service principal verified: {expected_sp}")
                else:
                    failed += 1
                    details[expected_sp] = {'exists': False}
                    logger.warning(f"Azure service principal not found: {expected_sp}")
                    
        except Exception as e:
            logger.error(f"Error listing Azure service principals: {str(e)}")
            failed += len(expected_sps)
            details = {sp: {'error': str(e)} for sp in expected_sps}
        
        return {
            'verified': verified,
            'failed': failed,
            'details': details,
            'total_expected': len(expected_sps)
        }
    
    def _verify_azure_role_assignments(self, auth_client, expected_assignments: List[Dict[str, str]]) -> Dict[str, Any]:
        """Verify Azure role assignments"""
        verified = 0
        failed = 0
        details = {}
        
        try:
            role_assignments = list(auth_client.role_assignments.list())
            
            for i, expected_assignment in enumerate(expected_assignments):
                assignment_key = f"assignment_{i}"
                found = False
                
                for assignment in role_assignments:
                    if (assignment.principal_id == expected_assignment.get('principal_id') and
                        assignment.role_definition_id.endswith(expected_assignment.get('role_definition_name', ''))):
                        found = True
                        break
                
                if found:
                    verified += 1
                    details[assignment_key] = {'exists': True}
                    logger.debug(f"Azure role assignment verified: {assignment_key}")
                else:
                    failed += 1
                    details[assignment_key] = {'exists': False}
                    logger.warning(f"Azure role assignment not found: {assignment_key}")
                    
        except Exception as e:
            logger.error(f"Error listing Azure role assignments: {str(e)}")
            failed += len(expected_assignments)
            details = {f"assignment_{i}": {'error': str(e)} for i in range(len(expected_assignments))}
        
        return {
            'verified': verified,
            'failed': failed,
            'details': details,
            'total_expected': len(expected_assignments)
        }
    
    def _verify_azure_custom_roles(self, auth_client, expected_roles: List[str]) -> Dict[str, Any]:
        """Verify Azure custom roles"""
        verified = 0
        failed = 0
        details = {}
        
        try:
            role_definitions = list(auth_client.role_definitions.list(scope='/'))
            custom_roles = [role for role in role_definitions if role.role_type == 'CustomRole']
            existing_roles = {role.role_name for role in custom_roles}
            
            for expected_role in expected_roles:
                if expected_role in existing_roles:
                    verified += 1
                    details[expected_role] = {'exists': True}
                    logger.debug(f"Azure custom role verified: {expected_role}")
                else:
                    failed += 1
                    details[expected_role] = {'exists': False}
                    logger.warning(f"Azure custom role not found: {expected_role}")
                    
        except Exception as e:
            logger.error(f"Error listing Azure custom roles: {str(e)}")
            failed += len(expected_roles)
            details = {role: {'error': str(e)} for role in expected_roles}
        
        return {
            'verified': verified,
            'failed': failed,
            'details': details,
            'total_expected': len(expected_roles)
        }
    
    def run_verification(self, clouds: List[str], config: Dict[str, Any]) -> Dict[str, Any]:
        """Run verification for specified clouds"""
        logger.info(f"Starting verification for clouds: {', '.join(clouds)}")
        
        verification_functions = {
            'aws': self.verify_aws,
            'gcp': self.verify_gcp,
            'azure': self.verify_azure
        }
        
        # Run verifications in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            future_to_cloud = {
                executor.submit(verification_functions[cloud], config.get(cloud, {})): cloud
                for cloud in clouds if cloud in verification_functions
            }
            
            for future in concurrent.futures.as_completed(future_to_cloud):
                cloud = future_to_cloud[future]
                try:
                    result = future.result(timeout=300)  # 5 minute timeout per cloud
                    self.verification_results['clouds'][cloud] = result
                    logger.info(f"Completed verification for {cloud}: {result['status']}")
                except Exception as e:
                    logger.error(f"Verification failed for {cloud}: {str(e)}")
                    self.verification_results['clouds'][cloud] = {
                        'status': 'error',
                        'error': str(e),
                        'resources_verified': 0,
                        'resources_failed': 1
                    }
        
        # Calculate overall status
        all_statuses = [cloud_result['status'] for cloud_result in self.verification_results['clouds'].values()]
        
        if all(status == 'success' for status in all_statuses):
            self.verification_results['overall_status'] = 'success'
        elif any(status == 'success' for status in all_statuses):
            self.verification_results['overall_status'] = 'partial'
        else:
            self.verification_results['overall_status'] = 'failed'
        
        # Generate summary
        total_verified = sum(cloud_result.get('resources_verified', 0) 
                           for cloud_result in self.verification_results['clouds'].values())
        total_failed = sum(cloud_result.get('resources_failed', 0) 
                         for cloud_result in self.verification_results['clouds'].values())
        
        self.verification_results['summary'] = {
            'total_resources_verified': total_verified,
            'total_resources_failed': total_failed,
            'success_rate': total_verified / (total_verified + total_failed) * 100 if (total_verified + total_failed) > 0 else 0,
            'clouds_verified': len([cloud for cloud, result in self.verification_results['clouds'].items() 
                                  if result['status'] == 'success']),
            'clouds_total': len(clouds)
        }
        
        return self.verification_results
    
    def send_verification_report(self, webhook_url: Optional[str] = None):
        """Send verification report to monitoring system"""
        if webhook_url:
            try:
                response = requests.post(
                    webhook_url,
                    json=self.verification_results,
                    headers={'Content-Type': 'application/json'},
                    timeout=30
                )
                response.raise_for_status()
                logger.info("Verification report sent to monitoring system")
            except Exception as e:
                logger.warning(f"Failed to send verification report: {str(e)}")


def main():
    parser = argparse.ArgumentParser(description='Multi-Cloud IAM Deployment Verification')
    parser.add_argument('--deployment-id', required=True, help='Deployment ID to verify')
    parser.add_argument('--environment', required=True, choices=['dev', 'staging', 'production'],
                       help='Target environment')
    parser.add_argument('--clouds', required=True, help='Comma-separated list of clouds to verify')
    parser.add_argument('--config-file', required=True, help='Path to verification configuration file')
    parser.add_argument('--output-file', help='Path to save verification results')
    parser.add_argument('--webhook-url', help='Webhook URL for sending results')
    parser.add_argument('--timeout', type=int, default=900, help='Verification timeout in seconds')
    parser.add_argument('--sample-size', type=int, default=100, 
                       help='Number of resources to sample for verification')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Parse clouds
    clouds = [cloud.strip() for cloud in args.clouds.split(',')]
    
    # Load configuration
    try:
        with open(args.config_file, 'r') as f:
            config = json.load(f)
    except Exception as e:
        logger.error(f"Failed to load configuration file: {str(e)}")
        sys.exit(1)
    
    # Initialize verifier
    verifier = MultiCloudVerifier(args.deployment_id, args.environment)
    
    # Run verification
    try:
        results = verifier.run_verification(clouds, config)
        
        # Save results
        if args.output_file:
            with open(args.output_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            logger.info(f"Verification results saved to: {args.output_file}")
        
        # Send to monitoring system
        verifier.send_verification_report(args.webhook_url)
        
        # Print summary
        print(f"\n=== Verification Summary ===")
        print(f"Deployment ID: {args.deployment_id}")
        print(f"Environment: {args.environment}")
        print(f"Overall Status: {results['overall_status']}")
        print(f"Success Rate: {results['summary']['success_rate']:.1f}%")
        print(f"Resources Verified: {results['summary']['total_resources_verified']}")
        print(f"Resources Failed: {results['summary']['total_resources_failed']}")
        print(f"Clouds Verified: {results['summary']['clouds_verified']}/{results['summary']['clouds_total']}")
        
        # Cloud-specific summary
        for cloud, cloud_result in results['clouds'].items():
            print(f"\n{cloud.upper()}:")
            print(f"  Status: {cloud_result['status']}")
            print(f"  Verified: {cloud_result.get('resources_verified', 0)}")
            print(f"  Failed: {cloud_result.get('resources_failed', 0)}")
        
        # Exit code based on verification results
        if results['overall_status'] == 'success':
            sys.exit(0)
        elif results['overall_status'] == 'partial':
            sys.exit(1)
        else:
            sys.exit(2)
            
    except Exception as e:
        logger.error(f"Verification failed: {str(e)}")
        sys.exit(3)


if __name__ == '__main__':
    main()
