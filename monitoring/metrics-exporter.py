#!/usr/bin/env python3
"""
Custom Metrics Exporter for IAM Automation
Collects and exposes metrics from AWS, GCP, and Azure
"""

import time
import json
import logging
import threading
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
import os
import boto3
import botocore.exceptions
from google.cloud import monitoring_v3, resource_manager_v1
from google.oauth2 import service_account
from azure.identity import DefaultAzureCredential
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.subscription import SubscriptionClient
from prometheus_client import start_http_server, Counter, Gauge, Histogram, Info
from prometheus_client.core import CollectorRegistry, REGISTRY
import requests
import psutil

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Prometheus Metrics
REGISTRY.unregister(REGISTRY._collector_to_names.keys())

# Deployment Metrics
deployment_total = Counter('iam_deployments_total', 'Total number of deployments', ['environment', 'cloud', 'status'])
deployment_duration = Histogram('iam_deployment_duration_seconds', 'Deployment duration', ['environment', 'cloud'])
resources_managed = Gauge('iam_resources_managed_total', 'Total resources managed', ['environment', 'cloud', 'resource_type'])
deployment_errors = Counter('iam_deployment_errors_total', 'Total deployment errors', ['environment', 'cloud', 'error_type'])

# Security Metrics
security_violations = Counter('iam_security_violations_total', 'Security policy violations', ['environment', 'cloud', 'severity'])
compliance_score = Gauge('iam_compliance_score', 'Compliance score percentage', ['environment', 'framework'])
policy_attachments = Gauge('iam_policy_attachments_total', 'Total policy attachments', ['environment', 'cloud'])
unused_permissions = Gauge('iam_unused_permissions_total', 'Unused permissions detected', ['environment', 'cloud'])

# Performance Metrics
api_request_duration = Histogram('iam_api_request_duration_seconds', 'API request duration', ['cloud', 'operation'])
api_requests_total = Counter('iam_api_requests_total', 'Total API requests', ['cloud', 'operation', 'status'])
quota_usage = Gauge('iam_quota_usage_percentage', 'Quota usage percentage', ['cloud', 'service'])
rate_limit_hits = Counter('iam_rate_limit_hits_total', 'Rate limit hits', ['cloud', 'service'])

# Cost Metrics
deployment_cost = Gauge('iam_deployment_cost_usd', 'Estimated deployment cost', ['environment', 'cloud'])
resource_cost = Gauge('iam_resource_cost_usd', 'Resource cost per hour', ['environment', 'cloud', 'resource_type'])

# Operational Metrics
active_accounts = Gauge('iam_active_accounts_total', 'Total active accounts', ['cloud'])
failed_accounts = Gauge('iam_failed_accounts_total', 'Failed account deployments', ['cloud'])
concurrent_deployments = Gauge('iam_concurrent_deployments', 'Current concurrent deployments')
queue_size = Gauge('iam_deployment_queue_size', 'Deployment queue size')

# System Metrics
exporter_info = Info('iam_exporter', 'IAM Automation Metrics Exporter Information')
last_successful_scrape = Gauge('iam_last_successful_scrape_timestamp', 'Timestamp of last successful metrics scrape')
scrape_duration = Histogram('iam_scrape_duration_seconds', 'Time spent scraping metrics')


class IAMMetricsExporter:
    """Multi-cloud IAM metrics exporter"""
    
    def __init__(self):
        self.config = self._load_config()
        self.last_scrape = {}
        self.scrape_interval = int(os.getenv('SCRAPE_INTERVAL', '30'))
        self.running = True
        
        # Initialize cloud clients
        self.aws_clients = self._init_aws_clients()
        self.gcp_clients = self._init_gcp_clients()
        self.azure_clients = self._init_azure_clients()
        
        # Set exporter info
        exporter_info.info({
            'version': '1.0.0',
            'clouds': 'aws,gcp,azure',
            'scrape_interval': str(self.scrape_interval)
        })
        
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration"""
        config_path = '/app/config/metrics-config.json'
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning(f"Config file not found: {config_path}, using defaults")
            return {
                'aws': {'regions': ['us-east-1', 'us-west-2']},
                'gcp': {'projects': []},
                'azure': {'subscriptions': []}
            }
    
    def _init_aws_clients(self) -> Dict[str, Any]:
        """Initialize AWS clients"""
        clients = {}
        try:
            for region in self.config.get('aws', {}).get('regions', ['us-east-1']):
                clients[region] = {
                    'iam': boto3.client('iam', region_name=region),
                    'cloudwatch': boto3.client('cloudwatch', region_name=region),
                    'organizations': boto3.client('organizations', region_name=region),
                    'cost_explorer': boto3.client('ce', region_name=region)
                }
        except Exception as e:
            logger.error(f"Failed to initialize AWS clients: {e}")
        return clients
    
    def _init_gcp_clients(self) -> Dict[str, Any]:
        """Initialize GCP clients"""
        clients = {}
        try:
            credentials_path = os.getenv('GOOGLE_APPLICATION_CREDENTIALS')
            if credentials_path:
                credentials = service_account.Credentials.from_service_account_file(
                    credentials_path,
                    scopes=['https://www.googleapis.com/auth/cloud-platform']
                )
            else:
                credentials = None
                
            clients = {
                'monitoring': monitoring_v3.MetricServiceClient(credentials=credentials),
                'resource_manager': resource_manager_v1.ProjectsClient(credentials=credentials)
            }
        except Exception as e:
            logger.error(f"Failed to initialize GCP clients: {e}")
        return clients
    
    def _init_azure_clients(self) -> Dict[str, Any]:
        """Initialize Azure clients"""
        clients = {}
        try:
            credential = DefaultAzureCredential()
            for subscription_id in self.config.get('azure', {}).get('subscriptions', []):
                clients[subscription_id] = {
                    'monitor': MonitorManagementClient(credential, subscription_id),
                    'subscription': SubscriptionClient(credential)
                }
        except Exception as e:
            logger.error(f"Failed to initialize Azure clients: {e}")
        return clients
    
    @scrape_duration.time()
    def collect_aws_metrics(self):
        """Collect AWS metrics"""
        logger.debug("Collecting AWS metrics...")
        
        try:
            for region, clients in self.aws_clients.items():
                # IAM Users and Roles
                try:
                    iam = clients['iam']
                    
                    # Count IAM users
                    users_paginator = iam.get_paginator('list_users')
                    total_users = sum(len(page['Users']) for page in users_paginator.paginate())
                    resources_managed.labels(
                        environment=os.getenv('DEPLOYMENT_ENVIRONMENT', 'unknown'),
                        cloud='aws',
                        resource_type='users'
                    ).set(total_users)
                    
                    # Count IAM roles
                    roles_paginator = iam.get_paginator('list_roles')
                    total_roles = sum(len(page['Roles']) for page in roles_paginator.paginate())
                    resources_managed.labels(
                        environment=os.getenv('DEPLOYMENT_ENVIRONMENT', 'unknown'),
                        cloud='aws',
                        resource_type='roles'
                    ).set(total_roles)
                    
                    # Count policies
                    policies_paginator = iam.get_paginator('list_policies')
                    total_policies = sum(len(page['Policies']) for page in policies_paginator.paginate(Scope='Local'))
                    resources_managed.labels(
                        environment=os.getenv('DEPLOYMENT_ENVIRONMENT', 'unknown'),
                        cloud='aws',
                        resource_type='policies'
                    ).set(total_policies)
                    
                    logger.debug(f"AWS {region}: Users={total_users}, Roles={total_roles}, Policies={total_policies}")
                    
                except Exception as e:
                    logger.error(f"Error collecting AWS IAM metrics for {region}: {e}")
                    deployment_errors.labels(
                        environment=os.getenv('DEPLOYMENT_ENVIRONMENT', 'unknown'),
                        cloud='aws',
                        error_type='iam_collection_error'
                    ).inc()
                
                # CloudWatch metrics
                try:
                    cloudwatch = clients['cloudwatch']
                    
                    # Get IAM-related metrics
                    end_time = datetime.utcnow()
                    start_time = end_time - timedelta(minutes=5)
                    
                    # This would be expanded based on actual CloudWatch metrics available
                    # for IAM service usage
                    
                except Exception as e:
                    logger.error(f"Error collecting AWS CloudWatch metrics for {region}: {e}")
                
                # Organizations metrics (if available)
                try:
                    if 'organizations' in clients:
                        org_client = clients['organizations']
                        accounts = org_client.list_accounts()
                        active_accounts.labels(cloud='aws').set(len(accounts.get('Accounts', [])))
                        
                except botocore.exceptions.ClientError as e:
                    if e.response['Error']['Code'] != 'AWSOrganizationsNotInUseException':
                        logger.error(f"Error collecting AWS Organizations metrics: {e}")
                except Exception as e:
                    logger.error(f"Error collecting AWS Organizations metrics: {e}")
                    
        except Exception as e:
            logger.error(f"Error in AWS metrics collection: {e}")
    
    @scrape_duration.time()
    def collect_gcp_metrics(self):
        """Collect GCP metrics"""
        logger.debug("Collecting GCP metrics...")
        
        try:
            if not self.gcp_clients:
                return
            
            projects = self.config.get('gcp', {}).get('projects', [])
            
            for project_id in projects:
                try:
                    # Get project metrics using Cloud Monitoring API
                    monitoring_client = self.gcp_clients['monitoring']
                    project_name = f"projects/{project_id}"
                    
                    # Query for IAM-related metrics
                    interval = monitoring_v3.TimeInterval({
                        "end_time": {"seconds": int(time.time())},
                        "start_time": {"seconds": int(time.time()) - 300}  # 5 minutes ago
                    })
                    
                    # This would be expanded with actual GCP IAM metrics
                    # For now, we'll collect basic resource counts
                    
                    # Count service accounts (placeholder - would use actual API)
                    resources_managed.labels(
                        environment=os.getenv('DEPLOYMENT_ENVIRONMENT', 'unknown'),
                        cloud='gcp',
                        resource_type='service_accounts'
                    ).set(0)  # Placeholder
                    
                    logger.debug(f"GCP project {project_id} metrics collected")
                    
                except Exception as e:
                    logger.error(f"Error collecting GCP metrics for project {project_id}: {e}")
                    deployment_errors.labels(
                        environment=os.getenv('DEPLOYMENT_ENVIRONMENT', 'unknown'),
                        cloud='gcp',
                        error_type='metrics_collection_error'
                    ).inc()
                    
        except Exception as e:
            logger.error(f"Error in GCP metrics collection: {e}")
    
    @scrape_duration.time()
    def collect_azure_metrics(self):
        """Collect Azure metrics"""
        logger.debug("Collecting Azure metrics...")
        
        try:
            for subscription_id, clients in self.azure_clients.items():
                try:
                    monitor_client = clients['monitor']
                    
                    # Get Azure Monitor metrics for IAM-related resources
                    # This would be expanded with actual Azure metrics queries
                    
                    # Placeholder metrics
                    resources_managed.labels(
                        environment=os.getenv('DEPLOYMENT_ENVIRONMENT', 'unknown'),
                        cloud='azure',
                        resource_type='service_principals'
                    ).set(0)  # Placeholder
                    
                    logger.debug(f"Azure subscription {subscription_id} metrics collected")
                    
                except Exception as e:
                    logger.error(f"Error collecting Azure metrics for subscription {subscription_id}: {e}")
                    deployment_errors.labels(
                        environment=os.getenv('DEPLOYMENT_ENVIRONMENT', 'unknown'),
                        cloud='azure',
                        error_type='metrics_collection_error'
                    ).inc()
                    
        except Exception as e:
            logger.error(f"Error in Azure metrics collection: {e}")
    
    def collect_system_metrics(self):
        """Collect system and application metrics"""
        try:
            # CPU and Memory usage
            cpu_percent = psutil.cpu_percent(interval=1)
            memory_percent = psutil.virtual_memory().percent
            
            # These would be proper Prometheus metrics in a real implementation
            logger.debug(f"System: CPU={cpu_percent}%, Memory={memory_percent}%")
            
            # Queue size (from Redis or database)
            try:
                # This would query actual queue system
                queue_size.set(0)  # Placeholder
            except Exception as e:
                logger.error(f"Error getting queue size: {e}")
                
            # Update last successful scrape timestamp
            last_successful_scrape.set_to_current_time()
            
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
    
    def collect_deployment_metrics(self):
        """Collect deployment-specific metrics from logs/database"""
        try:
            # Read deployment status from status files or database
            status_dir = '/app/logs'
            
            if os.path.exists(status_dir):
                for filename in os.listdir(status_dir):
                    if filename.startswith('deployment-status-') and filename.endswith('.json'):
                        try:
                            with open(os.path.join(status_dir, filename), 'r') as f:
                                status = json.load(f)
                                
                            environment = status.get('environment', 'unknown')
                            clouds = status.get('clouds', '').split(',')
                            deployment_status = status.get('status', 'unknown')
                            
                            for cloud in clouds:
                                cloud = cloud.strip()
                                if cloud:
                                    deployment_total.labels(
                                        environment=environment,
                                        cloud=cloud,
                                        status=deployment_status
                                    ).inc()
                                    
                        except Exception as e:
                            logger.error(f"Error processing status file {filename}: {e}")
                            
        except Exception as e:
            logger.error(f"Error collecting deployment metrics: {e}")
    
    def collect_compliance_metrics(self):
        """Collect compliance and security metrics"""
        try:
            # Read compliance scan results
            # This would integrate with actual compliance scanning tools
            
            # Placeholder compliance scores
            frameworks = ['SOC2', 'PCI-DSS', 'HIPAA', 'ISO27001']
            for framework in frameworks:
                # This would come from actual compliance scanning
                score = 85.0  # Placeholder
                compliance_score.labels(
                    environment=os.getenv('DEPLOYMENT_ENVIRONMENT', 'unknown'),
                    framework=framework
                ).set(score)
                
        except Exception as e:
            logger.error(f"Error collecting compliance metrics: {e}")
    
    def run_metrics_collection(self):
        """Main metrics collection loop"""
        logger.info("Starting metrics collection...")
        
        while self.running:
            try:
                start_time = time.time()
                
                # Collect metrics from all sources
                self.collect_aws_metrics()
                self.collect_gcp_metrics()
                self.collect_azure_metrics()
                self.collect_system_metrics()
                self.collect_deployment_metrics()
                self.collect_compliance_metrics()
                
                collection_duration = time.time() - start_time
                logger.debug(f"Metrics collection completed in {collection_duration:.2f}s")
                
                # Sleep until next collection cycle
                time.sleep(max(0, self.scrape_interval - collection_duration))
                
            except KeyboardInterrupt:
                logger.info("Received interrupt signal, stopping...")
                self.running = False
            except Exception as e:
                logger.error(f"Error in metrics collection loop: {e}")
                time.sleep(self.scrape_interval)
    
    def start(self):
        """Start the metrics exporter"""
        port = int(os.getenv('METRICS_PORT', '8080'))
        
        # Start HTTP server for Prometheus
        start_http_server(port)
        logger.info(f"Metrics server started on port {port}")
        
        # Start metrics collection in background thread
        metrics_thread = threading.Thread(target=self.run_metrics_collection, daemon=True)
        metrics_thread.start()
        
        logger.info("IAM Automation Metrics Exporter started successfully")
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutting down metrics exporter...")
            self.running = False


def main():
    """Main entry point"""
    logging.basicConfig(
        level=getattr(logging, os.getenv('LOG_LEVEL', 'INFO').upper()),
        format='%(asctime)s - %(levelname)s - %(name)s - %(message)s'
    )
    
    exporter = IAMMetricsExporter()
    exporter.start()


if __name__ == '__main__':
    main()
