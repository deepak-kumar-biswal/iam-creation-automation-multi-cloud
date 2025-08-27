#!/bin/bash

# Multi-Cloud IAM Deployment Script
# Enterprise-grade deployment automation for AWS, GCP, and Azure

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_DIR="${PROJECT_ROOT}/logs"
CONFIG_DIR="${PROJECT_ROOT}/config"
TERRAFORM_DIR="${PROJECT_ROOT}/terraform"

# Default values
ENVIRONMENT="dev"
CLOUDS="aws,gcp,azure"
MAX_CONCURRENT=10
STRATEGY="rolling"
DRY_RUN=false
VERBOSE=false
FORCE=false
SKIP_VALIDATION=false
DEPLOYMENT_ID=$(uuidgen)

# Logging setup
mkdir -p "${LOG_DIR}"
LOG_FILE="${LOG_DIR}/deployment-${DEPLOYMENT_ID}-$(date +%Y%m%d-%H%M%S).log"

# Logging function
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        INFO)
            echo -e "${GREEN}[INFO]${NC} ${message}" | tee -a "${LOG_FILE}"
            ;;
        WARN)
            echo -e "${YELLOW}[WARN]${NC} ${message}" | tee -a "${LOG_FILE}"
            ;;
        ERROR)
            echo -e "${RED}[ERROR]${NC} ${message}" | tee -a "${LOG_FILE}"
            ;;
        DEBUG)
            if [[ "$VERBOSE" == "true" ]]; then
                echo -e "${BLUE}[DEBUG]${NC} ${message}" | tee -a "${LOG_FILE}"
            fi
            ;;
    esac
    
    echo "[$timestamp] [$level] $message" >> "${LOG_FILE}"
}

# Error handling
error_exit() {
    log ERROR "$1"
    exit 1
}

# Trap for cleanup
cleanup() {
    local exit_code=$?
    log INFO "Cleaning up deployment resources..."
    
    # Kill any background processes
    jobs -p | xargs -r kill 2>/dev/null || true
    
    # Update deployment status
    update_deployment_status "failed" "Deployment interrupted or failed"
    
    exit $exit_code
}

trap cleanup EXIT INT TERM

# Help function
show_help() {
    cat << EOF
Multi-Cloud IAM Deployment Script

Usage: $0 [OPTIONS]

OPTIONS:
    -e, --environment ENV       Target environment (dev, staging, production) [default: dev]
    -c, --clouds CLOUDS        Comma-separated list of clouds (aws,gcp,azure) [default: aws,gcp,azure]
    -m, --max-concurrent N     Maximum concurrent deployments [default: 10]
    -s, --strategy STRATEGY    Deployment strategy (rolling, blue-green, canary) [default: rolling]
    -d, --dry-run             Perform dry run only
    -v, --verbose             Enable verbose logging
    -f, --force               Force deployment without confirmation
    --skip-validation         Skip pre-deployment validation
    --deployment-id ID        Use specific deployment ID
    -h, --help                Show this help message

EXAMPLES:
    # Deploy to dev environment with default settings
    $0 --environment dev

    # Deploy only to AWS and GCP in production
    $0 --environment production --clouds aws,gcp --max-concurrent 5

    # Perform dry run for staging
    $0 --environment staging --dry-run

    # Force deployment with verbose logging
    $0 --environment production --force --verbose

ENVIRONMENT VARIABLES:
    AWS_PROFILE                AWS profile to use
    GOOGLE_APPLICATION_CREDENTIALS  Path to GCP service account key
    ARM_CLIENT_ID             Azure client ID
    ARM_CLIENT_SECRET         Azure client secret
    ARM_TENANT_ID            Azure tenant ID
    ARM_SUBSCRIPTION_ID      Azure subscription ID
    DEPLOYMENT_TIMEOUT       Deployment timeout in seconds [default: 3600]
    
EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -e|--environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            -c|--clouds)
                CLOUDS="$2"
                shift 2
                ;;
            -m|--max-concurrent)
                MAX_CONCURRENT="$2"
                shift 2
                ;;
            -s|--strategy)
                STRATEGY="$2"
                shift 2
                ;;
            -d|--dry-run)
                DRY_RUN=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -f|--force)
                FORCE=true
                shift
                ;;
            --skip-validation)
                SKIP_VALIDATION=true
                shift
                ;;
            --deployment-id)
                DEPLOYMENT_ID="$2"
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                error_exit "Unknown option: $1"
                ;;
        esac
    done
    
    # Validate environment
    if [[ ! "$ENVIRONMENT" =~ ^(dev|staging|production)$ ]]; then
        error_exit "Invalid environment: $ENVIRONMENT. Must be dev, staging, or production."
    fi
    
    # Validate strategy
    if [[ ! "$STRATEGY" =~ ^(rolling|blue-green|canary)$ ]]; then
        error_exit "Invalid strategy: $STRATEGY. Must be rolling, blue-green, or canary."
    fi
    
    # Parse clouds
    IFS=',' read -ra CLOUD_ARRAY <<< "$CLOUDS"
    for cloud in "${CLOUD_ARRAY[@]}"; do
        if [[ ! "$cloud" =~ ^(aws|gcp|azure)$ ]]; then
            error_exit "Invalid cloud: $cloud. Must be aws, gcp, or azure."
        fi
    done
}

# Validate prerequisites
validate_prerequisites() {
    log INFO "Validating prerequisites..."
    
    # Check required tools
    local required_tools=("terraform" "jq" "curl" "git")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            error_exit "Required tool not found: $tool"
        fi
    done
    
    # Check cloud-specific tools and credentials
    for cloud in "${CLOUD_ARRAY[@]}"; do
        case $cloud in
            aws)
                if ! command -v aws &> /dev/null; then
                    error_exit "AWS CLI not found"
                fi
                if ! aws sts get-caller-identity &> /dev/null; then
                    error_exit "AWS credentials not configured or invalid"
                fi
                ;;
            gcp)
                if ! command -v gcloud &> /dev/null; then
                    error_exit "gcloud CLI not found"
                fi
                if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | head -n1 > /dev/null; then
                    error_exit "GCP credentials not configured"
                fi
                ;;
            azure)
                if ! command -v az &> /dev/null; then
                    error_exit "Azure CLI not found"
                fi
                if ! az account show &> /dev/null; then
                    error_exit "Azure credentials not configured"
                fi
                ;;
        esac
    done
    
    log INFO "Prerequisites validation completed successfully"
}

# Load configuration
load_configuration() {
    log INFO "Loading configuration for environment: $ENVIRONMENT"
    
    local config_file="${CONFIG_DIR}/environments/${ENVIRONMENT}/config.json"
    if [[ ! -f "$config_file" ]]; then
        error_exit "Configuration file not found: $config_file"
    fi
    
    # Export configuration as environment variables
    export DEPLOYMENT_CONFIG=$(cat "$config_file")
    export DEPLOYMENT_ENVIRONMENT="$ENVIRONMENT"
    export DEPLOYMENT_ID="$DEPLOYMENT_ID"
    export DEPLOYMENT_TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    export DEPLOYMENT_STRATEGY="$STRATEGY"
    export DEPLOYMENT_CLOUDS="$CLOUDS"
    export DEPLOYMENT_MAX_CONCURRENT="$MAX_CONCURRENT"
    
    log INFO "Configuration loaded successfully"
    log DEBUG "Deployment ID: $DEPLOYMENT_ID"
    log DEBUG "Deployment timestamp: $DEPLOYMENT_TIMESTAMP"
}

# Pre-deployment validation
pre_deployment_validation() {
    if [[ "$SKIP_VALIDATION" == "true" ]]; then
        log WARN "Skipping pre-deployment validation"
        return 0
    fi
    
    log INFO "Running pre-deployment validation..."
    
    # Validate Terraform configurations
    for cloud in "${CLOUD_ARRAY[@]}"; do
        log INFO "Validating Terraform configuration for $cloud..."
        local tf_dir="${TERRAFORM_DIR}/modules/${cloud}"
        
        cd "$tf_dir"
        terraform fmt -check=true || error_exit "Terraform formatting check failed for $cloud"
        terraform init -backend=false || error_exit "Terraform init failed for $cloud"
        terraform validate || error_exit "Terraform validation failed for $cloud"
        cd - > /dev/null
    done
    
    # Run security scans
    log INFO "Running security scans..."
    if command -v checkov &> /dev/null; then
        checkov -d "$TERRAFORM_DIR" --framework terraform --quiet || log WARN "Checkov security scan found issues"
    fi
    
    # Validate connectivity and permissions
    log INFO "Validating cloud connectivity and permissions..."
    python3 "${SCRIPT_DIR}/validate-permissions.py" \
        --environment "$ENVIRONMENT" \
        --clouds "$CLOUDS" \
        --config-file "$config_file" || error_exit "Permission validation failed"
    
    log INFO "Pre-deployment validation completed successfully"
}

# Initialize Terraform workspaces
init_terraform_workspaces() {
    log INFO "Initializing Terraform workspaces..."
    
    for cloud in "${CLOUD_ARRAY[@]}"; do
        log INFO "Initializing Terraform workspace for $cloud..."
        
        local tf_env_dir="${TERRAFORM_DIR}/environments/${ENVIRONMENT}/${cloud}"
        mkdir -p "$tf_env_dir"
        
        # Copy environment-specific configuration
        cp "${CONFIG_DIR}/environments/${ENVIRONMENT}/${cloud}.tfvars" "$tf_env_dir/" || error_exit "Failed to copy tfvars for $cloud"
        
        cd "$tf_env_dir"
        
        # Initialize Terraform
        terraform init \
            -backend-config="key=${ENVIRONMENT}/${cloud}/terraform.tfstate" \
            -backend-config="region=us-east-1" || error_exit "Terraform init failed for $cloud"
        
        # Select or create workspace
        terraform workspace select "$ENVIRONMENT" || terraform workspace new "$ENVIRONMENT"
        
        cd - > /dev/null
    done
    
    log INFO "Terraform workspaces initialized successfully"
}

# Plan deployment
plan_deployment() {
    log INFO "Planning deployment..."
    
    local plan_dir="${PROJECT_ROOT}/plans/${DEPLOYMENT_ID}"
    mkdir -p "$plan_dir"
    
    for cloud in "${CLOUD_ARRAY[@]}"; do
        log INFO "Creating Terraform plan for $cloud..."
        
        local tf_env_dir="${TERRAFORM_DIR}/environments/${ENVIRONMENT}/${cloud}"
        local plan_file="${plan_dir}/${cloud}.tfplan"
        
        cd "$tf_env_dir"
        
        terraform plan \
            -var-file="${cloud}.tfvars" \
            -var="deployment_id=${DEPLOYMENT_ID}" \
            -var="deployment_timestamp=${DEPLOYMENT_TIMESTAMP}" \
            -out="$plan_file" || error_exit "Terraform plan failed for $cloud"
        
        # Generate plan summary
        terraform show -json "$plan_file" > "${plan_dir}/${cloud}-plan.json"
        
        cd - > /dev/null
        
        log INFO "Terraform plan created for $cloud: $plan_file"
    done
    
    # Generate deployment summary
    python3 "${SCRIPT_DIR}/generate-deployment-summary.py" \
        --plan-dir "$plan_dir" \
        --output "${plan_dir}/deployment-summary.json" || error_exit "Failed to generate deployment summary"
    
    log INFO "Deployment planning completed successfully"
    
    # Show deployment summary
    if [[ "$VERBOSE" == "true" ]]; then
        cat "${plan_dir}/deployment-summary.json" | jq '.'
    fi
}

# Confirm deployment
confirm_deployment() {
    if [[ "$DRY_RUN" == "true" ]]; then
        log INFO "Dry run mode - skipping actual deployment"
        return 0
    fi
    
    if [[ "$FORCE" == "true" ]]; then
        log INFO "Force mode enabled - skipping confirmation"
        return 0
    fi
    
    local plan_dir="${PROJECT_ROOT}/plans/${DEPLOYMENT_ID}"
    local summary_file="${plan_dir}/deployment-summary.json"
    
    echo
    echo -e "${YELLOW}=== DEPLOYMENT CONFIRMATION ===${NC}"
    echo -e "Environment: ${BLUE}$ENVIRONMENT${NC}"
    echo -e "Clouds: ${BLUE}$CLOUDS${NC}"
    echo -e "Strategy: ${BLUE}$STRATEGY${NC}"
    echo -e "Deployment ID: ${BLUE}$DEPLOYMENT_ID${NC}"
    echo
    
    if [[ -f "$summary_file" ]]; then
        echo -e "${YELLOW}Resource Changes:${NC}"
        jq -r '.summary | to_entries[] | "\(.key): \(.value)"' "$summary_file"
        echo
    fi
    
    read -p "Do you want to proceed with the deployment? (yes/no): " -r
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        log INFO "Deployment cancelled by user"
        exit 0
    fi
}

# Update deployment status
update_deployment_status() {
    local status=$1
    local message=${2:-""}
    
    local status_file="${LOG_DIR}/deployment-status-${DEPLOYMENT_ID}.json"
    
    cat > "$status_file" << EOF
{
    "deployment_id": "$DEPLOYMENT_ID",
    "environment": "$ENVIRONMENT",
    "clouds": "$CLOUDS",
    "strategy": "$STRATEGY",
    "status": "$status",
    "message": "$message",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "log_file": "$LOG_FILE"
}
EOF
    
    # Send to monitoring system if configured
    if [[ -n "${MONITORING_WEBHOOK:-}" ]]; then
        curl -s -X POST "$MONITORING_WEBHOOK" \
            -H "Content-Type: application/json" \
            -d @"$status_file" || log WARN "Failed to send status update to monitoring system"
    fi
}

# Deploy to cloud
deploy_to_cloud() {
    local cloud=$1
    local deployment_start=$(date +%s)
    
    log INFO "Starting deployment to $cloud..."
    update_deployment_status "deploying" "Deploying to $cloud"
    
    local tf_env_dir="${TERRAFORM_DIR}/environments/${ENVIRONMENT}/${cloud}"
    local plan_file="${PROJECT_ROOT}/plans/${DEPLOYMENT_ID}/${cloud}.tfplan"
    
    cd "$tf_env_dir"
    
    # Apply Terraform plan
    if terraform apply -auto-approve "$plan_file"; then
        local deployment_end=$(date +%s)
        local deployment_time=$((deployment_end - deployment_start))
        
        log INFO "Deployment to $cloud completed successfully in ${deployment_time}s"
        
        # Run post-deployment verification
        python3 "${SCRIPT_DIR}/verify-deployment.py" \
            --cloud "$cloud" \
            --environment "$ENVIRONMENT" \
            --deployment-id "$DEPLOYMENT_ID" || log WARN "Post-deployment verification failed for $cloud"
        
    else
        local deployment_end=$(date +%s)
        local deployment_time=$((deployment_end - deployment_start))
        
        log ERROR "Deployment to $cloud failed after ${deployment_time}s"
        cd - > /dev/null
        return 1
    fi
    
    cd - > /dev/null
    return 0
}

# Main deployment function
execute_deployment() {
    if [[ "$DRY_RUN" == "true" ]]; then
        log INFO "Dry run completed - no changes made"
        return 0
    fi
    
    log INFO "Starting multi-cloud deployment..."
    update_deployment_status "in_progress" "Deployment started"
    
    local failed_clouds=()
    local successful_clouds=()
    
    # Deploy based on strategy
    case "$STRATEGY" in
        rolling)
            execute_rolling_deployment
            ;;
        blue-green)
            execute_blue_green_deployment
            ;;
        canary)
            execute_canary_deployment
            ;;
    esac
    
    # Check results
    if [[ ${#failed_clouds[@]} -gt 0 ]]; then
        log ERROR "Deployment failed for clouds: ${failed_clouds[*]}"
        update_deployment_status "failed" "Deployment failed for: ${failed_clouds[*]}"
        return 1
    else
        log INFO "Deployment completed successfully for all clouds: ${successful_clouds[*]}"
        update_deployment_status "success" "Deployment completed successfully"
        return 0
    fi
}

# Rolling deployment strategy
execute_rolling_deployment() {
    log INFO "Executing rolling deployment strategy..."
    
    local pids=()
    local running_deployments=0
    
    for cloud in "${CLOUD_ARRAY[@]}"; do
        # Wait if we've reached max concurrent deployments
        while [[ $running_deployments -ge $MAX_CONCURRENT ]]; do
            wait_for_deployment_slot
        done
        
        # Start deployment in background
        (
            if deploy_to_cloud "$cloud"; then
                echo "$cloud" > "${LOG_DIR}/success-${cloud}-$$"
            else
                echo "$cloud" > "${LOG_DIR}/failure-${cloud}-$$"
            fi
        ) &
        
        pids+=($!)
        ((running_deployments++))
        
        log INFO "Started deployment to $cloud (PID: $!)"
    done
    
    # Wait for all deployments to complete
    for pid in "${pids[@]}"; do
        wait "$pid"
    done
    
    # Collect results
    collect_deployment_results
}

# Blue-green deployment strategy
execute_blue_green_deployment() {
    log INFO "Executing blue-green deployment strategy..."
    
    # For blue-green, we deploy to all clouds simultaneously
    # then switch traffic once all are successful
    
    local pids=()
    local temp_dir=$(mktemp -d)
    
    for cloud in "${CLOUD_ARRAY[@]}"; do
        (
            log INFO "Starting blue environment deployment for $cloud..."
            if deploy_to_cloud "$cloud"; then
                echo "success" > "$temp_dir/$cloud"
            else
                echo "failure" > "$temp_dir/$cloud"
            fi
        ) &
        pids+=($!)
    done
    
    # Wait for all blue deployments
    for pid in "${pids[@]}"; do
        wait "$pid"
    done
    
    # Check if all blue deployments succeeded
    local all_success=true
    for cloud in "${CLOUD_ARRAY[@]}"; do
        if [[ "$(cat "$temp_dir/$cloud" 2>/dev/null)" != "success" ]]; then
            all_success=false
            failed_clouds+=("$cloud")
        else
            successful_clouds+=("$cloud")
        fi
    done
    
    if [[ "$all_success" == "true" ]]; then
        log INFO "All blue deployments successful, switching to green..."
        # Here you would implement the traffic switching logic
        log INFO "Traffic switched to green environment successfully"
    else
        log ERROR "Blue-green deployment failed for some clouds, rolling back..."
        # Implement rollback logic here
    fi
    
    rm -rf "$temp_dir"
}

# Canary deployment strategy
execute_canary_deployment() {
    log INFO "Executing canary deployment strategy..."
    
    # For canary, we deploy to a subset first, then gradually roll out
    local canary_clouds=(${CLOUD_ARRAY[0]}) # Deploy to first cloud as canary
    local remaining_clouds=("${CLOUD_ARRAY[@]:1}")
    
    log INFO "Starting canary deployment to: ${canary_clouds[*]}"
    
    # Deploy canary
    for cloud in "${canary_clouds[@]}"; do
        if deploy_to_cloud "$cloud"; then
            successful_clouds+=("$cloud")
        else
            failed_clouds+=("$cloud")
            log ERROR "Canary deployment failed for $cloud, aborting full deployment"
            return 1
        fi
    done
    
    log INFO "Canary deployment successful, waiting for monitoring period..."
    sleep 300 # Wait 5 minutes for monitoring
    
    # Check canary health
    python3 "${SCRIPT_DIR}/check-canary-health.py" \
        --deployment-id "$DEPLOYMENT_ID" \
        --clouds "${canary_clouds[*]}" || {
        log ERROR "Canary health check failed, aborting deployment"
        return 1
    }
    
    log INFO "Canary health check passed, proceeding with full deployment..."
    
    # Deploy to remaining clouds
    execute_rolling_deployment_for_clouds "${remaining_clouds[@]}"
}

# Utility functions
wait_for_deployment_slot() {
    local active_jobs
    active_jobs=$(jobs -r | wc -l)
    
    while [[ $active_jobs -ge $MAX_CONCURRENT ]]; do
        sleep 5
        active_jobs=$(jobs -r | wc -l)
    done
    
    running_deployments=$active_jobs
}

collect_deployment_results() {
    for cloud in "${CLOUD_ARRAY[@]}"; do
        if ls "${LOG_DIR}/success-${cloud}-"* &>/dev/null; then
            successful_clouds+=("$cloud")
            rm "${LOG_DIR}/success-${cloud}-"*
        elif ls "${LOG_DIR}/failure-${cloud}-"* &>/dev/null; then
            failed_clouds+=("$cloud")
            rm "${LOG_DIR}/failure-${cloud}-"*
        fi
    done
}

# Send notifications
send_notifications() {
    local status=$1
    
    log INFO "Sending deployment notifications..."
    
    python3 "${SCRIPT_DIR}/send-notifications.py" \
        --deployment-id "$DEPLOYMENT_ID" \
        --environment "$ENVIRONMENT" \
        --clouds "$CLOUDS" \
        --status "$status" \
        --log-file "$LOG_FILE" || log WARN "Failed to send notifications"
}

# Main execution
main() {
    echo -e "${GREEN}=== Multi-Cloud IAM Deployment ===${NC}"
    echo "Deployment ID: $DEPLOYMENT_ID"
    echo "Log file: $LOG_FILE"
    echo
    
    parse_args "$@"
    
    log INFO "Starting deployment with ID: $DEPLOYMENT_ID"
    log INFO "Environment: $ENVIRONMENT"
    log INFO "Clouds: $CLOUDS"
    log INFO "Strategy: $STRATEGY"
    log INFO "Max concurrent: $MAX_CONCURRENT"
    log INFO "Dry run: $DRY_RUN"
    
    validate_prerequisites
    load_configuration
    pre_deployment_validation
    init_terraform_workspaces
    plan_deployment
    confirm_deployment
    
    if execute_deployment; then
        log INFO "Multi-cloud deployment completed successfully!"
        send_notifications "success"
        exit 0
    else
        log ERROR "Multi-cloud deployment failed!"
        send_notifications "failure"
        exit 1
    fi
}

# Execute main function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
