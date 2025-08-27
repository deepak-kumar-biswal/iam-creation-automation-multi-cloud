# IAM Automation Troubleshooting Guide

## Common Issues and Solutions

### 1. Authentication and Authorization Errors

#### Problem: API Authentication Failures
**Symptoms:**
- `401 Unauthorized` responses from API calls
- "Invalid API token" error messages
- JWT token expiration errors

**Solutions:**
```bash
# Check token validity
curl -H "Authorization: Bearer ${API_TOKEN}" \
     https://api.iam-automation.com/v1/auth/validate

# Refresh expired token
curl -X POST https://api.iam-automation.com/v1/auth/refresh \
     -H "Content-Type: application/json" \
     -d '{"refreshToken":"your-refresh-token"}'

# Verify token permissions
jwt-decode $API_TOKEN | jq '.permissions'
```

#### Problem: Cross-Cloud Permission Issues
**Symptoms:**
- AWS role assumption failures
- Azure service principal authentication errors
- GCP service account key validation failures

**Solutions:**
```bash
# Test AWS role assumption
aws sts assume-role \
    --role-arn arn:aws:iam::123456789012:role/IAMAutomationRole \
    --role-session-name test-session

# Verify Azure service principal
az login --service-principal \
    --username ${AZURE_CLIENT_ID} \
    --password ${AZURE_CLIENT_SECRET} \
    --tenant ${AZURE_TENANT_ID}

# Test GCP service account
gcloud auth activate-service-account \
    --key-file=service-account-key.json
gcloud auth list
```

### 2. User Provisioning Failures

#### Problem: User Creation Fails Across Multiple Clouds
**Symptoms:**
- Partial user creation (success in AWS, failure in Azure/GCP)
- Inconsistent user attributes across clouds
- Email validation errors

**Solutions:**
```bash
# Check user creation status
curl -X GET https://api.iam-automation.com/v1/users/${USER_ID}/status \
     -H "Authorization: Bearer ${API_TOKEN}"

# Retry failed cloud provisioning
curl -X POST https://api.iam-automation.com/v1/users/${USER_ID}/retry \
     -H "Authorization: Bearer ${API_TOKEN}" \
     -d '{"cloudProviders":["azure","gcp"]}'

# Validate email format
echo "john.doe@company.com" | grep -E "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
```

#### Problem: Duplicate User Detection
**Symptoms:**
- "User already exists" errors
- Conflicts with existing usernames
- Email address conflicts

**Solutions:**
```bash
# Search for existing users
curl -X GET "https://api.iam-automation.com/v1/users/search?email=john.doe@company.com" \
     -H "Authorization: Bearer ${API_TOKEN}"

# Force update existing user
curl -X PUT https://api.iam-automation.com/v1/users/${USER_ID} \
     -H "Authorization: Bearer ${API_TOKEN}" \
     -d '{"force":true,"mergeAttributes":true}'
```

### 3. Role and Policy Management Issues

#### Problem: Policy Validation Failures
**Symptoms:**
- Invalid JSON syntax in policies
- Overly permissive policy warnings
- Compliance framework violations

**Solutions:**
```bash
# Validate policy syntax
python -c "
import json
with open('policy.json', 'r') as f:
    policy = json.load(f)
    print('Policy JSON is valid')
"

# Test policy with AWS Policy Simulator
aws iam simulate-principal-policy \
    --policy-source-arn arn:aws:iam::123456789012:user/test-user \
    --action-names s3:GetObject \
    --resource-arns arn:aws:s3:::test-bucket/test-key

# Check compliance violations
curl -X POST https://api.iam-automation.com/v1/policies/validate \
     -H "Authorization: Bearer ${API_TOKEN}" \
     -d @policy-document.json
```

#### Problem: Role Assignment Conflicts
**Symptoms:**
- "Role already assigned" errors
- Circular role dependencies
- Maximum role limits exceeded

**Solutions:**
```bash
# List current role assignments
curl -X GET https://api.iam-automation.com/v1/users/${USER_ID}/roles \
     -H "Authorization: Bearer ${API_TOKEN}"

# Check for circular dependencies
curl -X GET https://api.iam-automation.com/v1/roles/${ROLE_ID}/dependencies \
     -H "Authorization: Bearer ${API_TOKEN}"

# Remove conflicting assignments
curl -X DELETE https://api.iam-automation.com/v1/users/${USER_ID}/roles/${ROLE_ID} \
     -H "Authorization: Bearer ${API_TOKEN}"
```

### 4. Terraform Integration Issues

#### Problem: Terraform State Conflicts
**Symptoms:**
- State lock acquisition failures
- Resource import errors
- Drift between Terraform and actual resources

**Solutions:**
```bash
# Release stuck state lock
terraform force-unlock LOCK_ID

# Import existing resources
terraform import aws_iam_user.example john.doe
terraform import azuread_user.example 12345678-1234-1234-1234-123456789012

# Refresh state
terraform refresh -var-file="environments/prod.tfvars"

# Plan with detailed output
terraform plan -out=tfplan -detailed-exitcode
terraform show -json tfplan | jq '.resource_changes'
```

#### Problem: Provider Configuration Issues
**Symptoms:**
- Multiple provider instances conflicts
- Region mismatch errors
- Credential configuration problems

**Solutions:**
```hcl
# Properly configure multiple AWS providers
provider "aws" {
  alias  = "us-east-1"
  region = "us-east-1"
}

provider "aws" {
  alias  = "us-west-2"
  region = "us-west-2"
}

# Use explicit provider references
resource "aws_iam_user" "example" {
  provider = aws.us-east-1
  name     = "john.doe"
}
```

### 5. API Gateway and Lambda Issues

#### Problem: Lambda Function Timeouts
**Symptoms:**
- 504 Gateway Timeout errors
- Lambda function execution timeouts
- Cold start performance issues

**Solutions:**
```bash
# Increase Lambda timeout
aws lambda update-function-configuration \
    --function-name iam-automation-api \
    --timeout 300

# Configure provisioned concurrency
aws lambda put-provisioned-concurrency-config \
    --function-name iam-automation-api \
    --qualifier LIVE \
    --provisioned-concurrency-level 10

# Monitor Lambda metrics
aws cloudwatch get-metric-statistics \
    --namespace AWS/Lambda \
    --metric-name Duration \
    --dimensions Name=FunctionName,Value=iam-automation-api \
    --start-time 2024-01-15T00:00:00Z \
    --end-time 2024-01-15T23:59:59Z \
    --period 3600 \
    --statistics Average,Maximum
```

#### Problem: API Gateway Rate Limiting
**Symptoms:**
- 429 Too Many Requests errors
- Throttling in API Gateway logs
- Uneven request distribution

**Solutions:**
```bash
# Check API Gateway throttling settings
aws apigateway get-usage-plan --usage-plan-id ${USAGE_PLAN_ID}

# Update throttling limits
aws apigateway update-usage-plan \
    --usage-plan-id ${USAGE_PLAN_ID} \
    --patch-ops op=replace,path=/throttle/rateLimit,value=1000 \
                op=replace,path=/throttle/burstLimit,value=2000

# Monitor API Gateway metrics
aws cloudwatch get-metric-statistics \
    --namespace AWS/ApiGateway \
    --metric-name 4XXError \
    --dimensions Name=ApiName,Value=iam-automation-api
```

### 6. Database and State Management

#### Problem: DynamoDB Throttling
**Symptoms:**
- ProvisionedThroughputExceededException errors
- High consumed read/write capacity
- Slow API responses

**Solutions:**
```bash
# Enable auto-scaling
aws application-autoscaling register-scalable-target \
    --service-namespace dynamodb \
    --resource-id table/iam-automation-users \
    --scalable-dimension dynamodb:table:WriteCapacityUnits \
    --min-capacity 5 \
    --max-capacity 100

# Check consumed capacity
aws dynamodb describe-table --table-name iam-automation-users \
    --query 'Table.ConsumedThroughput'

# Enable DynamoDB Accelerator (DAX)
aws dax create-cluster \
    --cluster-name iam-automation-cache \
    --node-type dax.r4.large \
    --replication-factor 3
```

#### Problem: Data Consistency Issues
**Symptoms:**
- Stale data in API responses
- Eventual consistency problems
- Cross-region replication lag

**Solutions:**
```bash
# Use strong consistency for critical reads
aws dynamodb get-item \
    --table-name iam-automation-users \
    --key '{"userId":{"S":"usr_123456"}}' \
    --consistent-read

# Implement retry logic with exponential backoff
for i in {1..5}; do
    result=$(aws dynamodb get-item --table-name iam-automation-users \
                                   --key '{"userId":{"S":"usr_123456"}}')
    if [ $? -eq 0 ]; then
        echo "Success on attempt $i"
        break
    fi
    sleep $((2**i))
done
```

### 7. Monitoring and Alerting Issues

#### Problem: Missing or Inaccurate Metrics
**Symptoms:**
- Gaps in CloudWatch metrics
- Incorrect alert thresholds
- False positive alerts

**Solutions:**
```bash
# Verify metric filters
aws logs describe-metric-filters \
    --log-group-name /aws/lambda/iam-automation-api

# Test alarm configuration
aws cloudwatch set-alarm-state \
    --alarm-name IAMAutomation-HighErrorRate \
    --state-value ALARM \
    --state-reason "Testing alarm configuration"

# Create custom metrics
aws cloudwatch put-metric-data \
    --namespace "IAMAutomation/API" \
    --metric-data MetricName=UserCreations,Value=1,Unit=Count
```

#### Problem: Log Aggregation Issues
**Symptoms:**
- Missing log entries
- Log format inconsistencies
- Difficulty correlating logs across services

**Solutions:**
```bash
# Configure structured logging
export LOG_FORMAT=json
export LOG_LEVEL=INFO
export CORRELATION_ID_HEADER=X-Correlation-ID

# Search logs with correlation ID
aws logs filter-log-events \
    --log-group-name /aws/lambda/iam-automation-api \
    --filter-pattern "[timestamp, requestId=\"req_123456*\"]"

# Set up log streaming to external systems
aws logs create-export-task \
    --log-group-name /aws/lambda/iam-automation-api \
    --from 1640995200000 \
    --to 1641081600000 \
    --destination s3://log-archive-bucket/lambda-logs/
```

### 8. Security and Compliance Issues

#### Problem: Failed Compliance Scans
**Symptoms:**
- Compliance framework violations
- Security policy deviations
- Audit findings

**Solutions:**
```bash
# Run compliance check
curl -X POST https://api.iam-automation.com/v1/compliance/scan \
     -H "Authorization: Bearer ${API_TOKEN}" \
     -d '{"framework":"sox","scope":"all"}'

# Remediate common violations
# Remove excessive permissions
aws iam detach-user-policy \
    --user-name overprivileged-user \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Enable MFA enforcement
aws iam put-user-policy \
    --user-name ${USERNAME} \
    --policy-name EnforceMFA \
    --policy-document file://enforce-mfa-policy.json
```

#### Problem: Encryption and Data Protection
**Symptoms:**
- Unencrypted data at rest
- Weak encryption algorithms
- Key management issues

**Solutions:**
```bash
# Enable DynamoDB encryption
aws dynamodb update-table \
    --table-name iam-automation-users \
    --sse-specification Enabled=true,SSEType=KMS,KMSMasterKeyId=arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012

# Rotate KMS keys
aws kms enable-key-rotation \
    --key-id 12345678-1234-1234-1234-123456789012

# Encrypt Lambda environment variables
aws lambda update-function-configuration \
    --function-name iam-automation-api \
    --kms-key-arn arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012
```

## Performance Optimization

### 1. API Response Time Optimization
```bash
# Enable API Gateway caching
aws apigateway put-method \
    --rest-api-id ${API_ID} \
    --resource-id ${RESOURCE_ID} \
    --http-method GET \
    --cache-namespace ${CACHE_NAMESPACE} \
    --cache-key-parameters method.request.querystring.userId

# Implement Lambda response caching
redis-cli SET "user:${USER_ID}" "${USER_DATA}" EX 300
```

### 2. Database Performance Tuning
```bash
# Optimize DynamoDB queries
aws dynamodb query \
    --table-name iam-automation-users \
    --index-name DepartmentIndex \
    --key-condition-expression "Department = :dept" \
    --expression-attribute-values '{":dept":{"S":"Engineering"}}'

# Use batch operations for bulk updates
aws dynamodb batch-write-item \
    --request-items file://batch-write-request.json
```

### 3. Cost Optimization
```bash
# Monitor cost and usage
aws ce get-cost-and-usage \
    --time-period Start=2024-01-01,End=2024-01-31 \
    --granularity MONTHLY \
    --metrics BlendedCost \
    --group-by Type=DIMENSION,Key=SERVICE

# Optimize Lambda memory allocation
aws lambda update-function-configuration \
    --function-name iam-automation-api \
    --memory-size 512
```

## Emergency Procedures

### 1. Service Outage Response
```bash
# Check service health
curl -f https://api.iam-automation.com/health || echo "Service is down"

# Failover to backup region
aws route53 change-resource-record-sets \
    --hosted-zone-id Z123456789 \
    --change-batch file://failover-changeset.json

# Scale up backup infrastructure
aws application-autoscaling set-scalable-target-capacity \
    --service-namespace ecs \
    --scalable-dimension ecs:service:DesiredCount \
    --resource-id service/iam-automation-cluster/iam-automation-service \
    --capacity 10
```

### 2. Data Recovery Procedures
```bash
# Restore from backup
aws dynamodb restore-table-from-backup \
    --target-table-name iam-automation-users-restored \
    --backup-arn arn:aws:dynamodb:us-east-1:123456789012:table/iam-automation-users/backup/01640995200000-12345678

# Point-in-time recovery
aws dynamodb restore-table-to-point-in-time \
    --source-table-name iam-automation-users \
    --target-table-name iam-automation-users-recovered \
    --restore-date-time 2024-01-15T12:00:00Z
```

### 3. Security Incident Response
```bash
# Disable compromised API keys
curl -X DELETE https://api.iam-automation.com/v1/auth/tokens/${TOKEN_ID} \
     -H "Authorization: Bearer ${ADMIN_TOKEN}"

# Audit recent activities
curl -X GET "https://api.iam-automation.com/v1/audit/events?startDate=2024-01-15T00:00:00Z&severity=high" \
     -H "Authorization: Bearer ${ADMIN_TOKEN}"

# Force password reset for affected users
curl -X POST https://api.iam-automation.com/v1/users/${USER_ID}/force-password-reset \
     -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

## Support Escalation

### Level 1 Support
- Check service status page
- Review common issues documentation
- Search knowledge base
- Contact: support@iam-automation.com

### Level 2 Support
- Deep dive troubleshooting
- Log analysis and correlation
- Performance optimization
- Contact: engineering@iam-automation.com

### Level 3 Support
- Architecture and design issues
- Emergency security responses
- Critical system failures
- Contact: +1-555-IAM-HELP (24/7)

### Vendor Support
- Cloud provider support tickets
- Third-party integration issues
- Infrastructure-level problems
