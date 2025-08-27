# IAM Automation API Reference

## Overview

This document provides comprehensive API documentation for the IAM Automation System, including REST endpoints, authentication mechanisms, and integration patterns for multi-cloud IAM management.

## Authentication

### API Token Authentication
```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Service Account Authentication (Kubernetes)
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: iam-automation-sa
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/IAMAutomationRole
```

### Cross-Cloud Authentication
```json
{
  "aws": {
    "roleArn": "arn:aws:iam::account:role/IAMAutomationRole",
    "externalId": "unique-external-id"
  },
  "azure": {
    "tenantId": "tenant-id",
    "clientId": "client-id",
    "clientSecret": "client-secret"
  },
  "gcp": {
    "projectId": "project-id",
    "serviceAccountKey": "base64-encoded-key"
  }
}
```

## Core API Endpoints

### User Management

#### Create User
**Endpoint:** `POST /api/v1/users`

**Request Body:**
```json
{
  "username": "john.doe",
  "email": "john.doe@company.com",
  "firstName": "John",
  "lastName": "Doe",
  "department": "Engineering",
  "manager": "jane.smith",
  "cloudProviders": ["aws", "azure", "gcp"],
  "temporaryAccess": {
    "enabled": false,
    "expiryDate": "2024-12-31T23:59:59Z"
  },
  "customAttributes": {
    "costCenter": "CC-1234",
    "employeeId": "EMP-5678"
  }
}
```

**Response:**
```json
{
  "statusCode": 201,
  "data": {
    "userId": "usr_abc123def456",
    "username": "john.doe",
    "status": "active",
    "createdAt": "2024-01-15T10:30:00Z",
    "cloudAccounts": {
      "aws": {
        "accountId": "123456789012",
        "userId": "AIDACKCEVSQ6C2EXAMPLE",
        "status": "created"
      },
      "azure": {
        "tenantId": "12345678-1234-1234-1234-123456789012",
        "objectId": "87654321-4321-4321-4321-210987654321",
        "status": "created"
      },
      "gcp": {
        "projectId": "my-project-12345",
        "userId": "user.john.doe@my-project-12345.iam.gserviceaccount.com",
        "status": "created"
      }
    }
  }
}
```

#### Update User
**Endpoint:** `PUT /api/v1/users/{userId}`

**Request Body:**
```json
{
  "department": "Platform Engineering",
  "manager": "mike.johnson",
  "customAttributes": {
    "costCenter": "CC-5678"
  }
}
```

#### Delete User
**Endpoint:** `DELETE /api/v1/users/{userId}`

**Query Parameters:**
- `dryRun` (boolean): Preview changes without executing
- `force` (boolean): Force deletion even with active sessions
- `backup` (boolean): Create backup before deletion

**Response:**
```json
{
  "statusCode": 200,
  "data": {
    "userId": "usr_abc123def456",
    "deletionStatus": {
      "aws": "completed",
      "azure": "completed", 
      "gcp": "completed"
    },
    "backupLocation": "s3://iam-automation-backups/users/usr_abc123def456.json",
    "deletedAt": "2024-01-15T15:45:00Z"
  }
}
```

### Role Management

#### Create Role
**Endpoint:** `POST /api/v1/roles`

**Request Body:**
```json
{
  "roleName": "DataEngineerRole",
  "description": "Role for data engineering team with read access to data lakes",
  "cloudProviders": ["aws", "azure", "gcp"],
  "policies": [
    {
      "provider": "aws",
      "policyArn": "arn:aws:iam::123456789012:policy/DataEngineerPolicy",
      "attachmentType": "managed"
    },
    {
      "provider": "azure", 
      "roleDefinitionId": "/subscriptions/sub-id/providers/Microsoft.Authorization/roleDefinitions/role-id",
      "scope": "/subscriptions/sub-id/resourceGroups/data-rg"
    },
    {
      "provider": "gcp",
      "role": "roles/bigquery.dataViewer",
      "condition": {
        "title": "Time-based access",
        "description": "Access only during business hours",
        "expression": "request.time.getHours() >= 9 && request.time.getHours() <= 17"
      }
    }
  ],
  "maxSessionDuration": 3600,
  "mfaRequired": true,
  "ipRestrictions": ["192.168.1.0/24", "10.0.0.0/8"]
}
```

**Response:**
```json
{
  "statusCode": 201,
  "data": {
    "roleId": "rol_xyz789uvw012",
    "roleName": "DataEngineerRole",
    "cloudRoles": {
      "aws": {
        "roleArn": "arn:aws:iam::123456789012:role/DataEngineerRole",
        "assumeRolePolicy": "..."
      },
      "azure": {
        "roleAssignmentId": "12345678-1234-1234-1234-123456789012",
        "scope": "/subscriptions/sub-id/resourceGroups/data-rg"
      },
      "gcp": {
        "name": "projects/my-project/roles/DataEngineerRole",
        "bindings": ["..."]
      }
    },
    "createdAt": "2024-01-15T11:00:00Z"
  }
}
```

### Policy Management

#### Create Policy
**Endpoint:** `POST /api/v1/policies`

**Request Body:**
```json
{
  "policyName": "S3ReadOnlyPolicy",
  "description": "Read-only access to specific S3 buckets",
  "cloudProviders": ["aws"],
  "policyDocument": {
    "aws": {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Action": [
            "s3:GetObject",
            "s3:GetObjectVersion",
            "s3:ListBucket"
          ],
          "Resource": [
            "arn:aws:s3:::company-data-bucket/*",
            "arn:aws:s3:::company-data-bucket"
          ]
        }
      ]
    }
  },
  "tags": {
    "Department": "DataEngineering",
    "Environment": "Production",
    "Compliance": "SOX"
  }
}
```

#### Validate Policy
**Endpoint:** `POST /api/v1/policies/validate`

**Request Body:**
```json
{
  "cloudProvider": "aws",
  "policyDocument": {
    "Version": "2012-10-17",
    "Statement": [...]
  },
  "validationType": "syntax|permissions|compliance"
}
```

**Response:**
```json
{
  "statusCode": 200,
  "data": {
    "valid": true,
    "warnings": [
      {
        "code": "OVERLY_PERMISSIVE",
        "message": "Policy grants broad s3:* permissions",
        "severity": "medium",
        "recommendation": "Consider using more specific actions"
      }
    ],
    "complianceCheck": {
      "sox": "passed",
      "pci": "passed", 
      "hipaa": "failed",
      "issues": ["Healthcare data access detected without proper encryption requirements"]
    }
  }
}
```

### Group Management

#### Create Group
**Endpoint:** `POST /api/v1/groups`

**Request Body:**
```json
{
  "groupName": "DataEngineers",
  "description": "Data engineering team group",
  "cloudProviders": ["aws", "azure", "gcp"],
  "parentGroup": "Engineering",
  "members": ["john.doe", "jane.smith"],
  "roles": ["DataEngineerRole", "DeveloperRole"],
  "policies": ["S3ReadOnlyPolicy"],
  "groupType": "security|distribution|mail-enabled",
  "autoMembership": {
    "enabled": true,
    "criteria": {
      "department": "Engineering",
      "jobTitle": "Data Engineer"
    }
  }
}
```

### Access Control

#### Grant Access
**Endpoint:** `POST /api/v1/access/grant`

**Request Body:**
```json
{
  "principal": {
    "type": "user|group|role",
    "identifier": "john.doe"
  },
  "target": {
    "type": "role|resource",
    "identifier": "DataEngineerRole",
    "cloudProvider": "aws"
  },
  "duration": {
    "type": "temporary|permanent",
    "expiryDate": "2024-06-30T23:59:59Z"
  },
  "conditions": {
    "mfaRequired": true,
    "ipRestrictions": ["192.168.1.0/24"],
    "timeRestrictions": {
      "businessHoursOnly": true,
      "timezone": "America/New_York"
    }
  },
  "justification": "Temporary access for Q2 data analysis project",
  "approver": "mike.johnson"
}
```

#### Revoke Access
**Endpoint:** `POST /api/v1/access/revoke`

**Request Body:**
```json
{
  "accessId": "acc_def456ghi789",
  "reason": "Project completed",
  "immediate": true,
  "notifyUser": true
}
```

### Audit and Compliance

#### Access Audit
**Endpoint:** `GET /api/v1/audit/access`

**Query Parameters:**
- `startDate` (string): Start date for audit period
- `endDate` (string): End date for audit period
- `userId` (string): Filter by specific user
- `action` (string): Filter by action type
- `cloudProvider` (string): Filter by cloud provider

**Response:**
```json
{
  "statusCode": 200,
  "data": {
    "auditId": "aud_jkl012mno345",
    "period": {
      "start": "2024-01-01T00:00:00Z",
      "end": "2024-01-31T23:59:59Z"
    },
    "summary": {
      "totalEvents": 1234,
      "uniqueUsers": 89,
      "failedAttempts": 12,
      "privilegedOperations": 45
    },
    "events": [
      {
        "eventId": "evt_pqr678stu901",
        "timestamp": "2024-01-15T14:30:00Z",
        "userId": "john.doe",
        "action": "AssumeRole",
        "resource": "arn:aws:iam::123456789012:role/DataEngineerRole",
        "sourceIp": "192.168.1.100",
        "userAgent": "aws-cli/2.0.0",
        "result": "success",
        "duration": 3600
      }
    ]
  }
}
```

#### Compliance Report
**Endpoint:** `GET /api/v1/compliance/report`

**Query Parameters:**
- `framework` (string): Compliance framework (sox|pci|hipaa|gdpr)
- `format` (string): Report format (json|pdf|csv)

**Response:**
```json
{
  "statusCode": 200,
  "data": {
    "reportId": "rpt_vwx234yza567",
    "framework": "sox",
    "generatedAt": "2024-01-15T16:00:00Z",
    "overallScore": 85,
    "findings": [
      {
        "controlId": "SOX-AC-01",
        "description": "User access reviews",
        "status": "compliant",
        "evidence": ["Monthly access review completed", "Segregation of duties verified"]
      },
      {
        "controlId": "SOX-AC-02", 
        "description": "Privileged access management",
        "status": "non-compliant",
        "issues": ["3 users with permanent admin access"],
        "remediation": "Implement temporary elevated access for admin operations"
      }
    ]
  }
}
```

## Webhook Events

### Event Types
- `user.created`
- `user.updated` 
- `user.deleted`
- `role.assigned`
- `role.revoked`
- `policy.violated`
- `access.denied`

### Webhook Payload
```json
{
  "eventId": "evt_abc123def456",
  "eventType": "user.created",
  "timestamp": "2024-01-15T10:30:00Z",
  "source": "iam-automation-api",
  "data": {
    "userId": "usr_xyz789uvw012",
    "username": "john.doe",
    "cloudProviders": ["aws", "azure", "gcp"],
    "initiatedBy": "jane.smith"
  },
  "metadata": {
    "correlationId": "corr_ghi345jkl678",
    "version": "v1",
    "environment": "production"
  }
}
```

## Error Handling

### Error Response Format
```json
{
  "error": {
    "code": "IAM_ERR_001",
    "message": "Invalid user credentials",
    "details": "The provided username or password is incorrect",
    "timestamp": "2024-01-15T12:00:00Z",
    "requestId": "req_mno678pqr901",
    "supportId": "sup_stu234vwx567"
  }
}
```

### Error Codes

| Code | Description | HTTP Status |
|------|-------------|-------------|
| IAM_ERR_001 | Authentication failed | 401 |
| IAM_ERR_002 | Insufficient permissions | 403 |
| IAM_ERR_003 | Resource not found | 404 |
| IAM_ERR_004 | Rate limit exceeded | 429 |
| IAM_ERR_005 | Cloud provider error | 502 |
| IAM_ERR_006 | Validation failed | 400 |
| IAM_ERR_007 | Compliance violation | 409 |

## Rate Limits

| Endpoint Category | Limit | Window |
|-------------------|-------|--------|
| User Operations | 1000 requests | 1 hour |
| Role Operations | 500 requests | 1 hour |
| Policy Operations | 100 requests | 1 hour |
| Audit Queries | 200 requests | 1 hour |
| Compliance Reports | 10 requests | 1 hour |

## SDK Examples

### Python SDK
```python
from iam_automation import IAMClient

client = IAMClient(
    api_key="your-api-key",
    base_url="https://api.iam-automation.com"
)

# Create user
user = client.users.create({
    "username": "john.doe",
    "email": "john.doe@company.com",
    "cloudProviders": ["aws", "azure"]
})

# Assign role
client.access.grant({
    "principal": {"type": "user", "identifier": "john.doe"},
    "target": {"type": "role", "identifier": "DataEngineerRole"}
})
```

### JavaScript SDK
```javascript
import { IAMClient } from 'iam-automation-sdk';

const client = new IAMClient({
  apiKey: 'your-api-key',
  baseUrl: 'https://api.iam-automation.com'
});

// Create user
const user = await client.users.create({
  username: 'john.doe',
  email: 'john.doe@company.com',
  cloudProviders: ['aws', 'azure']
});

// Assign role
await client.access.grant({
  principal: { type: 'user', identifier: 'john.doe' },
  target: { type: 'role', identifier: 'DataEngineerRole' }
});
```
