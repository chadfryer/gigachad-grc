# GigaChad GRC - Integrations Setup Guide

This guide explains how to configure external integrations in GigaChad GRC. The platform is designed to work out-of-the-box in **demo mode**, providing sample data when external services are not configured. This allows teams to evaluate the platform before connecting to production systems.

## Table of Contents

1. [Understanding Demo Mode](#understanding-demo-mode)
2. [Cloud Provider Integrations](#cloud-provider-integrations)
   - [AWS Integration](#aws-integration)
   - [Azure Integration](#azure-integration)
   - [Google Workspace](#google-workspace-integration)
3. [Email Notifications](#email-notifications)
4. [Ticketing Integrations](#ticketing-integrations)
5. [AI Features](#ai-features)
6. [Vulnerability Scanning](#vulnerability-scanning)
7. [Troubleshooting](#troubleshooting)

---

## Understanding Demo Mode

GigaChad GRC operates in **demo mode** when external services are not configured. This is by design to allow:

- **Easy evaluation** - Start using the platform immediately without complex setup
- **Development testing** - Developers can work without production credentials
- **Graceful degradation** - The platform remains functional even if an external service is unavailable

### How Demo Mode Works

When an external service is not configured:

1. **Warning Logged** - A clear warning message is logged indicating the service is running in demo mode
2. **Sample Data Returned** - The API returns realistic sample data
3. **Mock Mode Flag** - API responses include `isMockMode: true` so clients can detect demo mode
4. **UI Indicators** - The frontend displays informational banners about configuration status

### Example API Response in Demo Mode

```json
{
  "data": {
    "findings": [
      {
        "id": "demo-finding-1",
        "title": "Sample Security Finding",
        "severity": "HIGH",
        "description": "This is sample data..."
      }
    ]
  },
  "isMockMode": true,
  "mockModeReason": "AWS credentials not configured - set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY"
}
```

---

## Cloud Provider Integrations

### AWS Integration

GigaChad GRC can collect security evidence from AWS services including Security Hub, CloudTrail, IAM, S3, and GuardDuty.

#### Prerequisites

1. An AWS account with the services you want to monitor enabled
2. An IAM user or role with read-only access to security services
3. AWS access keys or IAM role ARN

#### Step 1: Create an IAM Policy

Create a policy named `GigaChadGRCReadOnly` with these permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SecurityEvidence",
      "Effect": "Allow",
      "Action": [
        "securityhub:GetFindings",
        "securityhub:DescribeStandards",
        "cloudtrail:LookupEvents",
        "cloudtrail:DescribeTrails",
        "config:DescribeComplianceByConfigRule",
        "config:GetComplianceDetailsByConfigRule"
      ],
      "Resource": "*"
    },
    {
      "Sid": "IAMAnalysis",
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers",
        "iam:ListRoles",
        "iam:ListPolicies",
        "iam:ListMFADevices",
        "iam:ListAccessKeys",
        "iam:GetCredentialReport",
        "iam:GenerateCredentialReport"
      ],
      "Resource": "*"
    },
    {
      "Sid": "S3Security",
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketEncryption",
        "s3:GetBucketVersioning",
        "s3:GetBucketLogging",
        "s3:GetPublicAccessBlock",
        "s3:GetBucketPolicy"
      ],
      "Resource": "*"
    },
    {
      "Sid": "GuardDuty",
      "Effect": "Allow",
      "Action": [
        "guardduty:ListDetectors",
        "guardduty:ListFindings",
        "guardduty:GetFindings"
      ],
      "Resource": "*"
    },
    {
      "Sid": "Identity",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

#### Step 2: Create an IAM User or Role

**Option A: IAM User (for non-AWS deployments)**

1. Create an IAM user named `gigachad-grc-collector`
2. Attach the `GigaChadGRCReadOnly` policy
3. Create access keys and save them securely

**Option B: IAM Role (recommended for AWS deployments)**

1. Create an IAM role named `GigaChadGRCRole`
2. Set the trust policy to allow your EC2 instances or ECS tasks
3. Attach the `GigaChadGRCReadOnly` policy

#### Step 3: Configure Environment Variables

```bash
# For IAM User
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_REGION=us-east-1

# For IAM Role (leave access keys empty)
AWS_ROLE_ARN=arn:aws:iam::123456789012:role/GigaChadGRCRole
AWS_REGION=us-east-1
```

#### Step 4: Install AWS SDK (if not already installed)

The AWS SDK packages are optional dependencies. Install them for full functionality:

```bash
cd services/controls
npm install @aws-sdk/client-sts @aws-sdk/client-securityhub @aws-sdk/client-cloudtrail \
  @aws-sdk/client-config-service @aws-sdk/client-iam @aws-sdk/client-s3 @aws-sdk/client-guardduty
```

#### Verification

Test the connection by checking the logs when evidence collection runs:

```
[AWSConnector] Successfully authenticated with AWS account 123456789012
[AWSConnector] Collected 15 Security Hub findings
```

If you see demo mode warnings, check your credentials:

```
[AWSConnector] WARN: AWS credentials not configured - using demo mode
```

---

### Azure Integration

Collect security evidence from Azure Security Center including secure scores and recommendations.

#### Prerequisites

1. An Azure subscription with Security Center enabled
2. An Azure AD application registration
3. Security Reader role assignment

#### Step 1: Register an Azure AD Application

1. Go to Azure Portal > Azure Active Directory > App registrations
2. Click "New registration"
3. Name: `GigaChad GRC Collector`
4. Supported account types: Single tenant
5. Click Register

#### Step 2: Create a Client Secret

1. Go to Certificates & secrets
2. Click "New client secret"
3. Set an expiration (recommended: 24 months)
4. Copy the secret value immediately

#### Step 3: Assign Permissions

1. Go to your Subscription > Access control (IAM)
2. Click "Add role assignment"
3. Role: Security Reader
4. Assign to: The application you created

#### Step 4: Configure Environment Variables

```bash
AZURE_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AZURE_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AZURE_CLIENT_SECRET=your-client-secret
AZURE_SUBSCRIPTION_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

#### Step 5: Install Azure SDK (if not already installed)

```bash
npm install @azure/identity @azure/arm-security
```

---

### Google Workspace Integration

Collect audit logs and user activity from Google Workspace.

#### Prerequisites

1. Google Workspace admin access
2. A Google Cloud project
3. Domain-wide delegation enabled

#### Step 1: Create a Service Account

1. Go to Google Cloud Console > IAM & Admin > Service Accounts
2. Create a new service account named `gigachad-grc-collector`
3. Enable domain-wide delegation
4. Create and download a JSON key file

#### Step 2: Configure Domain-Wide Delegation

1. Go to Google Workspace Admin Console
2. Security > API Controls > Domain-wide delegation
3. Add a new client with:
   - Client ID: The service account's client ID
   - OAuth Scopes:
     - `https://www.googleapis.com/auth/admin.reports.audit.readonly`
     - `https://www.googleapis.com/auth/admin.directory.user.readonly`

#### Step 3: Configure Environment Variables

```bash
# The entire JSON key file content (escaped)
GOOGLE_SERVICE_ACCOUNT_KEY='{"type":"service_account","project_id":"your-project",...}'

# An admin email for impersonation
GOOGLE_ADMIN_EMAIL=admin@yourcompany.com

# Your Google Workspace customer ID (found in Admin Console > Account > Account settings)
GOOGLE_CUSTOMER_ID=C0xxxxxxx
```

---

## Email Notifications

GigaChad GRC sends notifications for various events including audit findings, risk alerts, and scheduled reports.

### Supported Providers

| Provider | Environment Variables | Best For |
|----------|----------------------|----------|
| SMTP | `SMTP_HOST`, `SMTP_PORT`, etc. | Self-hosted email servers |
| SendGrid | `SENDGRID_API_KEY` | High-volume transactional email |
| Amazon SES | `AWS_SES_REGION` | AWS-native deployments |

### SMTP Configuration

```bash
SMTP_HOST=smtp.yourprovider.com
SMTP_PORT=587
SMTP_USER=notifications@yourcompany.com
SMTP_PASSWORD=your-password
SMTP_FROM="GigaChad GRC <notifications@yourcompany.com>"
SMTP_SECURE=false        # true for port 465
SMTP_REQUIRE_TLS=true    # Use STARTTLS
```

### SendGrid Configuration

```bash
EMAIL_PROVIDER=sendgrid
SENDGRID_API_KEY=SG.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
SMTP_FROM=notifications@yourcompany.com
```

### Amazon SES Configuration

```bash
EMAIL_PROVIDER=ses
AWS_SES_REGION=us-east-1
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
SMTP_FROM=notifications@yourcompany.com
```

### Demo Mode Behavior

When no email provider is configured:

- Emails are logged to the console with full content
- The Notification Settings page displays a warning banner
- Scheduled reports note that delivery is simulated
- No actual emails are sent

The console output looks like:

```
[EmailService] CONSOLE MODE: Would send email
  To: user@example.com
  Subject: Weekly Compliance Report
  Body: <html>...
```

---

## Ticketing Integrations

### Jira Integration

Create and sync issues between GigaChad GRC and Jira.

#### Configuration

```bash
JIRA_URL=https://yourcompany.atlassian.net
JIRA_EMAIL=jira-bot@yourcompany.com
JIRA_API_TOKEN=your-api-token
JIRA_PROJECT_KEY=GRC
```

#### Creating an API Token

1. Go to https://id.atlassian.com/manage-profile/security/api-tokens
2. Create a new API token
3. Save the token securely

#### Demo Mode

When Jira is not configured, the integration:
- Returns successful mock responses for issue creation
- Logs what would be sent to Jira
- Includes `isMockMode: true` in responses

### ServiceNow Integration

```bash
SERVICENOW_INSTANCE=yourcompany.service-now.com
SERVICENOW_USERNAME=integration-user
SERVICENOW_PASSWORD=your-password
```

---

## AI Features

### Risk Analysis and Recommendations

GigaChad GRC includes AI-powered features for risk analysis, control recommendations, and vendor assessment.

#### OpenAI Configuration

```bash
ENABLE_AI_FEATURES=true
OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
OPENAI_MODEL=gpt-4  # or gpt-3.5-turbo
```

#### Azure OpenAI Configuration

```bash
ENABLE_AI_FEATURES=true
AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com
AZURE_OPENAI_API_KEY=your-api-key
AZURE_OPENAI_DEPLOYMENT=gpt-4
```

#### Demo Mode Behavior

When AI is not configured:
- Risk analysis returns sample recommendations
- Responses include `isMockMode: true`
- The UI displays "AI features running in demo mode"

---

## Vulnerability Scanning

### Container Scanning with Trivy

#### Installation

```bash
# macOS
brew install trivy

# Ubuntu/Debian
sudo apt-get install trivy

# Docker
docker pull aquasec/trivy
```

No environment variables required - the scanner uses the Trivy CLI.

### Network Scanning with Nmap

#### Installation

```bash
# macOS
brew install nmap

# Ubuntu/Debian
sudo apt-get install nmap
```

#### Demo Mode

If scanning tools are not installed, the vulnerability scanner:
- Returns sample vulnerability data
- Includes `toolsRequired: ["trivy"]` or `toolsRequired: ["nmap"]`
- Logs which tools need to be installed

---

## Troubleshooting

### Common Issues

#### "AWS credentials not configured"

**Cause:** The `AWS_ACCESS_KEY_ID` or `AWS_SECRET_ACCESS_KEY` environment variables are not set.

**Solution:**
1. Verify the variables are set: `echo $AWS_ACCESS_KEY_ID`
2. Check for typos in variable names
3. Ensure credentials are not expired

#### "Email notifications in demo mode"

**Cause:** No email provider is configured.

**Solution:**
1. Configure SMTP settings or a provider API key
2. Restart the controls service
3. Check the Notification Settings page for status

#### "MODULE_NOT_FOUND" errors in logs

**Cause:** An optional SDK package is not installed.

**Solution:**
```bash
# For AWS
npm install @aws-sdk/client-sts @aws-sdk/client-securityhub

# For Azure
npm install @azure/identity @azure/arm-security
```

### Checking Configuration Status

Use the API to check integration status:

```bash
# Email status
curl http://localhost:3001/api/notifications-config/email-status

# Response:
# {"isConfigured":true,"provider":"smtp","isConsoleMode":false}
```

### Log Messages to Look For

| Log Level | Message Pattern | Meaning |
|-----------|----------------|---------|
| WARN | "not configured - using demo mode" | Feature working but using sample data |
| WARN | "SDK not installed" | Install the required package |
| ERROR | "Authentication failed" | Check credentials |
| INFO | "Successfully connected" | Integration working |

---

## Next Steps

After configuring integrations:

1. **Test each integration** - Trigger a manual sync or evidence collection
2. **Review the collected data** - Check that real data is appearing
3. **Set up schedules** - Configure automated collection intervals
4. **Monitor logs** - Watch for any authentication or connection errors

For production deployments, see the [Production Deployment Guide](../PRODUCTION_DEPLOYMENT.md).

---

*Last updated: January 2026*
