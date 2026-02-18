# Quick Start: AWS RDS IAM Authentication

## 5-Minute Setup Guide

### Step 1: Enable IAM Authentication on RDS
```bash
aws rds modify-db-instance \
    --db-instance-identifier your-db-instance \
    --enable-iam-database-authentication \
    --apply-immediately
```

### Step 2: Create IAM Policy
Create a file `rds-iam-policy.json`:
```json
{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": "rds-db:connect",
        "Resource": "arn:aws:rds-db:REGION:ACCOUNT_ID:dbuser:RESOURCE_ID/USERNAME"
    }]
}
```

Apply the policy:
```bash
aws iam create-policy \
    --policy-name NutsNodeRDSAccess \
    --policy-document file://rds-iam-policy.json

# Attach to role (for EC2)
aws iam attach-role-policy \
    --role-name YourEC2Role \
    --policy-arn arn:aws:iam::ACCOUNT_ID:policy/NutsNodeRDSAccess

# Or attach to user (for local development)
aws iam attach-user-policy \
    --user-name YourIAMUser \
    --policy-arn arn:aws:iam::ACCOUNT_ID:policy/NutsNodeRDSAccess
```

### Step 3: Create Database User

**For PostgreSQL:**
```sql
CREATE USER nutsuser;
GRANT rds_iam TO nutsuser;
GRANT ALL PRIVILEGES ON DATABASE nuts TO nutsuser;
```

**For MySQL:**
```sql
CREATE USER nutsuser IDENTIFIED WITH AWSAuthenticationPlugin AS 'RDS';
GRANT ALL PRIVILEGES ON nuts.* TO nutsuser@'%';
FLUSH PRIVILEGES;
```

### Step 4: Configure Nuts Node

Edit your Nuts configuration file (e.g., `nuts.yaml`):

```yaml
storage:
  sql:
    # No password in the connection string!
    connection: "postgres://nutsuser@your-db.region.rds.amazonaws.com:5432/nuts"
    
    rdsiam:
      enabled: true
      region: "us-east-1"
      dbuser: "nutsuser"
```

### Step 5: Set AWS Credentials

**Option A - Environment Variables (for development):**
```bash
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_REGION="us-east-1"
```

**Option B - EC2 Instance Profile (for production, recommended):**
- Attach IAM role with policy to EC2 instance
- No environment variables needed!

### Step 6: Start Nuts Node
```bash
./nuts-node server
```

Look for this log message:
```
INFO AWS RDS IAM authentication enabled for SQL database
```

## Verification

Test the connection:
```bash
# Check logs for successful connection
grep "AWS RDS IAM" nuts.log

# Health check
curl http://localhost:8081/health
```

## Getting the RDS Resource ID

The Resource ID is needed for the IAM policy:

```bash
aws rds describe-db-instances \
    --db-instance-identifier your-db-instance \
    --query 'DBInstances[0].DbiResourceId' \
    --output text
```

## Common Issues

### "Access Denied" Error
- **Cause**: IAM policy not attached or incorrect Resource ARN
- **Fix**: Verify IAM policy and ensure Resource ID is correct

### "Password Authentication Failed"
- **Cause**: Database user not created with IAM authentication
- **Fix**: Recreate user with `GRANT rds_iam` (PostgreSQL) or `AWSAuthenticationPlugin` (MySQL)

### "Region Not Found"
- **Cause**: AWS credentials not configured or wrong region
- **Fix**: Set `AWS_REGION` environment variable or use instance profile

### "Token Refresh Failed"
- **Cause**: AWS credentials expired or network issues
- **Fix**: Check AWS credentials and network connectivity to AWS API

## Minimal Example

**Nuts Configuration:**
```yaml
storage:
  sql:
    connection: "postgres://nutsuser@mydb.us-east-1.rds.amazonaws.com:5432/nuts"
    rdsiam:
      enabled: true
      region: "us-east-1"
```

**Environment:**
```bash
export AWS_REGION=us-east-1
# AWS credentials via instance profile or ~/.aws/credentials
```

**That's it!** The Nuts node will automatically:
- Generate IAM tokens
- Connect to RDS
- Refresh tokens every 14 minutes

## Advanced Configuration

### Custom Token Refresh Interval
```yaml
storage:
  sql:
    rdsiam:
      enabled: true
      region: "us-east-1"
      tokenrefreshinterval: 10m  # Refresh every 10 minutes
```

### Multiple Regions Setup
Use AWS credentials with cross-region access and specify the correct region:
```yaml
storage:
  sql:
    connection: "postgres://user@db.eu-west-1.rds.amazonaws.com:5432/nuts"
    rdsiam:
      enabled: true
      region: "eu-west-1"
```

## Production Checklist

- [ ] IAM authentication enabled on RDS instance
- [ ] EC2 instance has IAM role with `rds-db:connect` permission
- [ ] Database user created with IAM authentication
- [ ] Security groups allow EC2 to reach RDS
- [ ] Connection string has no password
- [ ] `rdsiam.enabled: true` in configuration
- [ ] Correct region specified
- [ ] Tested connection and verified logs

## Support

For detailed documentation, see [RDS_IAM_AUTHENTICATION.md](RDS_IAM_AUTHENTICATION.md)

For implementation details, see [IMPLEMENTATION_SUMMARY.md](../IMPLEMENTATION_SUMMARY.md)
