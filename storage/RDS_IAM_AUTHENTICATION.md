# AWS RDS IAM Authentication

This document describes how to configure the Nuts node to authenticate to AWS RDS databases using IAM authentication instead of traditional username/password authentication.

## Overview

AWS RDS IAM authentication provides enhanced security by using temporary authentication tokens instead of database passwords. Benefits include:

- **No password storage**: Credentials are generated on-demand using IAM
- **Automatic token rotation**: Tokens are refreshed automatically every 14 minutes (they expire after 15 minutes)
- **IAM-based access control**: Database access is controlled through AWS IAM policies
- **Audit trail**: All authentication attempts are logged in AWS CloudTrail

## Prerequisites

1. **AWS RDS Database** with IAM authentication enabled
2. **IAM permissions** to generate RDS authentication tokens
3. **Database user** configured for IAM authentication
4. **AWS credentials** configured on the Nuts node (via environment variables, instance profile, or AWS config file)
5. **RDS CA certificate** downloaded and accessible (required for SSL/TLS verification)

## Configuration

**First**, download the RDS CA certificate:
```bash
curl -o /etc/ssl/rds-ca-bundle.pem https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem
```

Add the following configuration to your Nuts node configuration file:

```yaml
storage:
  sql:
    connection: "postgres://nutsuser@your-db.region.rds.amazonaws.com:5432/nuts?sslmode=verify-full&sslrootcert=/etc/ssl/rds-ca-bundle.pem"
    rdsiam:
      enabled: true
      region: "us-east-1"
      dbuser: "iamuser"  # Optional: if not specified, uses user from connection string
```

### Configuration Options

- `storage.sql.rdsiam.enabled` (boolean): Enable RDS IAM authentication
- `storage.sql.rdsiam.region` (string): AWS region where the RDS instance is located
- `storage.sql.rdsiam.dbuser` (string): Database username for IAM authentication (optional)

### Connection String Format

The connection string should follow the standard format but **without a password** and **with SSL/TLS enabled** (required for RDS IAM authentication):

**PostgreSQL:**
```
postgres://username@hostname:port/database?sslmode=require&sslrootcert=/path/to/rds-ca-bundle.pem
```

Or for stricter SSL verification:
```
postgres://username@hostname:port/database?sslmode=verify-full&sslrootcert=/path/to/rds-ca-bundle.pem
```

**MySQL:**
```
mysql://username@hostname:port/database?tls=true
```

**Important:** 
- SSL/TLS is **required** for RDS IAM authentication. Without it, you will get authentication errors like "PAM authentication failed" or "pg_hba.conf rejects connection...no encryption".
- You **must provide the RDS CA certificate** using `sslrootcert` parameter (PostgreSQL) or equivalent. Download it from: https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem
- You **must use the actual RDS endpoint hostname** (e.g., `mydb.abc123.region.rds.amazonaws.com`), not a CNAME or Route53 alias. AWS IAM tokens are signed for the specific endpoint hostname.

## AWS Setup

### 1. Enable IAM Authentication on RDS

When creating or modifying your RDS instance:
```bash
aws rds modify-db-instance \
    --db-instance-identifier mydb \
    --enable-iam-database-authentication \
    --apply-immediately
```

### 2. Create IAM Policy

Create an IAM policy that allows generating authentication tokens:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "rds-db:connect"
            ],
            "Resource": [
                "arn:aws:rds-db:us-east-1:123456789012:dbuser:db-ABCDEFGHIJKL/iamuser"
            ]
        }
    ]
}
```

Attach this policy to the IAM role or user that the Nuts node uses.

### 3. Create Database User

Connect to your database and create a user for IAM authentication:

**PostgreSQL:**
```sql
CREATE USER iamuser;
GRANT rds_iam TO iamuser;
GRANT ALL PRIVILEGES ON DATABASE mydatabase TO iamuser;
```

**MySQL:**
```sql
CREATE USER iamuser IDENTIFIED WITH AWSAuthenticationPlugin AS 'RDS';
GRANT ALL PRIVILEGES ON mydatabase.* TO iamuser@'%';
```

## AWS Credentials

**IMPORTANT:** The Nuts node needs AWS credentials to generate authentication tokens. **You must configure AWS credentials before enabling RDS IAM authentication.**

The Nuts node uses the **AWS SDK default credential chain**, which automatically tries the following methods in order:

1. **Environment variables**:
   - `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`
   - `AWS_PROFILE` (to select a specific profile from `~/.aws/credentials`)

2. **Shared credentials file** (`~/.aws/credentials`):
   ```ini
   [default]
   aws_access_key_id = your-access-key
   aws_secret_access_key = your-secret-key
   
   [production]
   aws_access_key_id = prod-access-key
   aws_secret_access_key = prod-secret-key
   ```
   Use with: `export AWS_PROFILE=production`

3. **Shared configuration file** (`~/.aws/config`):
   - Supports role assumption, SSO, and other advanced configurations

4. **EC2 Instance Metadata (IMDS)**:
   - Automatically used when running on EC2 instances with an IAM instance profile

5. **ECS/EKS Container Credentials**:
   - Automatically used in ECS tasks or EKS pods with IAM roles (IRSA)

6. **Web Identity Token**:
   - Used for OIDC-based authentication (e.g., EKS IRSA, GitHub Actions)

**No explicit configuration is needed** - the SDK will automatically find and use available credentials. Just ensure your environment has AWS credentials configured through any of the above methods.

**Note:** If you see errors like "no EC2 IMDS role found" or "dial tcp 169.254.169.254:80: connect: host is down", it means the SDK couldn't find credentials through any method. Configure credentials using one of the methods above.

## How It Works

1. On startup, the Nuts node generates an initial IAM authentication token
2. The token is injected into the database connection
3. A background goroutine refreshes the token every 14 minutes
4. The token is valid for 15 minutes, providing a 1-minute safety margin

## Supported Databases

- PostgreSQL (via `postgres://` connection string)
- MySQL (via `mysql://` connection string)

SQLite and SQL Server are not supported as they don't run on AWS RDS with IAM authentication.

##Cause:** The AWS SDK default credential chain couldn't find credentials through any of its standard methods.

**Solutions** (choose one based on your environment):

1. **Using AWS Profile** (recommended for local development):
   ```bash
   export AWS_PROFILE=your-profile-name
   ./nuts-node server ...
   ```

2. **Using environment variables**:
   ```bash
   export AWS_ACCESS_KEY_ID="your-access-key"
   export AWS_SECRET_ACCESS_KEY="your-secret-key"
   export AWS_SESSION_TOKEN="your-session-token"  # Optional, for temporary credentials
   ./nuts-node server ...
   ```

3. **Configure AWS credentials file** (`~/.aws/credentials`):
   ```ini
   [default]
   aws_access_key_id = your-access-key
   aws_secret_access_key = your-secret-key
   ```

4. **On EC2**: Attach an IAM instance profile (no additional configuration needed)

5. **On EKS**: Configure IAM Roles for Service Accounts (IRSA) - the pod will automatically use the assigned role

After configuring credentials, restart the nuts-node server.
To fix:
1. Set AWS environment variables:
   ```bash
   export AWS_ACCESS_KEY_ID="your-access-key"
   export AWS_SECRET_ACCESS_KEY="your-secret-key"
   export AWS_REGION="eu-west-1"  # Must match your RDS region
   ```

2. Or configure `~/.aws/credentials` file

3. Then restart the nuts-node server
Download RDS CA certificate**: 
   ```bash
   curl -o /etc/ssl/rds-ca-bundle.pem https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem
   ```
   Then add `sslrootcert=/etc/ssl/rds-ca-bundle.pem` to your connection string query parameters.

2. **Enable SSL/TLS**: Ensure your connection string includes SSL parameters (`?sslmode=require&sslrootcert=/path/to/cert` for PostgreSQL, `?tls=true` for MySQL). This is **required** for RDS IAM authentication.

3. **Check IAM permissions**: Ensure the IAM role/user has `rds-db:connect` permission

4. **Verify database user**: Confirm the database user is created with IAM authentication (has `rds_iam` role granted)

5. **Check AWS credentials**: Ensure the Nuts node can access AWS credentials (see above)

6. **Verify region**: Ensure the `region` in config matches your RDS instance region

7. **Enable SSL/TLS**: Ensure your connection string includes SSL parameters (`?sslmode=require` for PostgreSQL, `?tls=true` for MySQL). This is **required** for RDS IAM authentication.
2. **Check IAM permissions**: Ensure the IAM role/user has `rds-db:connect` permission
3. **Verify database user**: Confirm the database user is created with IAM authentication
4. **Check AWS credentials**: Ensure the Nuts node can access AWS credentials (see above)
5. **Verify region**: Ensure the `region` in config matches your RDS instance region
6. **Check security groups**: Ensure the Nuts node can reach the RDS instance

### Token Refresh Errors

Check the Nuts node logs for token refresh messages:
```
Failed to refresh RDS IAM token
```

Common causes:
- AWS credentials expired or invalid
- IAM permissions changed
- Network connectivity issues to AWS API

## Security Considerations

- IAM authentication tokens are logged at DEBUG level but never at INFO or higher
- Connection strings should not include passwords when IAM auth is enabled
- EnsAWS credentials (choose one method):
```bash
# Option 1: Using AWS Profile&sslrootcert=/etc/ssl/rds-ca-bundle.pem"
    rdsiam:
      enabled: true
      region: "us-east-1"
      dbuser: "nutsuser"
```

First, download the RDS CA certificate:
```bash
curl -o /etc/ssl/rds-ca-bundle.pem https://truststore.pki.rds.amazonaws.com/global/global-bundle.pemcredentials
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
./nuts-node server

# Option 3: On EC2/EKS - credentials automatically provided by instance profile/IRSA
./nuts-node server

```yaml
# Nuts node configuration with RDS IAM authentication
storage:
  sql:
    connection: "postgres://nutsuser@your-db.region.rds.amazonaws.com:5432/nuts?sslmode=require"
    rdsiam:
      enabled: true
      region: "us-east-1"
      dbuser: "nutsuser"
```

With environment variables:
```bash
export AWS_REGION="us-east-1"
# Credentials from instance profile (recommended on EC2)
# Or set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY
```
