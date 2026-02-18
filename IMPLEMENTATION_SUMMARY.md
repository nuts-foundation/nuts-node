# AWS RDS IAM Authentication Implementation Summary

## Overview
This implementation adds support for AWS RDS IAM authentication to the Nuts node, allowing secure database connections using temporary IAM tokens instead of static passwords.

## Files Added

### 1. `/storage/rds_iam.go` (Main Implementation)
- `rdsIAMAuthenticator`: Manages IAM token generation and refresh
- `modifyConnectionStringForRDSIAM()`: Modifies connection strings for IAM auth
- `parsePostgresConnectionString()`: Parses PostgreSQL connection strings
- `parseMySQLConnectionString()`: Parses MySQL connection strings
- Token refresh logic with configurable intervals (default: 14 minutes)

### 2. `/storage/rds_iam_test.go` (Unit Tests)
- Tests for connection string parsing
- Tests for token injection
- Tests for authenticator initialization
- All tests passing ✓

### 3. `/storage/RDS_IAM_AUTHENTICATION.md` (Documentation)
- Complete setup guide
- AWS configuration instructions
- Security best practices
- Troubleshooting tips

### 4. `/storage/rds_iam_example_config.yaml` (Example Configuration)
- Ready-to-use configuration examples for PostgreSQL and MySQL
- Commented explanations for each option

## Files Modified

### 1. `/storage/config.go`
- Added `RDSIAMConfig` struct with fields:
  - `Enabled`: Enable/disable IAM authentication
  - `Region`: AWS region
  - `DBUser`: Database username
  - `TokenRefreshInterval`: Token refresh interval

### 2. `/storage/engine.go`
- Added `rdsIAMAuth` field to engine struct
- Modified `initSQLDatabase()` to handle RDS IAM authentication
- Added `Start()` method to launch background token refresh
- Added `refreshRDSIAMTokenPeriodically()` for periodic token updates

### 3. `/go.mod` (Dependencies Added)
- `github.com/aws/aws-sdk-go-v2` v1.41.1
- `github.com/aws/aws-sdk-go-v2/config` v1.32.7
- `github.com/aws/aws-sdk-go-v2/feature/rds/auth` v1.6.17
- And related AWS SDK v2 dependencies

## Features

✅ **Automatic Token Management**
- Tokens generated on startup
- Background refresh every 14 minutes (configurable)
- Tokens valid for 15 minutes with 1-minute safety margin

✅ **Database Support**
- PostgreSQL (via `postgres://` connection strings)
- MySQL (via `mysql://` connection strings)

✅ **Security**
- No passwords stored in configuration
- Uses AWS IAM for authentication
- Integrates with AWS credential chain
- Supports EC2 instance profiles

✅ **Configuration**
- Simple YAML configuration
- Optional overrides for user and region
- Backward compatible (disabled by default)

## Usage Example

```yaml
storage:
  sql:
    connection: "postgres://nutsuser@mydb.us-east-1.rds.amazonaws.com:5432/nuts"
    rds_iam:
      enabled: true
      region: "us-east-1"
      db_user: "nutsuser"
```

## Testing

All tests pass:
```
✓ TestParsePostgresConnectionString
✓ TestParseMySQLConnectionString
✓ TestInjectPasswordIntoConnectionString
✓ TestModifyConnectionStringForRDSIAM
✓ TestNewRDSIAMAuthenticator
✓ TestRDSIAMAuthenticator_GetToken
```

## Build Status

✅ Storage package builds successfully
✅ Full project builds successfully
✅ Dependencies cleaned with `go mod tidy`

## AWS Prerequisites

1. **RDS Instance**: IAM authentication enabled
2. **IAM Policy**: `rds-db:connect` permission
3. **Database User**: Created with IAM authentication
4. **AWS Credentials**: Available via environment, instance profile, or config file

## Security Considerations

- Tokens are not logged (only at DEBUG level)
- Connection strings without passwords when IAM enabled
- AWS credentials secured via IAM best practices
- CloudTrail integration for audit logging

## Backward Compatibility

✅ Feature is opt-in (disabled by default)
✅ No breaking changes to existing configurations
✅ Works alongside traditional password authentication
✅ Gracefully handles missing AWS credentials

## Next Steps for Users

1. Enable IAM authentication on RDS instance
2. Create IAM policy with `rds-db:connect` permission
3. Create database user for IAM authentication
4. Configure Nuts node with RDS IAM settings
5. Ensure AWS credentials are available
6. Start the node and verify connection

## Implementation Notes

- Token refresh runs in background goroutine
- Refresh interval prevents token expiry
- Error handling for AWS API failures
- Clean shutdown of refresh goroutine
- Thread-safe token updates
