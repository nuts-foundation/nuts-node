/*
 * Copyright (C) 2026 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

package storage

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	_ "github.com/jackc/pgx/v5/stdlib" // Import postgres driver for sql.Open
	"github.com/nuts-foundation/nuts-node/storage/log"
)

var loadAWSConfigForRegion = func(ctx context.Context, region string) (aws.Config, error) {
	return config.LoadDefaultConfig(ctx, config.WithRegion(region))
}

var buildRDSAuthToken = func(ctx context.Context, endpoint, region, dbUser string, credentials aws.CredentialsProvider) (string, error) {
	return auth.BuildAuthToken(ctx, endpoint, region, dbUser, credentials)
}

// rdsIAMAuthenticator handles AWS RDS IAM authentication
type rdsIAMAuthenticator struct {
	config               RDSIAMConfig
	endpoint             string
	currentToken         string
	lastRefresh          time.Time
	baseConnectionString string // Connection string without password
}

// newRDSIAMAuthenticator creates a new RDS IAM authenticator
func newRDSIAMAuthenticator(cfg RDSIAMConfig, endpoint, baseConnStr string) *rdsIAMAuthenticator {
	return &rdsIAMAuthenticator{
		config:               cfg,
		endpoint:             endpoint,
		baseConnectionString: baseConnStr,
	}
}

// getToken retrieves or refreshes the IAM authentication token
func (a *rdsIAMAuthenticator) getToken(ctx context.Context) (string, error) {
	// Refresh token if needed
	if time.Since(a.lastRefresh) > a.config.TokenRefreshInterval {
		if err := a.refreshToken(ctx); err != nil {
			return "", fmt.Errorf("failed to refresh RDS IAM token: %w", err)
		}
	}
	return a.currentToken, nil
}

// refreshToken generates a new IAM authentication token
func (a *rdsIAMAuthenticator) refreshToken(ctx context.Context) error {
	// Load AWS configuration
	cfg, err := loadAWSConfigForRegion(ctx, a.config.Region)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Build authentication token
	authToken, err := buildRDSAuthToken(ctx, a.endpoint, a.config.Region, a.config.DBUser, cfg.Credentials)
	if err != nil {
		return fmt.Errorf("failed to build auth token: %w", err)
	}

	a.currentToken = authToken
	a.lastRefresh = time.Now()

	return nil
}

// modifyConnectionStringForRDSIAM modifies the connection string to use AWS RDS IAM authentication
// It extracts the endpoint, removes password if present, and sets up the IAM authenticator
func modifyConnectionStringForRDSIAM(ctx context.Context, connectionString string, iamConfig RDSIAMConfig) (string, *rdsIAMAuthenticator, error) {
	if !iamConfig.Enabled {
		return connectionString, nil, nil
	}

	// Parse connection string to extract endpoint
	// Support both postgres:// and mysql:// formats
	var endpoint, modifiedConnectionString string
	var err error

	if strings.HasPrefix(connectionString, "postgres://") {
		endpoint, modifiedConnectionString, err = parseConnectionStringForRDSIAM(connectionString, iamConfig)
	} else if strings.HasPrefix(connectionString, "mysql://") {
		endpoint, modifiedConnectionString, err = parseConnectionStringForRDSIAM(connectionString, iamConfig)
	} else {
		return "", nil, fmt.Errorf("RDS IAM authentication is only supported for postgres:// and mysql:// connection strings")
	}

	if err != nil {
		return "", nil, err
	}

	// Create authenticator
	authenticator := newRDSIAMAuthenticator(iamConfig, endpoint, modifiedConnectionString)

	// Generate initial token
	if err := authenticator.refreshToken(ctx); err != nil {
		return "", nil, fmt.Errorf("failed to generate initial RDS IAM token: %w", err)
	}

	// Inject token into connection string
	modifiedConnectionString, err = injectPasswordIntoConnectionString(modifiedConnectionString, authenticator.currentToken)
	if err != nil {
		return "", nil, fmt.Errorf("failed to inject RDS IAM token into connection string: %w", err)
	}

	log.Logger().Info("AWS RDS IAM authentication enabled for SQL database")

	return modifiedConnectionString, authenticator, nil
}

// GetCurrentConnectionString returns the connection string with the current (fresh) token
func (a *rdsIAMAuthenticator) GetCurrentConnectionString(ctx context.Context) (string, error) {
	// Refresh token if needed
	if time.Since(a.lastRefresh) > a.config.TokenRefreshInterval {
		if err := a.refreshToken(ctx); err != nil {
			return "", fmt.Errorf("failed to refresh RDS IAM token: %w", err)
		}
	}

	// Inject current token into connection string
	connectionString, err := injectPasswordIntoConnectionString(a.baseConnectionString, a.currentToken)
	if err != nil {
		return "", fmt.Errorf("failed to inject RDS IAM token into connection string: %w", err)
	}

	return connectionString, nil
}

// parseConnectionStringForRDSIAM parses a connection string, extracts the endpoint and normalizes username/password for IAM usage.
func parseConnectionStringForRDSIAM(connectionString string, iamConfig RDSIAMConfig) (endpoint, modified string, err error) {
	var username *string
	if iamConfig.DBUser != "" {
		username = &iamConfig.DBUser
	}

	modified, endpoint, err = updateConnectionStringCredentials(connectionString, username, nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse connection string: %w", err)
	}

	return endpoint, modified, nil
}

// updateConnectionStringCredentials parses and updates username/password while preserving URL semantics.
func updateConnectionStringCredentials(connectionString string, username *string, password *string) (modified, endpoint string, err error) {
	u, err := url.Parse(connectionString)
	if err != nil {
		return "", "", err
	}

	endpoint = u.Host

	finalUsername := ""
	if username != nil {
		finalUsername = *username
	} else if u.User != nil {
		finalUsername = u.User.Username()
	}

	if password != nil {
		u.User = url.UserPassword(finalUsername, *password)
	} else if finalUsername != "" || u.User != nil {
		u.User = url.User(finalUsername)
	}

	return u.String(), endpoint, nil
}

// injectPasswordIntoConnectionString injects the password (token) into a connection string
func injectPasswordIntoConnectionString(connectionString, password string) (string, error) {
	modified, _, err := updateConnectionStringCredentials(connectionString, nil, &password)
	if err != nil {
		log.Logger().Errorf("Failed to parse connection string for password injection: %v", err)
		return connectionString, err
	}

	return modified, nil
}

// rdsIAMConnector wraps a driver.Connector and refreshes IAM tokens before opening connections
type rdsIAMConnector struct {
	driver.Connector
	authenticator    *rdsIAMAuthenticator
	underlyingDriver driver.Driver
}

// Connect implements driver.Connector
func (c *rdsIAMConnector) Connect(ctx context.Context) (driver.Conn, error) {
	// Get fresh connection string with current token
	connStr, err := c.authenticator.GetCurrentConnectionString(ctx)
	if err != nil {
		return nil, err
	}

	// Open connection with updated credentials
	return c.underlyingDriver.Open(connStr)
}

// Driver implements driver.Connector
func (c *rdsIAMConnector) Driver() driver.Driver {
	return c.underlyingDriver
}

// createRDSIAMConnector creates a database connector that automatically refreshes RDS IAM tokens
func createRDSIAMConnector(driverName, connectionString string, authenticator *rdsIAMAuthenticator) (driver.Connector, error) {
	// Map connection string prefix to actual SQL driver name
	// "postgres://" uses the "pgx" driver from github.com/jackc/pgx/v5/stdlib
	actualDriverName := driverName
	if driverName == "postgres" {
		actualDriverName = "pgx"
	}

	// Get the underlying driver
	db, err := sql.Open(actualDriverName, connectionString)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	// Get the driver from the opened connection
	underlyingDriver := db.Driver()

	// Create our connector that will inject fresh tokens
	connector := &rdsIAMConnector{
		authenticator:    authenticator,
		underlyingDriver: underlyingDriver,
	}

	return connector, nil
}
