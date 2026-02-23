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
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseConnectionStringForRDSIAM(t *testing.T) {
	t.Run("extracts endpoint correctly", func(t *testing.T) {
		connStr := "postgres://user:password@mydb.123456789012.us-east-1.rds.amazonaws.com:5432/mydb"
		config := RDSIAMConfig{
			Enabled: true,
			Region:  "us-east-1",
			DBUser:  "iamuser",
		}

		endpoint, modified, err := parseConnectionStringForRDSIAM(connStr, config)
		require.NoError(t, err)
		assert.Equal(t, "mydb.123456789012.us-east-1.rds.amazonaws.com:5432", endpoint)
		assert.Contains(t, modified, "iamuser")
		assert.NotContains(t, modified, "password")
	})

	t.Run("uses existing user if DBUser not specified", func(t *testing.T) {
		connStr := "postgres://existinguser:password@mydb.amazonaws.com:5432/mydb"
		config := RDSIAMConfig{
			Enabled: true,
			Region:  "us-east-1",
		}

		endpoint, modified, err := parseConnectionStringForRDSIAM(connStr, config)
		require.NoError(t, err)
		assert.Equal(t, "mydb.amazonaws.com:5432", endpoint)
		assert.Contains(t, modified, "existinguser")
		assert.NotContains(t, modified, "password")
	})

	t.Run("extracts endpoint correctly", func(t *testing.T) {
		connStr := "mysql://user:password@mydb.123456789012.us-west-2.rds.amazonaws.com:3306/mydb"
		config := RDSIAMConfig{
			Enabled: true,
			Region:  "us-west-2",
			DBUser:  "iamuser",
		}

		endpoint, modified, err := parseConnectionStringForRDSIAM(connStr, config)
		require.NoError(t, err)
		assert.Equal(t, "mydb.123456789012.us-west-2.rds.amazonaws.com:3306", endpoint)
		assert.Contains(t, modified, "iamuser")
		assert.NotContains(t, modified, "password")
	})
}

func TestInjectPasswordIntoConnectionString(t *testing.T) {
	t.Run("injects password into postgres connection string", func(t *testing.T) {
		connStr := "postgres://user@mydb.amazonaws.com:5432/mydb"
		token := "generatedtoken123"

		result, err := injectPasswordIntoConnectionString(connStr, token)
		require.NoError(t, err)
		assert.Contains(t, result, "user:generatedtoken123")
	})

	t.Run("replaces existing password", func(t *testing.T) {
		connStr := "postgres://user:oldpassword@mydb.amazonaws.com:5432/mydb"
		token := "newtoken456"

		result, err := injectPasswordIntoConnectionString(connStr, token)
		require.NoError(t, err)
		assert.Contains(t, result, "user:newtoken456")
		assert.NotContains(t, result, "oldpassword")
	})

	t.Run("returns error for malformed connection string", func(t *testing.T) {
		connStr := "%"
		token := "newtoken456"

		_, err := injectPasswordIntoConnectionString(connStr, token)
		require.Error(t, err)
	})
}

func TestModifyConnectionStringForRDSIAM(t *testing.T) {
	t.Run("disabled config returns original string", func(t *testing.T) {
		connStr := "postgres://user:password@localhost:5432/db"
		config := RDSIAMConfig{
			Enabled: false,
		}

		modified, auth, err := modifyConnectionStringForRDSIAM(context.Background(), connStr, config)
		require.NoError(t, err)
		assert.Equal(t, connStr, modified)
		assert.Nil(t, auth)
	})

	t.Run("unsupported connection string returns error", func(t *testing.T) {
		connStr := "sqlite:file:test.db"
		config := RDSIAMConfig{
			Enabled: true,
			Region:  "us-east-1",
		}

		_, _, err := modifyConnectionStringForRDSIAM(context.Background(), connStr, config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "only supported for postgres:// and mysql://")
	})
}

func TestNewRDSIAMAuthenticator(t *testing.T) {
	t.Run("uses configured token refresh interval", func(t *testing.T) {
		config := RDSIAMConfig{
			Enabled:              true,
			Region:               "us-east-1",
			DBUser:               "testuser",
			TokenRefreshInterval: 14 * time.Minute,
		}

		auth := newRDSIAMAuthenticator(config, "localhost:5432", "postgres://testuser@localhost:5432/testdb")
		assert.Equal(t, 14*time.Minute, auth.config.TokenRefreshInterval)
	})

	t.Run("uses custom token refresh interval", func(t *testing.T) {
		config := RDSIAMConfig{
			Enabled:              true,
			Region:               "us-east-1",
			DBUser:               "testuser",
			TokenRefreshInterval: 5 * time.Minute,
		}

		auth := newRDSIAMAuthenticator(config, "localhost:5432", "postgres://testuser@localhost:5432/testdb")
		assert.Equal(t, 5*time.Minute, auth.config.TokenRefreshInterval)
	})
}

func TestRDSIAMAuthenticator_GetToken(t *testing.T) {
	t.Run("refreshes token when needed", func(t *testing.T) {
		originalLoadAWSConfigForRegion := loadAWSConfigForRegion
		originalBuildRDSAuthToken := buildRDSAuthToken
		t.Cleanup(func() {
			loadAWSConfigForRegion = originalLoadAWSConfigForRegion
			buildRDSAuthToken = originalBuildRDSAuthToken
		})

		loadAWSConfigForRegion = func(ctx context.Context, region string) (aws.Config, error) {
			return aws.Config{}, nil
		}

		buildCalls := 0
		buildRDSAuthToken = func(ctx context.Context, endpoint, region, dbUser string, credentials aws.CredentialsProvider) (string, error) {
			buildCalls++
			return fmt.Sprintf("token-%d", buildCalls), nil
		}

		config := RDSIAMConfig{
			Enabled:              true,
			Region:               "us-east-1",
			DBUser:               "testuser",
			TokenRefreshInterval: 1 * time.Millisecond,
		}

		auth := newRDSIAMAuthenticator(config, "localhost:5432", "postgres://testuser@localhost:5432/testdb")
		// Set an old refresh time to trigger refresh
		auth.lastRefresh = time.Now().Add(-2 * time.Millisecond)
		auth.currentToken = "oldtoken"

		token, err := auth.getToken(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "token-1", token)
		assert.Equal(t, 1, buildCalls)
	})
}

func TestModifyConnectionStringForRDSIAM_WithStubbedAWS(t *testing.T) {
	originalLoadAWSConfigForRegion := loadAWSConfigForRegion
	originalBuildRDSAuthToken := buildRDSAuthToken
	t.Cleanup(func() {
		loadAWSConfigForRegion = originalLoadAWSConfigForRegion
		buildRDSAuthToken = originalBuildRDSAuthToken
	})

	loadAWSConfigForRegion = func(ctx context.Context, region string) (aws.Config, error) {
		return aws.Config{}, nil
	}

	buildCalls := 0
	buildRDSAuthToken = func(ctx context.Context, endpoint, region, dbUser string, credentials aws.CredentialsProvider) (string, error) {
		buildCalls++
		assert.Equal(t, "mydb.example.com:5432", endpoint)
		assert.Equal(t, "eu-west-1", region)
		assert.Equal(t, "iam-user", dbUser)
		return fmt.Sprintf("stub-token-%d", buildCalls), nil
	}

	connStr := "postgres://legacy:old-password@mydb.example.com:5432/nuts"
	config := RDSIAMConfig{
		Enabled:              true,
		Region:               "eu-west-1",
		DBUser:               "iam-user",
		TokenRefreshInterval: 1 * time.Millisecond,
	}

	modified, authenticator, err := modifyConnectionStringForRDSIAM(context.Background(), connStr, config)
	require.NoError(t, err)
	require.NotNil(t, authenticator)
	assert.Equal(t, 1, buildCalls)
	assert.Contains(t, modified, "iam-user:stub-token-1")
	assert.NotContains(t, modified, "old-password")

	authenticator.lastRefresh = time.Now().Add(-2 * time.Millisecond)
	next, err := authenticator.GetCurrentConnectionString(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, buildCalls)
	assert.Contains(t, next, "iam-user:stub-token-2")
}
