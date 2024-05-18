/*
 * Copyright (C) 2024 Nuts community
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

package azure

import (
	"context"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"time"
)

// Config contains the config options to configure the vaultKVStorage backend
type Config struct {
	// Token to authenticate to the Vault cluster.
	URL string `koanf:"url"`
	// Timeout specifies the Vault client timeout.
	Timeout time.Duration `koanf:"timeout"`
	// KeyType specifies the type of key to create.
	KeyType azkeys.KeyType `koanf:"keytype"`
}

// DefaultConfig returns the default configuration for the Azure Key Vault storage backend.
func DefaultConfig() Config {
	return Config{
		Timeout: 10 * time.Second,
		KeyType: azkeys.KeyTypeEC,
	}
}

// keyVaultClient is an interface for the Azure Key Vault client, to support mocking.
type keyVaultClient interface {
	CreateKey(ctx context.Context, name string, parameters azkeys.CreateKeyParameters, options *azkeys.CreateKeyOptions) (azkeys.CreateKeyResponse, error)
	GetKey(ctx context.Context, name string, version string, options *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error)
	Sign(ctx context.Context, name string, version string, parameters azkeys.SignParameters, options *azkeys.SignOptions) (azkeys.SignResponse, error)
	DeleteKey(ctx context.Context, name string, options *azkeys.DeleteKeyOptions) (azkeys.DeleteKeyResponse, error)
}
