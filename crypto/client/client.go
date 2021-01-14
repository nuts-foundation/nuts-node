/*
 * Nuts registry
 * Copyright (C) 2020. Nuts community
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

package client

import (
	"time"

	"github.com/nuts-foundation/nuts-node/core"

	api "github.com/nuts-foundation/nuts-node/crypto/api/v1"
	"github.com/nuts-foundation/nuts-node/crypto"
)

// NewCryptoClient creates a new local or remote client, depending on engine configuration.
func NewCryptoClient() crypto.Client {
	instance := crypto.Instance()
	if core.NutsConfig().GetEngineMode(instance.Config.Mode) == core.ServerEngineMode {
		return instance
	}

	return api.HttpClient{
		ServerAddress: instance.Config.Address,
		Timeout:       time.Duration(instance.Config.ClientTimeout) * time.Second,
	}
}
