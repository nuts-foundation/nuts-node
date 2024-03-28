/*
 * Copyright (C) 2023 Nuts community
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

package policy

import (
	"context"
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/pki"
	"github.com/nuts-foundation/nuts-node/policy/api/v1/client"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"net/url"
	"os"
)

// NewRouter creates a new policy backend router that can forward requests to the correct backend
func NewRouter(pkiInstance pki.Provider) *Router {
	return &Router{
		pkiInstance: pkiInstance,
	}
}

type Router struct {
	backend     PDPBackend
	config      Config
	pkiInstance pki.Provider
}

func (b *Router) Name() string {
	return ModuleName
}

func (b *Router) Configure(config core.ServerConfig) error {
	// check if directory exists
	if b.config.Directory != "" {
		_, err := os.Stat(b.config.Directory)
		if err != nil {
			if os.IsNotExist(err) && b.config.Directory == defaultConfig().Directory {
				// assume this is the default config value and remove it
				b.config.Directory = ""
			} else {
				return fmt.Errorf("failed to load policy from directory: %w", err)
			}
		}
		// keep valid directory
	}

	// if both directory and address are set, return error
	if b.config.Directory != "" && b.config.Address != "" {
		return errors.New("both policy.directory and policy.address are set, please choose one")
	}

	// if address is set use remote backend, otherwise use local backend
	if b.config.Address != "" {
		_, err := url.Parse(b.config.Address)
		if err != nil {
			return fmt.Errorf("failed to parse policy.address: %w", err)
		}
		tlsConfig, err := b.pkiInstance.CreateTLSConfig(config.TLS)
		if err != nil {
			return err
		}
		b.backend = &remote{
			address: b.config.Address,
			client:  client.NewHTTPClient(config.Strictmode, config.HTTPClient.Timeout, tlsConfig),
		}
	}
	if b.config.Directory != "" {
		backend := &localPDP{}
		if err := backend.loadFromDirectory(b.config.Directory); err != nil {
			return fmt.Errorf("failed to load policy from directory: %w", err)
		}
		b.backend = backend
	}

	return nil
}

func (b *Router) Config() interface{} {
	return &b.config
}

func (b *Router) PresentationDefinition(ctx context.Context, authorizer did.DID, scope string) (*pe.PresentationDefinition, error) {
	if b.backend == nil {
		return nil, errors.New("no policy backend configured")
	}
	return b.backend.PresentationDefinition(ctx, authorizer, scope)
}

func (b *Router) Authorized(ctx context.Context, requestInfo client.AuthorizedRequest) (bool, error) {
	if b.backend == nil {
		return false, errors.New("no policy backend configured")
	}
	return b.backend.Authorized(ctx, requestInfo)
}
