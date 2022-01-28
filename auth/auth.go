/*
 * Copyright (C) 2021 Nuts community
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

package auth

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"path"
	"time"

	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/nuts-foundation/nuts-node/auth/services/contract"
	"github.com/nuts-foundation/nuts-node/auth/services/oauth"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crl"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/didman"
	vcr "github.com/nuts-foundation/nuts-node/vcr/types"
	"github.com/nuts-foundation/nuts-node/vdr/doc"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

// ErrMissingPublicURL is returned when the publicUrl is missing from the config
var ErrMissingPublicURL = errors.New("missing publicUrl")

const contractValidity = 60 * time.Minute

// Auth is the main struct of the Auth service
type Auth struct {
	config          Config
	oauthClient     services.OAuthClient
	contractNotary  services.ContractNotary
	serviceResolver didman.CompoundServiceResolver
	keyStore        crypto.KeyStore
	registry        types.Store
	vcr             vcr.VCR
	tlsConfig       *tls.Config
	crlValidator    crl.Validator
	shutdownFunc    func()
}

// Name returns the name of the module.
func (auth *Auth) Name() string {
	return ModuleName
}

// Config returns the actual config of the module.
func (auth *Auth) Config() interface{} {
	return &auth.config
}

// HTTPTimeout returns the HTTP timeout to use for the Auth API HTTP client
func (auth *Auth) HTTPTimeout() time.Duration {
	return time.Duration(auth.config.HTTPTimeout) * time.Second
}

// TLSConfig returns the TLS configuration when TLS is enabled and nil if it's disabled
func (auth *Auth) TLSConfig() *tls.Config {
	return auth.tlsConfig
}

// ContractNotary returns an implementation of the ContractNotary interface.
func (auth *Auth) ContractNotary() services.ContractNotary {
	return auth.contractNotary
}

// NewAuthInstance accepts a Config with several Nuts Engines and returns an instance of Auth
func NewAuthInstance(config Config, registry types.Store, vcr vcr.VCR, keyStore crypto.KeyStore, serviceResolver didman.CompoundServiceResolver) *Auth {
	return &Auth{
		config:          config,
		registry:        registry,
		keyStore:        keyStore,
		vcr:             vcr,
		serviceResolver: serviceResolver,
		shutdownFunc:    func() {},
	}
}

// OAuthClient returns an instance of OAuthClient
func (auth *Auth) OAuthClient() services.OAuthClient {
	return auth.oauthClient
}

// Configure the Auth struct by creating a validator and create an Irma server
func (auth *Auth) Configure(config core.ServerConfig) error {
	if auth.config.IrmaSchemeManager == "" {
		return errors.New("IRMA SchemeManager must be set")
	}

	if config.Strictmode && auth.config.IrmaSchemeManager != "pbdf" {
		return errors.New("in strictmode the only valid irma-scheme-manager is 'pbdf'")
	}

	// TODO: this is verifier/signer specific
	if auth.config.PublicURL == "" {
		if config.Strictmode {
			return ErrMissingPublicURL
		}

		auth.config.PublicURL = "http://" + config.HTTP.Address
	}

	auth.contractNotary = contract.NewNotary(contract.Config{
		PublicURL:             auth.config.PublicURL,
		IrmaConfigPath:        path.Join(config.Datadir, "irma"),
		IrmaSchemeManager:     auth.config.IrmaSchemeManager,
		AutoUpdateIrmaSchemas: auth.config.IrmaAutoUpdateSchemas,
		ContractValidators:    auth.config.ContractValidators,
		ContractValidity:      contractValidity,
	}, auth.vcr, doc.KeyResolver{Store: auth.registry}, auth.keyStore)

	if config.Strictmode && !auth.config.tlsEnabled() {
		return errors.New("in strictmode TLS must be enabled")
	}

	if auth.config.tlsEnabled() {
		clientCertificate, err := tls.LoadX509KeyPair(auth.config.CertFile, auth.config.CertKeyFile)
		if err != nil {
			return fmt.Errorf("unable to load node TLS client certificate (certfile=%s,certkeyfile=%s): %w", auth.config.CertFile, auth.config.CertKeyFile, err)
		}

		trustStore, err := core.LoadTrustStore(auth.config.TrustStoreFile)
		if err != nil {
			return err
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{clientCertificate},
			RootCAs:      trustStore.CertPool,
			MinVersion:   core.MinTLSVersion,
		}

		validator := crl.NewValidator(trustStore.Certificates())
		validator.Configure(tlsConfig, auth.config.MaxCRLValidityDays)

		auth.crlValidator = validator
		auth.tlsConfig = tlsConfig
	}

	if err := auth.contractNotary.Configure(); err != nil {
		return err
	}

	auth.oauthClient = oauth.NewOAuthService(auth.registry, auth.vcr, auth.vcr, auth.serviceResolver, auth.keyStore, auth.contractNotary)

	if err := auth.oauthClient.Configure(auth.config.ClockSkew); err != nil {
		return err
	}

	return nil
}

// Start starts the CRL validator synchronization loop
func (auth *Auth) Start() error {
	ctx, cancel := context.WithCancel(context.Background())

	auth.shutdownFunc = cancel

	if auth.crlValidator != nil {
		auth.crlValidator.SyncLoop(ctx)
	}

	return nil
}

// Shutdown stops the CRL validator synchronization loop
func (auth *Auth) Shutdown() error {
	auth.shutdownFunc()

	return nil
}
