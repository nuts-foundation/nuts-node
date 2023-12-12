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

package auth

import (
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"net/url"
	"path"
	"time"

	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/nuts-foundation/nuts-node/auth/services/notary"
	"github.com/nuts-foundation/nuts-node/auth/services/oauth"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/didman"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/pki"
	"github.com/nuts-foundation/nuts-node/vcr"
)

const contractValidity = 60 * time.Minute

var _ AuthenticationServices = (*Auth)(nil)

// Auth is the main struct of the Auth service
type Auth struct {
	config                  Config
	jsonldManager           jsonld.JSONLD
	authzServer             oauth.AuthorizationServer
	relyingParty            oauth.RelyingParty
	verifier                oauth.Verifier
	contractNotary          services.ContractNotary
	serviceResolver         didman.CompoundServiceResolver
	keyStore                crypto.KeyStore
	vcr                     vcr.VCR
	pkiProvider             pki.Provider
	shutdownFunc            func()
	vdrInstance             vdr.VDR
	publicURL               *url.URL
	presentationDefinitions *pe.DefinitionResolver
}

// Name returns the name of the module.
func (auth *Auth) Name() string {
	return ModuleName
}

// Config returns the actual config of the module.
func (auth *Auth) Config() interface{} {
	return &auth.config
}

// V2APIEnabled returns true if the v2 API is enabled
func (auth *Auth) V2APIEnabled() bool {
	return auth.config.V2APIEnabled
}

// PublicURL returns the public URL of the node.
func (auth *Auth) PublicURL() *url.URL {
	return auth.publicURL
}

// ContractNotary returns an implementation of the ContractNotary interface.
func (auth *Auth) ContractNotary() services.ContractNotary {
	return auth.contractNotary
}

func (auth *Auth) PresentationDefinitions() *pe.DefinitionResolver {
	return auth.presentationDefinitions
}

// NewAuthInstance accepts a Config with several Nuts Engines and returns an instance of Auth
func NewAuthInstance(config Config, vdrInstance vdr.VDR, vcr vcr.VCR, keyStore crypto.KeyStore, serviceResolver didman.CompoundServiceResolver, jsonldManager jsonld.JSONLD, pkiProvider pki.Provider) *Auth {
	return &Auth{
		config:                  config,
		jsonldManager:           jsonldManager,
		vdrInstance:             vdrInstance,
		keyStore:                keyStore,
		vcr:                     vcr,
		pkiProvider:             pkiProvider,
		serviceResolver:         serviceResolver,
		shutdownFunc:            func() {},
		presentationDefinitions: &pe.DefinitionResolver{},
	}
}

// AuthzServer returns the oauth.AuthorizationServer
func (auth *Auth) AuthzServer() oauth.AuthorizationServer {
	return auth.authzServer
}

// RelyingParty returns the oauth.RelyingParty
func (auth *Auth) RelyingParty() oauth.RelyingParty {
	return auth.relyingParty
}

func (auth *Auth) Verifier() oauth.Verifier {
	return auth.verifier
}

// Configure the Auth struct by creating a validator and create an Irma server
func (auth *Auth) Configure(config core.ServerConfig) error {
	if auth.config.Irma.SchemeManager == "" {
		return errors.New("IRMA SchemeManager must be set")
	}

	if config.Strictmode && auth.config.Irma.SchemeManager != "pbdf" {
		return errors.New("in strictmode the only valid irma-scheme-manager is 'pbdf'")
	}

	var err error
	auth.publicURL, err = config.ServerURL()
	if err != nil {
		return err
	}

	auth.contractNotary = notary.NewNotary(notary.Config{
		PublicURL:             auth.publicURL.String(),
		IrmaConfigPath:        path.Join(config.Datadir, "irma"),
		IrmaSchemeManager:     auth.config.Irma.SchemeManager,
		AutoUpdateIrmaSchemas: auth.config.Irma.AutoUpdateSchemas,
		ContractValidators:    auth.config.ContractValidators,
		ContractValidity:      contractValidity,
		StrictMode:            config.Strictmode,
	}, auth.vcr, resolver.DIDKeyResolver{Resolver: auth.vdrInstance.Resolver()}, auth.keyStore, auth.jsonldManager, auth.pkiProvider)

	tlsEnabled := config.TLS.Enabled()
	if config.Strictmode && !tlsEnabled {
		return errors.New("in strictmode TLS must be enabled")
	}

	tlsConfig, err := auth.pkiProvider.CreateTLSConfig(config.TLS) // returns nil if TLS is disabled
	if err != nil {
		return err
	}

	if err := auth.contractNotary.Configure(); err != nil {
		return err
	}

	// load presentation definitions
	if auth.config.PresentationExchangeMappingFile != "" {
		if err := auth.presentationDefinitions.LoadFromFile(auth.config.PresentationExchangeMappingFile); err != nil {
			return fmt.Errorf("failed to load presentation exchange mapping file: %w", err)
		}
	}

	accessTokenLifeSpan := time.Duration(auth.config.AccessTokenLifeSpan) * time.Second
	auth.authzServer = oauth.NewAuthorizationServer(auth.vdrInstance.Resolver(), auth.vcr, auth.vcr.Verifier(), auth.serviceResolver,
		auth.keyStore, auth.contractNotary, auth.jsonldManager, accessTokenLifeSpan)
	auth.relyingParty = oauth.NewRelyingParty(auth.vdrInstance.Resolver(), auth.serviceResolver,
		auth.keyStore, auth.vcr.Wallet(), time.Duration(auth.config.HTTPTimeout)*time.Second, tlsConfig, config.Strictmode)
	auth.verifier = oauth.NewVerifier(config.Strictmode, time.Duration(auth.config.HTTPTimeout)*time.Second, tlsConfig)

	if err := auth.authzServer.Configure(auth.config.ClockSkew, config.Strictmode); err != nil {
		return err
	}

	return nil
}

// Start starts the Auth engine (Noop)
func (auth *Auth) Start() error {
	return nil
}

// Shutdown stops the Auth engine
func (auth *Auth) Shutdown() error {
	return nil
}
