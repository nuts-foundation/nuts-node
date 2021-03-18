package auth

import (
	"errors"
	"path"
	"time"

	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/nuts-foundation/nuts-node/auth/services/contract"
	"github.com/nuts-foundation/nuts-node/auth/services/oauth"
	"github.com/nuts-foundation/nuts-node/auth/services/validator"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

// ErrMissingPublicURL is returned when the publicUrl is missing from the config
var ErrMissingPublicURL = errors.New("missing publicUrl")

const contractValidity = 60 * time.Minute

// Auth is the main struct of the Auth service
type Auth struct {
	config         Config
	oauthClient    services.OAuthClient
	contractClient services.ContractClient
	contractNotary services.ContractNotary
	keyStore       crypto.KeyStore
	registry       types.VDR
	vcr            vcr.VCR
}

// Name returns the name of the module.
func (auth *Auth) Name() string {
	return moduleName
}

// ConfigKey returns the config key of the module.
func (auth *Auth) ConfigKey() string {
	return configKey
}

// Config returns the actual config of the module.
func (auth *Auth) Config() interface{} {
	return &auth.config
}

// ContractNotary returns an implementation of the ContractNotary interface.
func (auth *Auth) ContractNotary() services.ContractNotary {
	return auth.contractNotary
}

// NewAuthInstance accepts a Config with several Nuts Engines and returns an instance of Auth
func NewAuthInstance(config Config, registry types.VDR, vcr vcr.VCR, keyStore crypto.KeyStore) *Auth {
	return &Auth{
		config:   config,
		registry: registry,
		keyStore: keyStore,
		vcr:      vcr,
	}
}

// OAuthClient returns an instance of OAuthClient
func (auth *Auth) OAuthClient() services.OAuthClient {
	return auth.oauthClient
}

// ContractClient returns an instance of ContractClient
func (auth *Auth) ContractClient() services.ContractClient {
	return auth.contractClient
}

// Configure the Auth struct by creating a validator and create an Irma server
func (auth *Auth) Configure(config core.ServerConfig) error {
	if auth.config.Irma.SchemeManager == "" {
		return errors.New("IRMA SchemeManager must be set")
	}
	if config.Strictmode && auth.config.Irma.SchemeManager != "pbdf" {
		return errors.New("in strictmode the only valid irma-scheme-manager is 'pbdf'")
	}

	// TODO: this is verifier/signer specific
	if auth.config.PublicURL == "" {
		if config.Strictmode {
			return ErrMissingPublicURL
		}
		auth.config.PublicURL = "http://" + config.HTTP.Address
	}

	cfg := validator.Config{
		PublicURL:             auth.config.PublicURL,
		IrmaConfigPath:        path.Join(config.Datadir, "irma"),
		IrmaSchemeManager:     auth.config.Irma.SchemeManager,
		AutoUpdateIrmaSchemas: auth.config.Irma.AutoUpdateSchemas,
		ContractValidators:    auth.config.ContractValidators,
	}
	nameResolver := auth.vcr
	auth.contractNotary = contract.NewContractNotary(nameResolver, contractValidity)
	auth.contractClient = validator.NewContractInstance(cfg, auth.registry, auth.keyStore)
	if err := auth.contractClient.Configure(); err != nil {
		return err
	}
	auth.oauthClient = oauth.NewOAuthService(auth.registry, nameResolver, auth.keyStore, auth.contractClient)
	if err := auth.oauthClient.Configure(); err != nil {
		return err
	}

	return nil
}
