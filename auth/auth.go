package auth

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"path"
	"time"

	"github.com/nuts-foundation/nuts-node/didman"

	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/nuts-foundation/nuts-node/auth/services/contract"
	"github.com/nuts-foundation/nuts-node/auth/services/oauth"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vdr/doc"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

// ErrMissingPublicURL is returned when the publicUrl is missing from the config
var ErrMissingPublicURL = errors.New("missing publicUrl")

const contractValidity = 60 * time.Minute

// Auth is the main struct of the Auth service
type Auth struct {
	config            Config
	oauthClient       services.OAuthClient
	contractNotary    services.ContractNotary
	keyStore          crypto.KeyStore
	registry          types.Store
	vcr               vcr.VCR
	trustStore        *x509.CertPool
	clientCertificate *tls.Certificate
	serviceResolver   didman.ServiceResolver
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

// TrustStore contains an x509 certificate pool (only when TLS is enabled)
func (auth *Auth) TrustStore() *x509.CertPool {
	return auth.trustStore
}

func (auth *Auth) TLSEnabled() bool {
	return auth.config.EnableTLS
}

func (auth *Auth) ClientCertificate() *tls.Certificate {
	return auth.clientCertificate
}

// ContractNotary returns an implementation of the ContractNotary interface.
func (auth *Auth) ContractNotary() services.ContractNotary {
	return auth.contractNotary
}

// NewAuthInstance accepts a Config with several Nuts Engines and returns an instance of Auth
func NewAuthInstance(config Config, registry types.Store, vcr vcr.VCR, keyStore crypto.KeyStore, serviceResolver didman.ServiceResolver) *Auth {
	return &Auth{
		config:          config,
		registry:        registry,
		keyStore:        keyStore,
		vcr:             vcr,
		serviceResolver: serviceResolver,
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

	cfg := contract.Config{
		PublicURL:             auth.config.PublicURL,
		IrmaConfigPath:        path.Join(config.Datadir, "irma"),
		IrmaSchemeManager:     auth.config.IrmaSchemeManager,
		AutoUpdateIrmaSchemas: auth.config.IrmaAutoUpdateSchemas,
		ContractValidators:    auth.config.ContractValidators,
		ContractValidity:      contractValidity,
	}

	keyResolver := doc.KeyResolver{Store: auth.registry}

	auth.contractNotary = contract.NewNotary(cfg, auth.vcr, keyResolver, auth.keyStore)

	if config.Strictmode && !auth.config.EnableTLS {
		return errors.New("in strictmode auth.enabletls must be true")
	}
	if auth.config.EnableTLS {
		clientCertificate, err := tls.LoadX509KeyPair(auth.config.CertFile, auth.config.CertKeyFile)
		if err != nil {
			return fmt.Errorf("unable to load node TLS client certificate (certfile=%s,certkeyfile=%s): %w", auth.config.CertFile, auth.config.CertKeyFile, err)
		}

		trustStore, err := core.LoadTrustStore(auth.config.TrustStoreFile)
		if err != nil {
			return err
		}

		auth.trustStore = trustStore.CertPool
		auth.clientCertificate = &clientCertificate
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
