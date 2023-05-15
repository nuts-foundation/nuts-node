/*
 * Nuts node
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

package vcr

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/pki"
	"io/fs"
	"net/url"
	"path"
	"strings"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/go-leia/v3"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/events"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vcr/assets"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vcr/issuer"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"github.com/nuts-foundation/nuts-node/vcr/trust"
	"github.com/nuts-foundation/nuts-node/vcr/types"
	"github.com/nuts-foundation/nuts-node/vcr/verifier"
	"github.com/nuts-foundation/nuts-node/vdr/didservice"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"
	"gopkg.in/yaml.v3"
)

// NewVCRInstance creates a new vcr instance with default config and empty concept registry
func NewVCRInstance(keyStore crypto.KeyStore, docResolver vdr.DocResolver, keyResolver vdr.KeyResolver,
	network network.Transactions, jsonldManager jsonld.JSONLD, eventManager events.Event, storageClient storage.Engine,
	pkiProvider pki.Provider) VCR {
	r := &vcr{
		config:          DefaultConfig(),
		docResolver:     docResolver,
		keyStore:        keyStore,
		keyResolver:     keyResolver,
		serviceResolver: didservice.NewServiceResolver(docResolver),
		network:         network,
		jsonldManager:   jsonldManager,
		eventManager:    eventManager,
		storageClient:   storageClient,
		pkiProvider:     pkiProvider,
	}
	return r
}

type vcr struct {
	config          Config
	store           leia.Store
	keyStore        crypto.KeyStore
	docResolver     vdr.DocResolver
	keyResolver     vdr.KeyResolver
	serviceResolver didservice.ServiceResolver
	ambassador      Ambassador
	network         network.Transactions
	trustConfig     *trust.Config
	tenants         TenantRegistry
	issuer          issuer.Issuer
	verifier        verifier.Verifier
	holder          holder.Holder
	issuerStore     issuer.Store
	verifierStore   verifier.Store
	jsonldManager   jsonld.JSONLD
	eventManager    events.Event
	storageClient   storage.Engine
	oidcIssuer      issuer.OIDCIssuer
	pkiProvider     pki.Provider
	clientTLSConfig *tls.Config
}

func (c *vcr) GetOIDCIssuer() issuer.OIDCIssuer {
	return c.oidcIssuer
}

func (c *vcr) GetOIDCWallet(id did.DID) holder.OIDCWallet {
	identifier := core.JoinURLPaths(c.config.OIDC4VCI.URL, "n2n", "identity", url.PathEscape(id.String()))
	return holder.NewOIDCWallet(id, identifier, c, c.keyStore, c.keyResolver, c.config.OIDC4VCI.Timeout, c.clientTLSConfig)
}

func (c *vcr) Issuer() issuer.Issuer {
	return c.issuer
}

func (c *vcr) Holder() holder.Holder {
	return c.holder
}

func (c *vcr) Verifier() verifier.Verifier {
	return c.verifier
}

func (c *vcr) Tenants() TenantRegistry {
	return c.tenants
}

func (c *vcr) Configure(config core.ServerConfig) error {
	var err error

	// store config parameters for use in Start()
	c.config.datadir = config.Datadir

	issuerStorePath := path.Join(c.config.datadir, "vcr", "issued-credentials.db")
	issuerBackupStore, err := c.storageClient.GetProvider(ModuleName).GetKVStore("backup-issued-credentials", storage.PersistentStorageClass)
	if err != nil {
		return err
	}
	c.issuerStore, err = issuer.NewLeiaIssuerStore(issuerStorePath, issuerBackupStore)
	if err != nil {
		return err
	}

	verifierStorePath := path.Join(c.config.datadir, "vcr", "verifier-store.db")
	c.verifierStore, err = verifier.NewLeiaVerifierStore(verifierStorePath)
	if err != nil {
		return err
	}

	// create trust config
	tcPath := path.Join(config.Datadir, "vcr", "trusted_issuers.yaml")
	c.trustConfig = trust.NewConfig(tcPath)

	networkPublisher := issuer.NewNetworkPublisher(c.network, c.docResolver, c.keyStore)
	if c.config.OIDC4VCI.Enabled {
		if c.config.OIDC4VCI.URL == "" {
			return errors.New("vcr.oidc4vci.url must be configured to enable OIDC4VCI")
		}
		// Must be either HTTP or HTTPS, in strict mode HTTPS is required
		if strings.HasPrefix(c.config.OIDC4VCI.URL, "http://") {
			if config.Strictmode {
				return errors.New("vcr.oidc4vci.url must use HTTPS when strictmode is enabled")
			}
		} else if !strings.HasPrefix(c.config.OIDC4VCI.URL, "https://") {
			return errors.New("vcr.oidc4vci.url must contain a valid URL (using http:// or https://)")
		}

		c.clientTLSConfig, err = c.pkiProvider.CreateTLSConfig(config.TLS) // returns nil if TLS is disabled
		if err != nil {
			return err
		}

		c.oidcIssuer = issuer.NewOIDCIssuer(core.JoinURLPaths(c.config.OIDC4VCI.URL, "n2n", "identity"), c.clientTLSConfig, c.config.OIDC4VCI.Timeout, c.keyResolver)
	}
	c.issuer = issuer.NewIssuer(c.issuerStore, c, networkPublisher, c.oidcIssuer, c.docResolver, c.keyStore, c.jsonldManager, c.trustConfig)
	c.verifier = verifier.NewVerifier(c.verifierStore, c.docResolver, c.keyResolver, c.jsonldManager, c.trustConfig)

	c.ambassador = NewAmbassador(c.network, c, c.verifier, c.eventManager)

	c.holder = holder.New(c.keyResolver, c.keyStore, c.verifier, c.jsonldManager)

	return c.trustConfig.Load()
}

func (c *vcr) credentialsDBPath() string {
	return path.Join(c.config.datadir, "vcr", "credentials.db")
}

func (c *vcr) Start() error {
	var err error

	// setup DB connection
	if c.store, err = leia.NewStore(c.credentialsDBPath(), leia.WithDocumentLoader(c.jsonldManager.DocumentLoader())); err != nil {
		return err
	}

	// init indices
	if err = c.initJSONLDIndices(); err != nil {
		return err
	}

	// start listening for new credentials
	c.ambassador.Configure()

	return c.ambassador.Start()
}

func (c *vcr) Shutdown() error {
	err := c.issuerStore.Close()
	if err != nil {
		log.Logger().
			WithError(err).
			Error("Unable to close issuer store")
	}
	err = c.verifierStore.Close()
	if err != nil {
		log.Logger().
			WithError(err).
			Error("Unable to close verifier store")
	}
	return c.store.Close()
}

func whitespaceOrExactTokenizer(text string) (tokens []string) {
	tokens = leia.WhiteSpaceTokenizer(text)
	tokens = append(tokens, text)

	return
}

func (c *vcr) credentialCollection() leia.Collection {
	return c.store.JSONLDCollection("credentials")
}

func (c *vcr) loadJSONLDConfig() ([]indexConfig, error) {
	list, err := fs.Glob(assets.Assets, "**/*.index.yaml")
	if err != nil {
		return nil, err
	}

	configs := make([]indexConfig, 0)
	for _, f := range list {
		bytes, err := assets.Assets.ReadFile(f)
		if err != nil {
			return nil, err
		}
		config := indexConfig{}
		err = yaml.Unmarshal(bytes, &config)
		if err != nil {
			return nil, err
		}

		configs = append(configs, config)
	}

	return configs, nil
}

func (c *vcr) initJSONLDIndices() error {
	collection := c.credentialCollection()

	configs, err := c.loadJSONLDConfig()
	if err != nil {
		return err
	}

	for _, config := range configs {
		for _, index := range config.Indices {
			var leiaParts []leia.FieldIndexer

			for _, iParts := range index.Parts {
				options := make([]leia.IndexOption, 0)
				if iParts.Tokenizer != nil {
					tokenizer := strings.ToLower(*iParts.Tokenizer)
					switch tokenizer {
					case "whitespaceorexact":
						options = append(options, leia.TokenizerOption(whitespaceOrExactTokenizer))
					case "whitespace":
						options = append(options, leia.TokenizerOption(leia.WhiteSpaceTokenizer))
					default:
						return fmt.Errorf("unknown tokenizer %s for %s", *iParts.Tokenizer, index.Name)
					}
				}
				if iParts.Transformer != nil {
					transformer := strings.ToLower(*iParts.Transformer)
					switch transformer {
					case "cologne":
						options = append(options, leia.TransformerOption(CologneTransformer))
					case "lowercase":
						options = append(options, leia.TransformerOption(leia.ToLower))
					default:
						return fmt.Errorf("unknown transformer %s for %s", *iParts.Transformer, index.Name)
					}
				}

				leiaParts = append(leiaParts, leia.NewFieldIndexer(leia.NewIRIPath(iParts.IRIPath...), options...))
			}

			leiaIndex := collection.NewIndex(index.Name, leiaParts...)
			log.Logger().Debugf("Adding index %s", index.Name)

			if err := collection.AddIndex(leiaIndex); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *vcr) Name() string {
	return ModuleName
}

func (c *vcr) Config() interface{} {
	return &c.config
}

func (c *vcr) OIDC4VCIEnabled() bool {
	return c.config.OIDC4VCI.Enabled
}

func (c *vcr) Resolve(ID ssi.URI, resolveTime *time.Time) (*vc.VerifiableCredential, error) {
	credential, err := c.find(ID)
	if err != nil {
		return nil, err
	}

	// we don't have to check the signature, it's coming from our own store.
	if err = c.verifier.Verify(credential, false, false, resolveTime); err != nil {
		switch err {
		case types.ErrRevoked:
			return &credential, types.ErrRevoked
		case types.ErrUntrusted:
			return &credential, types.ErrUntrusted
		default:
			return nil, err
		}
	}
	return &credential, nil
}

// find only returns a VC from storage, it does not tell anything about validity
func (c *vcr) find(ID ssi.URI) (vc.VerifiableCredential, error) {
	credential := vc.VerifiableCredential{}
	qp := leia.Eq(leia.NewIRIPath(), leia.MustParseScalar(ID.String()))
	q := leia.New(qp)

	ctx, cancel := context.WithTimeout(context.Background(), maxFindExecutionTime)
	defer cancel()

	docs, err := c.credentialCollection().Find(ctx, q)
	if err != nil {
		return credential, err
	}
	if len(docs) > 0 {
		// there can be only one
		err = json.Unmarshal(docs[0], &credential)
		if err != nil {
			return credential, fmt.Errorf("unable to parse credential from db: %w", err)
		}

		return credential, nil
	}

	return credential, types.ErrNotFound
}

func (c *vcr) Trust(credentialType ssi.URI, issuer ssi.URI) error {
	err := c.trustConfig.AddTrust(credentialType, issuer)
	if err != nil {
		log.Logger().
			WithField(core.LogFieldCredentialType, credentialType).
			WithField(core.LogFieldCredentialIssuer, issuer).
			Info("Added trust for Verifiable Credential issuer")
	}
	return err
}

func (c *vcr) Untrust(credentialType ssi.URI, issuer ssi.URI) error {
	err := c.trustConfig.RemoveTrust(credentialType, issuer)
	if err != nil {
		log.Logger().
			WithField(core.LogFieldCredentialType, credentialType).
			WithField(core.LogFieldCredentialIssuer, issuer).
			Info("Untrusted for Verifiable Credential issuer")
	}
	return err
}

func (c *vcr) Trusted(credentialType ssi.URI) ([]ssi.URI, error) {
	return c.trustConfig.List(credentialType), nil
}

func (c *vcr) Untrusted(credentialType ssi.URI) ([]ssi.URI, error) {
	trustMap := make(map[string]bool)
	untrusted := make([]ssi.URI, 0)
	for _, trusted := range c.trustConfig.List(credentialType) {
		trustMap[trusted.String()] = true
	}

	// check all issued VCs
	query := leia.New(leia.NotNil(leia.NewIRIPath(jsonld.CredentialIssuerPath...)))

	// use type specific collection
	collection := c.credentialCollection()

	// for each key: add to untrusted if not present in trusted
	err := collection.IndexIterate(query, func(key []byte, value []byte) error {
		// we iterate over all issuers->reference pairs
		issuer := string(key)
		if _, ok := trustMap[issuer]; !ok {
			u, err := ssi.ParseURI(issuer)
			if err != nil {
				return err
			}
			trustMap[issuer] = true

			// only add to untrusted if issuer is not deactivated or has active controllers
			issuerDid, err := did.ParseDIDURL(issuer)
			if err != nil {
				return err
			}
			_, _, err = c.docResolver.Resolve(*issuerDid, nil)
			if err != nil {
				if !(errors.Is(err, did.DeactivatedErr) || errors.Is(err, vdr.ErrNoActiveController)) {
					return err
				}
			} else {
				untrusted = append(untrusted, *u)
			}
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, leia.ErrNoIndex) {
			log.Logger().
				WithField(core.LogFieldCredentialType, credentialType).
				Warn("No index with field 'issuer' found for credential")

			return nil, types.ErrInvalidCredential
		}
		return nil, err
	}

	return untrusted, nil
}

func (c *vcr) Diagnostics() []core.DiagnosticResult {
	var credentialCount int
	var err error
	credentialCount, err = c.credentialCollection().DocumentCount()
	if err != nil {
		credentialCount = -1
		log.Logger().
			WithError(err).
			Warn("unable to retrieve credential document count")
	}
	return []core.DiagnosticResult{
		core.DiagnosticResultMap{
			Title: "issuer",
			Items: c.issuerStore.Diagnostics(),
		},
		core.DiagnosticResultMap{
			Title: "verifier",
			Items: c.verifierStore.Diagnostics(),
		},
		core.GenericDiagnosticResult{
			Title:   "credential_count",
			Outcome: credentialCount,
		},
	}
}
