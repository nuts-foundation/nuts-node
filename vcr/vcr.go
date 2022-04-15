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
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strings"
	"time"

	"github.com/nuts-foundation/go-leia/v3"

	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr/holder"

	"gopkg.in/yaml.v2"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/vcr/assets"
	"github.com/nuts-foundation/nuts-node/vcr/issuer"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"github.com/nuts-foundation/nuts-node/vcr/trust"
	"github.com/nuts-foundation/nuts-node/vcr/types"
	"github.com/nuts-foundation/nuts-node/vcr/verifier"
	"github.com/nuts-foundation/nuts-node/vdr/doc"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"
)

var timeFunc = time.Now

// noSync is used to disable bbolt syncing on go-leia during tests
var noSync bool

// NewVCRInstance creates a new vcr instance with default config and empty concept registry
func NewVCRInstance(keyStore crypto.KeyStore, docResolver vdr.DocResolver, keyResolver vdr.KeyResolver, network network.Transactions, jsonldManager jsonld.JSONLD) VCR {
	r := &vcr{
		config:          DefaultConfig(),
		docResolver:     docResolver,
		keyStore:        keyStore,
		keyResolver:     keyResolver,
		serviceResolver: doc.NewServiceResolver(docResolver),
		network:         network,
		jsonldManager:   jsonldManager,
	}

	return r
}

type vcr struct {
	config          Config
	store           leia.Store
	keyStore        crypto.KeyStore
	docResolver     vdr.DocResolver
	keyResolver     vdr.KeyResolver
	serviceResolver doc.ServiceResolver
	ambassador      Ambassador
	network         network.Transactions
	trustConfig     *trust.Config
	issuer          issuer.Issuer
	verifier        verifier.Verifier
	holder          holder.Holder
	issuerStore     issuer.Store
	verifierStore   verifier.Store
	jsonldManager   jsonld.JSONLD
}

func (c vcr) Issuer() issuer.Issuer {
	return c.issuer
}

func (c vcr) Holder() holder.Holder {
	return c.holder
}

func (c *vcr) Verifier() verifier.Verifier {
	return c.verifier
}

func (c *vcr) Configure(config core.ServerConfig) error {
	var err error

	// store config parameters for use in Start()
	c.config.strictMode = config.Strictmode
	c.config.datadir = config.Datadir

	issuerStorePath := path.Join(c.config.datadir, "vcr", "issued-credentials.db")
	c.issuerStore, err = issuer.NewLeiaIssuerStore(issuerStorePath)
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

	publisher := issuer.NewNetworkPublisher(c.network, c.docResolver, c.keyStore)
	c.issuer = issuer.NewIssuer(c.issuerStore, publisher, c.docResolver, c.keyStore, c.jsonldManager, c.trustConfig)
	c.verifier = verifier.NewVerifier(c.verifierStore, c.keyResolver, c.jsonldManager, c.trustConfig)

	c.ambassador = NewAmbassador(c.network, c, c.verifier)

	c.holder = holder.New(c.keyResolver, c.keyStore, c.verifier, c.jsonldManager)

	return c.trustConfig.Load()
}

func (c *vcr) credentialsDBPath() string {
	return path.Join(c.config.datadir, "vcr", "credentials.db")
}

func (c *vcr) Migrate() error {
	// the migration to go-leia V3 needs a fresh DB
	// The DAG is rewalked so all entries are added
	// just delete
	// TODO remove after all parties in development network have migrated.
	err := os.Remove(c.credentialsDBPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
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

	return nil
}

func (c *vcr) Shutdown() error {
	err := c.issuerStore.Close()
	if err != nil {
		log.Logger().Errorf("Unable to close issuer store: %v", err)
	}
	err = c.verifierStore.Close()
	if err != nil {
		log.Logger().Errorf("Unable to close verifier store: %v", err)
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
	return moduleName
}

func (c *vcr) Config() interface{} {
	return &c.config
}

func (c *vcr) Resolve(ID ssi.URI, resolveTime *time.Time) (*vc.VerifiableCredential, error) {
	credential, err := c.find(ID)
	if err != nil {
		return nil, err
	}

	// we don't have to check the signature, it's coming from our own store.
	if err = c.Validate(credential, false, false, resolveTime); err != nil {
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

// Validate validates the provided credential.
// The function returns nil when the credential is considered valid, the validation error otherwise.
//
// It accepts a few extra flags which configure the validation process:
// * If the allowUntrusted bool is set to true, the credential is not checked for trust.
//   This means that the validity does not depend on if the issuer-type combination is set to be trusted on this node.
// * If the checkSignature is set to false, the signature will not be checked.
//   If it is set to true, the signature must compute. Also, the used signing key must be valid at the validAt time.
//   A signing key is considered valid if the issuer AND at least one (if any) of its controllers was active at the validAt time.
// * If the validAt is not provided, validAt will be set to the current time.
//
// In addition to the signing key time checks, the following checks will be performed:
// * The ID fields must be set
// * The credential is not revoked (note: the revocation state is currently time independent)
// * The type must contain exactly one type in addition to the default `VerifiableCredential` type.
// * The issuanceDate must be before the validAt.
// * The expirationDate must be after the validAt.
func (c *vcr) Validate(credential vc.VerifiableCredential, allowUntrusted bool, checkSignature bool, validAt *time.Time) error {
	if credential.ID == nil {
		return errors.New("verifying a credential requires it to have a valid ID")
	}

	if validAt == nil {
		now := timeFunc()
		validAt = &now
	}

	if checkSignature {
		// check if the issuer was valid at the given time. (not deactivated, or deactivated controller)
		issuerDID, _ := did.ParseDID(credential.Issuer.String())
		_, _, err := c.docResolver.Resolve(*issuerDID, &vdr.ResolveMetadata{ResolveTime: validAt, AllowDeactivated: false})
		if err != nil {
			return fmt.Errorf("could not check validity of signing key: %w", err)
		}
	}

	// perform the rest of the verification steps
	return c.verifier.Verify(credential, allowUntrusted, checkSignature, validAt)
}

func (c *vcr) isTrusted(credential vc.VerifiableCredential) bool {
	for _, t := range credential.Type {
		if c.trustConfig.IsTrusted(t, credential.Issuer) {
			return true
		}
	}

	return false
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
		log.Logger().Infof("Added trust for Verifiable Credential issuer (type=%s, issuer=%s)", credentialType, issuer)
	}
	return err
}

func (c *vcr) Untrust(credentialType ssi.URI, issuer ssi.URI) error {
	err := c.trustConfig.RemoveTrust(credentialType, issuer)
	if err != nil {
		log.Logger().Infof("Untrusted for Verifiable Credential issuer (type=%s, issuer=%s)", credentialType, issuer)
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
			untrusted = append(untrusted, *u)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, leia.ErrNoIndex) {
			log.Logger().Warnf("No index with field 'issuer' found for %s", credentialType.String())

			return nil, types.ErrInvalidCredential
		}
		return nil, err
	}

	return untrusted, nil
}
