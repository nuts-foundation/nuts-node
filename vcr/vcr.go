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
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"time"

	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-leia"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/logging"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/pkg/errors"
)

// NewVCRInstance creates a new vcr instance with default config and empty concept registry
func NewVCRInstance(keystore crypto.KeyStore, docResolver vdr.Resolver, network network.Transactions) VCR {
	return &vcr{
		config:      DefaultConfig(),
		registry:    concept.NewRegistry(),
		keystore:    keystore,
		docResolver: docResolver,
		network:     network,
	}
}

type vcr struct {
	registry    concept.Registry
	config      Config
	store       leia.Store
	keystore    crypto.KeyStore
	docResolver vdr.Resolver
	network     network.Transactions
}

// JSONWebSignature2020Proof is a VC proof with a signature according to JsonWebSignature2020
type JSONWebSignature2020Proof struct {
	did.Proof
	Jws string `json:"jws"`
}

func (c *vcr) Registry() concept.Registry {
	return c.registry
}

func (c *vcr) Configure(config core.ServerConfig) error {
	var err error
	fsPath := path.Join(config.Datadir, "vcr", "credentials.db")

	// load VC concept templates
	if err = c.loadTemplates(); err != nil {
		return err
	}

	// setup DB connection
	if c.store, err = leia.NewStore(fsPath); err != nil {
		return err
	}

	// init indices
	if err = c.initIndices(); err != nil {
		return err
	}

	return nil
}

func (c *vcr) loadTemplates() error {
	list, err := fs.Glob(defaultTemplates, "**/*.json")
	if err != nil {
		return err
	}

	for _, f := range list {
		bytes, err := defaultTemplates.ReadFile(f)
		if err != nil {
			return err
		}
		t, err := concept.ParseTemplate(string(bytes))
		if err != nil {
			return err
		}

		if err = c.registry.Add(t); err != nil {
			return err
		}
	}

	return nil
}

func (c *vcr) initIndices() error {
	for _, templates := range c.registry.ConceptTemplates() {
		for _, t := range templates {
			collection := c.store.Collection(t.VCType())
			for i, index := range t.Indices() {
				var leiaParts []leia.IndexPart

				for _, iParts := range index {
					name := iParts
					jsonPath := t.ToVCPath(iParts)
					leiaParts = append(leiaParts, leia.NewJSONIndexPart(name, jsonPath))
				}

				if err := collection.AddIndex(leia.NewIndex(fmt.Sprintf("index_%d", i), leiaParts...)); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (c *vcr) Name() string {
	return moduleName
}

func (c *vcr) ConfigKey() string {
	return configKey
}

func (c *vcr) Config() interface{} {
	return &c.config
}

func (c *vcr) Search(query concept.Query) ([]did.VerifiableCredential, error) {
	//transform query to leia query, for each template a query is returned
	queries := c.convert(query)

	var VCs = make([]did.VerifiableCredential, 0)
	for vcType, q := range queries {
		docs, err := c.store.Collection(vcType).Find(q)
		if err != nil {
			return nil, err
		}
		for _, doc := range docs {
			vc := did.VerifiableCredential{}
			err = json.Unmarshal(doc, &vc)
			if err != nil {
				return nil, errors.Wrap(err, "unable to parse credential from db")
			}
			VCs = append(VCs, vc)
		}
	}

	return VCs, nil
}

func (c *vcr) Issue(vc did.VerifiableCredential) (*did.VerifiableCredential, error) {
	validator, builder := credential.FindValidatorAndBuilder(vc)
	if validator == nil || builder == nil {
		return nil, errors.New("validation failed: unknown credential type")
	}

	// find issuer
	issuer, err := did.ParseDID(vc.Issuer.String())
	if err != nil {
		return nil, fmt.Errorf("validation failed: failed to parse issuer: %w", err)
	}

	// resolve an assertionMethod key for issuer
	kid, err := c.docResolver.ResolveAssertionKey(*issuer)
	if err != nil {
		return nil, fmt.Errorf("validation failed: invalid issuer: %w", err)
	}

	// set defaults
	builder.Fill(&vc)

	// sign
	if err := c.generateProof(&vc, kid); err != nil {
		return nil, fmt.Errorf("failed to generate credential proof: %w", err)
	}

	// do same validation as network nodes
	if err := validator.Validate(vc); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	payload, err := json.Marshal(vc)
	if err != nil {
		return nil, err
	}

	_, err = c.network.CreateTransaction(createDocumentType(builder.Type()), payload, kid.String(), nil, vc.IssuanceDate)
	if err != nil {
		return nil, fmt.Errorf("failed to publish credential: %w", err)
	}

	logging.Log().Infof("Verifiable Credential created: %s", vc.ID)

	return &vc, nil
}

func (c *vcr) Resolve(ID string) (did.VerifiableCredential, error) {
	panic("implement me")
}

func (c *vcr) Verify(vc did.VerifiableCredential, credentialSubject interface{}, at time.Time) (bool, error) {
	panic("implement me")
}

func createDocumentType(vcType string) string {
	return fmt.Sprintf(vcDocumentType, vcType)
}

// convert returns a map of credential type to query
// credential type is then used as collection input
func (c *vcr) convert(query concept.Query) map[string]leia.Query {
	var qs = make(map[string]leia.Query, 0)

	for _, tq := range query.Parts() {
		var q leia.Query
		for _, clause := range tq.Clauses {
			// todo this should map better
			qp := leia.Range(clause.Key(), clause.Seek(), clause.Match())
			if q == nil {
				q = leia.New(qp)
			} else {
				q = q.And(qp)
			}
		}
		qs[tq.VCType()] = q
	}

	return qs
}

func (c *vcr) generateProof(vc *did.VerifiableCredential, kid did.URI) error {
	payload, err := json.Marshal(vc)
	if err != nil {
		return err
	}

	// create proof
	pr := did.Proof{
		Type:               "JsonWebSignature2020",
		ProofPurpose:       "assertionMethod",
		VerificationMethod: kid,
		Created:            vc.IssuanceDate,
	}
	prJSON, err := json.Marshal(pr)
	if err != nil {
		return err
	}
	tbs := append(hash.SHA256Sum(prJSON).Slice(), hash.SHA256Sum(payload).Slice()...)

	sig, err := c.keystore.SignJWS(tbs, detachedJWSHeaders(), kid.String())
	if err != nil {
		return err
	}

	// remove payload from sig since a detached jws is required.
	dsig := toDetachedSignature(sig)

	vc.Proof = []interface{}{
		JSONWebSignature2020Proof{
			pr,
			dsig,
		},
	}

	return nil
}

// detachedJWSHeaders creates headers for JsonWebSignature2020
// the alg will be based upon the key
// {"alg":"ES256","b64":false,"crit":["b64"]}
func detachedJWSHeaders() map[string]interface{} {
	return map[string]interface{} {
		"b64": false,
		"crit": []string{"b64"},
	}
}

// toDetachedSignature removes the middle part of the signature
func toDetachedSignature(sig string) string {
	splitted := strings.Split(sig, ".")
	return strings.Join([]string{splitted[0], splitted[2]}, ".")
}
