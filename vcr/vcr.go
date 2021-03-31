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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-leia"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/logging"
	"github.com/nuts-foundation/nuts-node/vcr/trust"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/pkg/errors"
)

// NewVCRInstance creates a new vcr instance with default config and empty concept registry
func NewVCRInstance(signer crypto.JWSSigner, keyResolver vdr.KeyResolver, network network.Transactions) VCR {
	r := &vcr{
		config:      DefaultConfig(),
		registry:    concept.NewRegistry(),
		signer:      signer,
		keyResolver: keyResolver,
		network:     network,
	}

	r.ambassador = NewAmbassador(network, r)

	return r
}

type vcr struct {
	registry    concept.Registry
	config      Config
	store       leia.Store
	signer      crypto.JWSSigner
	keyResolver vdr.KeyResolver
	ambassador  Ambassador
	network     network.Transactions
	trustConfig *trust.Config
}

func (c *vcr) Registry() concept.Reader {
	return c.registry
}

func (c *vcr) Configure(config core.ServerConfig) error {
	var err error
	fsPath := path.Join(config.Datadir, "vcr", "credentials.db")
	tcPath := path.Join(config.Datadir, "vcr", "trusted_issuers.yaml")

	// load VC concept templates
	if err = c.loadTemplates(); err != nil {
		return err
	}

	// load trusted issuers
	c.trustConfig = trust.NewConfig(tcPath)

	if err = c.trustConfig.Load(); err != nil {
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

	// start listening for new credentials
	c.ambassador.Configure()

	return nil
}

func (c *vcr) loadTemplates() error {
	list, err := fs.Glob(defaultTemplates, "**/*.json.template")
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

	// generic indices
	gIndex := c.globalIndex()
	if err := gIndex.AddIndex(leia.NewIndex("index_id", leia.NewJSONIndexPart(concept.IDField, concept.IDField))); err != nil {
		return err
	}
	if err := gIndex.AddIndex(leia.NewIndex("index_issuer", leia.NewJSONIndexPart(concept.IssuerField, concept.IssuerField))); err != nil {
		return err
	}
	rIndex := c.revocationIndex()
	if err := rIndex.AddIndex(leia.NewIndex("index_subject", leia.NewJSONIndexPart(concept.SubjectField, concept.SubjectField))); err != nil {
		return err
	}

	return nil
}

func (c *vcr) globalIndex() leia.Collection {
	return c.store.Collection(leia.GlobalCollection)
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

func (c *vcr) Search(query concept.Query) ([]vc.VerifiableCredential, error) {
	//transform query to leia query, for each template a query is returned
	queries := c.convert(query)

	var VCs = make([]vc.VerifiableCredential, 0)
	for vcType, q := range queries {
		docs, err := c.store.Collection(vcType).Find(q)
		if err != nil {
			return nil, err
		}
		for _, doc := range docs {
			foundCredential := vc.VerifiableCredential{}
			err = json.Unmarshal(doc, &foundCredential)
			if err != nil {
				return nil, errors.Wrap(err, "unable to parse credential from db")
			}

			trusted := c.isTrusted(foundCredential)
			revoked, err := c.isRevoked(*foundCredential.ID)
			if err != nil {
				return nil, errors.Wrap(err, "unable to check revocation state for credential")
			}
			if trusted && !revoked {
				VCs = append(VCs, foundCredential)
			}
		}
	}

	return VCs, nil
}

func (c *vcr) Issue(template vc.VerifiableCredential) (*vc.VerifiableCredential, error) {
	validator, builder := credential.FindValidatorAndBuilder(template)
	if validator == nil || builder == nil {
		return nil, errors.New("unknown credential type")
	}

	if len(template.Type) > 1 {
		return nil, errors.New("can only issue credential with 1 type")
	}

	var credential vc.VerifiableCredential
	credential.Type = template.Type
	credential.CredentialSubject = template.CredentialSubject
	credential.Issuer = template.Issuer
	credential.ExpirationDate = template.ExpirationDate

	// find issuer
	issuer, err := did.ParseDID(credential.Issuer.String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse issuer: %w", err)
	}

	// resolve an assertionMethod key for issuer
	kid, err := c.keyResolver.ResolveAssertionKeyID(*issuer)
	if err != nil {
		return nil, fmt.Errorf("invalid issuer: %w", err)
	}

	// set defaults
	builder.Fill(&credential)

	// sign
	if err := c.generateProof(&credential, kid); err != nil {
		return nil, fmt.Errorf("failed to generate credential proof: %w", err)
	}

	// do same validation as network nodes
	if err := validator.Validate(credential); err != nil {
		return nil, err
	}

	payload, _ := json.Marshal(credential)

	_, err = c.network.CreateTransaction(vcDocumentType, payload, kid.String(), nil, credential.IssuanceDate)
	if err != nil {
		return nil, fmt.Errorf("failed to publish credential: %w", err)
	}

	logging.Log().Infof("Verifiable Credential issued: %s", credential.ID)

	return &credential, nil
}

func (c *vcr) Resolve(ID ssi.URI) (*vc.VerifiableCredential, error) {
	credential, err := c.find(ID)
	if err != nil {
		return nil, err
	}

	revoked, err := c.isRevoked(ID)
	if revoked {
		return &credential, ErrRevoked
	}
	if err != nil {
		return nil, err
	}

	trusted := c.isTrusted(credential)
	if !trusted {
		return &credential, ErrUntrusted
	}

	return &credential, nil
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
	qp := leia.Eq(concept.IDField, ID.String())
	q := leia.New(qp)

	gIndex := c.globalIndex()
	docs, err := gIndex.Find(q)
	if err != nil {
		return credential, err
	}

	if len(docs) != 1 {
		return credential, ErrNotFound
	}

	err = json.Unmarshal(docs[0], &credential)
	if err != nil {
		return credential, errors.Wrap(err, "unable to parse credential from db")
	}

	return credential, nil
}

func (c *vcr) Verify(subject vc.VerifiableCredential, at *time.Time) error {
	// it must have valid content
	validator, _ := credential.FindValidatorAndBuilder(subject)
	if validator == nil {
		return errors.New("unknown credential type")
	}

	if err := validator.Validate(subject); err != nil {
		return err
	}

	// create correct challenge for verification
	payload, err := generateCredentialChallenge(subject)
	if err != nil {
		return fmt.Errorf("cannot generate challenge: %w", err)
	}

	// extract proof, can't fail already done in generateCredentialChallenge
	var proofs = make([]vc.JSONWebSignature2020Proof, 0)
	_ = subject.UnmarshalProofValue(&proofs)
	proof := proofs[0]
	splittedJws := strings.Split(proof.Jws, "..")
	if len(splittedJws) != 2 {
		return errors.New("invalid 'jws' value in proof")
	}
	sig, err := base64.RawURLEncoding.DecodeString(splittedJws[1])
	if err != nil {
		return err
	}

	// check if key is of issuer
	vm := proof.VerificationMethod
	vm.Fragment = ""
	if vm != subject.Issuer {
		return errors.New("verification method is not of issuer")
	}

	// find key
	pk, err := c.keyResolver.ResolveSigningKey(proof.VerificationMethod.String(), at)
	if err != nil {
		return err
	}

	// the proof must be correct
	alg, err := crypto.SignatureAlgorithm(pk)
	if err != nil {
		return err
	}

	verifier, _ := jws.NewVerifier(alg)
	// the jws lib can't do this for us, so we concat hdr with payload for verification
	challenge := fmt.Sprintf("%s.%s", splittedJws[0], base64.RawURLEncoding.EncodeToString(payload))
	if err = verifier.Verify([]byte(challenge), sig, pk); err != nil {
		return err
	}

	// next check timeRestrictions
	if at != nil {
		if subject.IssuanceDate.After(*at) {
			return errors.New("credential not valid yet at given time")
		}
		if subject.ExpirationDate != nil && (*subject.ExpirationDate).Before(*at) {
			return errors.New("credential not valid anymore at given time")
		}
	}

	// check if issuer is trusted
	// todo requires trusted config

	return nil
}

func (c *vcr) Revoke(ID ssi.URI) (*credential.Revocation, error) {
	// first find it using a query on id.
	vc, err := c.find(ID)
	if err != nil {
		// not found and other errors
		return nil, err
	}

	// already revoked, return error
	conflict, err := c.isRevoked(ID)
	if err != nil {
		return nil, err
	}
	if conflict {
		return nil, ErrRevoked
	}

	// find issuer
	issuer, err := did.ParseDID(vc.Issuer.String())
	if err != nil {
		return nil, fmt.Errorf("failed to extract issuer: %w", err)
	}

	// resolve an assertionMethod key for issuer
	kid, err := c.keyResolver.ResolveAssertionKeyID(*issuer)
	if err != nil {
		return nil, fmt.Errorf("invalid issuer: %w", err)
	}

	// set defaults
	r := credential.BuildRevocation(vc)

	// sign
	if err = c.generateRevocationProof(&r, kid); err != nil {
		return nil, fmt.Errorf("failed to generate revocation proof: %w", err)
	}

	// do same validation as network nodes
	if err := credential.ValidateRevocation(r); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	payload, _ := json.Marshal(r)

	_, err = c.network.CreateTransaction(revocationDocumentType, payload, kid.String(), nil, r.Date)
	if err != nil {
		return nil, fmt.Errorf("failed to publish revocation: %w", err)
	}

	logging.Log().Infof("Verifiable Credential revoked: %s", vc.ID)

	return &r, nil
}

func (c *vcr) Trust(credentialType ssi.URI, issuer ssi.URI) error {
	return c.trustConfig.AddTrust(credentialType, issuer)
}

func (c *vcr) Untrust(credentialType ssi.URI, issuer ssi.URI) error {
	return c.trustConfig.RemoveTrust(credentialType, issuer)
}

func (c *vcr) Trusted(credentialType ssi.URI) ([]ssi.URI, error) {
	templates := c.registry.ConceptTemplates()
	found := false

outer:
	for _, vs := range templates {
		for _, v := range vs {
			if v.VCType() == credentialType.String() {
				found = true
				break outer
			}
		}
	}

	if !found {
		return nil, ErrInvalidCredential
	}

	return c.trustConfig.List(credentialType), nil
}

func (c *vcr) Untrusted(credentialType ssi.URI) ([]ssi.URI, error) {
	trustMap := make(map[string]bool)
	untrusted := make([]ssi.URI, 0)
	for _, trusted := range c.trustConfig.List(credentialType) {
		trustMap[trusted.String()] = true
	}

	// match all keys
	query := leia.New(leia.Prefix(concept.IssuerField, ""))

	// use type specific collection
	collection := c.store.Collection(credentialType.String())

	// for each key: add to untrusted if not present in trusted
	err := collection.Iterate(query, func(key []byte, value []byte) error {
		// we iterate over all issuers->reference pairs
		issuer := string(key)
		if _, ok := trustMap[issuer]; !ok {
			u, err := ssi.ParseURI(issuer)
			if err != nil {
				return err
			}
			untrusted = append(untrusted, *u)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, leia.ErrNoIndex) {
			return nil, ErrInvalidCredential
		}
		return nil, err
	}

	return untrusted, nil
}

func (c *vcr) Get(conceptName string, subject string) (concept.Concept, error) {
	q, err := c.Registry().QueryFor(conceptName)
	if err != nil {
		return nil, err
	}

	q.AddClause(concept.Eq(concept.SubjectField, subject))

	vcs, err := c.Search(q)
	if err != nil {
		return nil, err
	}

	if len(vcs) == 0 {
		return nil, ErrNotFound
	}

	// multiple valids, use first one
	return c.Registry().Transform(conceptName, vcs[0])
}

func (c *vcr) verifyRevocation(r credential.Revocation) error {
	// it must have valid content
	if err := credential.ValidateRevocation(r); err != nil {
		return err
	}

	// issuer must be the same as vc issuer
	subject := r.Subject
	subject.Fragment = ""
	if subject != r.Issuer {
		return errors.New("issuer of revocation is not the same as issuer of credential")
	}

	// create correct challenge for verification
	payload := generateRevocationChallenge(r)

	// extract proof, can't fail, already done in generateRevocationChallenge
	splittedJws := strings.Split(r.Proof.Jws, "..")
	if len(splittedJws) != 2 {
		return errors.New("invalid 'jws' value in proof")
	}
	sig, err := base64.RawURLEncoding.DecodeString(splittedJws[1])
	if err != nil {
		return err

	}

	// check if key is of issuer
	vm := r.Proof.VerificationMethod
	vm.Fragment = ""
	if vm != r.Issuer {
		return errors.New("verification method is not of issuer")
	}

	// find key
	pk, err := c.keyResolver.ResolveSigningKey(r.Proof.VerificationMethod.String(), &r.Date)
	if err != nil {
		return err
	}

	// the proof must be correct
	verifier, _ := jws.NewVerifier(jwa.ES256)
	// the jws lib can't do this for us, so we concat hdr with payload for verification
	challenge := fmt.Sprintf("%s.%s", splittedJws[0], base64.RawURLEncoding.EncodeToString(payload))
	if err = verifier.Verify([]byte(challenge), sig, pk); err != nil {
		return err
	}

	return nil
}

func (c *vcr) isRevoked(ID ssi.URI) (bool, error) {
	qp := leia.Eq(concept.SubjectField, ID.String())
	q := leia.New(qp)

	gIndex := c.revocationIndex()
	docs, err := gIndex.Find(q)
	if err != nil {
		return false, err
	}

	if len(docs) >= 1 {
		return true, nil
	}

	return false, nil
}

// convert returns a map of credential type to query
// credential type is then used as collection input
func (c *vcr) convert(query concept.Query) map[string]leia.Query {
	var qs = make(map[string]leia.Query, 0)

	for _, tq := range query.Parts() {
		var q leia.Query
		for _, clause := range tq.Clauses {
			var qp leia.QueryPart

			switch clause.Type() {
			case concept.EqType:
				qp = leia.Eq(clause.Key(), clause.Seek())
			case concept.PrefixType:
				qp = leia.Prefix(clause.Key(), clause.Seek())
			default:
				qp = leia.Range(clause.Key(), clause.Seek(), clause.Match())
			}

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

func (c *vcr) generateProof(credential *vc.VerifiableCredential, kid ssi.URI) error {
	// create proof
	pr := vc.Proof{
		Type:               "JsonWebSignature2020",
		ProofPurpose:       "assertionMethod",
		VerificationMethod: kid,
		Created:            credential.IssuanceDate,
	}
	credential.Proof = []interface{}{pr}

	// create correct signing challenge
	challenge, err := generateCredentialChallenge(*credential)
	if err != nil {
		return err
	}

	sig, err := c.signer.SignJWS(challenge, detachedJWSHeaders(), kid.String())
	if err != nil {
		return err
	}

	// remove payload from sig since a detached jws is required.
	dsig := toDetachedSignature(sig)

	credential.Proof = []interface{}{
		vc.JSONWebSignature2020Proof{
			Proof: pr,
			Jws:   dsig,
		},
	}

	return nil
}

func (c *vcr) generateRevocationProof(r *credential.Revocation, kid ssi.URI) error {
	// create proof
	r.Proof = &vc.JSONWebSignature2020Proof{
		Proof: vc.Proof{
			Type:               "JsonWebSignature2020",
			ProofPurpose:       "assertionMethod",
			VerificationMethod: kid,
			Created:            r.Date,
		},
	}

	// create correct signing challenge
	challenge := generateRevocationChallenge(*r)

	sig, err := c.signer.SignJWS(challenge, detachedJWSHeaders(), kid.String())
	if err != nil {
		return err
	}

	// remove payload from sig since a detached jws is required.
	dsig := toDetachedSignature(sig)

	r.Proof.Jws = dsig

	return nil
}

func generateCredentialChallenge(credential vc.VerifiableCredential) ([]byte, error) {
	var proofs = make([]vc.JSONWebSignature2020Proof, 1)

	if err := credential.UnmarshalProofValue(&proofs); err != nil {
		return nil, err
	}

	if len(proofs) != 1 {
		return nil, errors.New("expected a single Proof for challenge generation")
	}

	// payload
	credential.Proof = nil
	payload, _ := json.Marshal(credential)

	// proof
	proof := proofs[0]
	proof.Jws = ""
	prJSON, _ := json.Marshal(proof)

	tbs := append(hash.SHA256Sum(prJSON).Slice(), hash.SHA256Sum(payload).Slice()...)

	return tbs, nil
}

func generateRevocationChallenge(r credential.Revocation) []byte {
	// without JWS
	proof := r.Proof.Proof

	// payload
	r.Proof = nil
	payload, _ := json.Marshal(r)

	// proof
	prJSON, _ := json.Marshal(proof)

	tbs := append(hash.SHA256Sum(prJSON).Slice(), hash.SHA256Sum(payload).Slice()...)

	return tbs
}

// detachedJWSHeaders creates headers for JsonWebSignature2020
// the alg will be based upon the key
// {"b64":false,"crit":["b64"]}
func detachedJWSHeaders() map[string]interface{} {
	return map[string]interface{}{
		"b64":  false,
		"crit": []string{"b64"},
	}
}

// toDetachedSignature removes the middle part of the signature
func toDetachedSignature(sig string) string {
	splitted := strings.Split(sig, ".")
	return strings.Join([]string{splitted[0], splitted[2]}, "..")
}
