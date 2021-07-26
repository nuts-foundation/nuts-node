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

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
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
	"gopkg.in/yaml.v2"
)

var timeFunc = time.Now

// NewVCRInstance creates a new vcr instance with default config and empty concept registry
func NewVCRInstance(keyStore crypto.KeyStore, docResolver vdr.DocResolver, keyResolver vdr.KeyResolver, network network.Transactions) VCR {
	r := &vcr{
		config:      DefaultConfig(),
		docResolver: docResolver,
		keyStore:    keyStore,
		keyResolver: keyResolver,
		network:     network,
		registry:    concept.NewRegistry(),
	}

	r.ambassador = NewAmbassador(network, r)

	return r
}

type vcr struct {
	registry    concept.Registry
	config      Config
	store       leia.Store
	keyStore    crypto.KeyStore
	docResolver vdr.DocResolver
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
	list, err := fs.Glob(defaultTemplates, "**/*.config.yaml")
	if err != nil {
		return err
	}

	for _, f := range list {
		bytes, err := defaultTemplates.ReadFile(f)
		if err != nil {
			return err
		}
		config := concept.Config{}
		err = yaml.Unmarshal(bytes, &config)
		if err != nil {
			return err
		}

		if err = c.registry.Add(config); err != nil {
			return err
		}
	}

	return nil
}

func (c *vcr) initIndices() error {
	for _, config := range c.registry.Concepts() {
		collection := c.store.Collection(config.CredentialType)
		for _, index := range config.Indices {
			var leiaParts []leia.FieldIndexer

			for _, iParts := range index.Parts {
				options := make([]leia.IndexOption, 0)
				if iParts.Alias != nil {
					options = append(options, leia.AliasOption(*iParts.Alias))
				}
				if iParts.Tokenizer != nil {
					switch *iParts.Tokenizer {
					case "whitespace":
						options = append(options, leia.TokenizerOption(leia.WhiteSpaceTokenizer))
					default:
						return fmt.Errorf("unknown tokenizer %s for %s", *iParts.Tokenizer, config.CredentialType)
					}
				}
				if iParts.Transformer != nil {
					switch *iParts.Transformer {
					case "cologne":
						options = append(options, leia.TransformerOption(concept.CologneTransformer))
					case "lowerCase":
						options = append(options, leia.TransformerOption(leia.ToLower))
					default:
						return fmt.Errorf("unknown transformer %s for %s", *iParts.Transformer, config.CredentialType)
					}
				}

				leiaParts = append(leiaParts, leia.NewFieldIndexer(iParts.JSONPath, options...))
			}

			leiaIndex := leia.NewIndex(index.Name, leiaParts...)
			logging.Log().Debugf("Adding index %s to %s using: %v", index.Name, config.CredentialType, leiaIndex)

			if err := collection.AddIndex(leiaIndex); err != nil {
				return err
			}
		}
	}

	// revocation indices
	rIndex := c.revocationIndex()
	return rIndex.AddIndex(leia.NewIndex("index_subject", leia.NewFieldIndexer(concept.SubjectField)))
}

func (c *vcr) Name() string {
	return moduleName
}

func (c *vcr) Config() interface{} {
	return &c.config
}

func (c *vcr) Search(query concept.Query, resolveTime *time.Time) ([]vc.VerifiableCredential, error) {
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
			err = json.Unmarshal(doc.Bytes(), &foundCredential)
			if err != nil {
				return nil, errors.Wrap(err, "unable to parse credential from db")
			}

			if err = c.validateForUse(foundCredential, resolveTime); err == nil {
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

	if len(template.Type) != 1 {
		return nil, errors.New("can only issue credential with 1 type")
	}
	templateType := template.Type[0]

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

	key, err := c.keyStore.Resolve(kid.String())
	if err != nil {
		return nil, fmt.Errorf("could not resolve kid: %w", err)
	}

	// set defaults
	builder.Fill(&credential)

	// sign
	if err := c.generateProof(&credential, kid, key); err != nil {
		return nil, fmt.Errorf("failed to generate credential proof: %w", err)
	}

	// do same validation as network nodes
	if err := validator.Validate(credential); err != nil {
		return nil, err
	}

	payload, _ := json.Marshal(credential)

	_, err = c.network.CreateTransaction(vcDocumentType, payload, key, false, credential.IssuanceDate, []hash.SHA256Hash{})
	if err != nil {
		return nil, fmt.Errorf("failed to publish credential: %w", err)
	}
	logging.Log().Infof("Verifiable Credential issued (id=%s,type=%s)", credential.ID, templateType)

	if !c.trustConfig.IsTrusted(templateType, issuer.URI()) {
		logging.Log().Debugf("Issuer not yet trusted, adding trust (did=%s,type=%s)", *issuer, templateType)
		if err := c.Trust(templateType, issuer.URI()); err != nil {
			return &credential, fmt.Errorf("failed to trust issuer after issuing VC (did=%s,type=%s): %w", *issuer, templateType, err)
		}
	} else {
		logging.Log().Debugf("Issuer already trusted (did=%s,type=%s)", *issuer, templateType)
	}

	return &credential, nil
}

func (c *vcr) Resolve(ID ssi.URI, resolveTime *time.Time) (*vc.VerifiableCredential, error) {
	credential, err := c.find(ID)
	if err != nil {
		return nil, err
	}

	if err = c.validateForUse(credential, resolveTime); err != nil {
		switch err {
		case ErrRevoked:
			return &credential, ErrRevoked
		case ErrUntrusted:
			return &credential, ErrUntrusted
		default:
			return nil, err
		}
	}
	return &credential, nil
}

func (c *vcr) validateForUse(credential vc.VerifiableCredential, validAt *time.Time) error {
	revoked, err := c.isRevoked(*credential.ID)
	if revoked {
		return ErrRevoked
	}
	if err != nil {
		return err
	}

	trusted := c.isTrusted(credential)
	if !trusted {
		return ErrUntrusted
	}

	return c.validate(credential, validAt)
}

func (c *vcr) validate(credential vc.VerifiableCredential, validAt *time.Time) error {
	at := timeFunc()
	if validAt != nil {
		at = *validAt
	}
	issuer, err := did.ParseDIDURL(credential.Issuer.String())
	if err != nil {
		return err
	}

	if credential.IssuanceDate.After(at) {
		return ErrInvalidPeriod
	}
	if credential.ExpirationDate != nil && credential.ExpirationDate.Before(at) {
		return ErrInvalidPeriod
	}

	_, _, err = c.docResolver.Resolve(*issuer, &vdr.ResolveMetadata{ResolveTime: &at})
	return err
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

	for _, t := range c.registry.Concepts() {
		docs, err := c.store.Collection(t.CredentialType).Find(q)
		if err != nil {
			return credential, err
		}
		if len(docs) > 0 {
			// there can be only one
			err = json.Unmarshal(docs[0].Bytes(), &credential)
			if err != nil {
				return credential, errors.Wrap(err, "unable to parse credential from db")
			}

			return credential, nil
		}
	}

	return credential, ErrNotFound
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

	// next check trusted/period and revocation
	return c.validate(subject, at)
}

func (c *vcr) Revoke(ID ssi.URI) (*credential.Revocation, error) {
	// first find it using a query on id.
	target, err := c.find(ID)
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
	issuer, err := did.ParseDID(target.Issuer.String())
	if err != nil {
		return nil, fmt.Errorf("failed to extract issuer: %w", err)
	}

	// resolve an assertionMethod key for issuer
	kid, err := c.keyResolver.ResolveAssertionKeyID(*issuer)
	if err != nil {
		return nil, fmt.Errorf("invalid issuer: %w", err)
	}

	key, err := c.keyStore.Resolve(kid.String())
	if err != nil {
		return nil, fmt.Errorf("could not resolve kid: %w", err)
	}

	// set defaults
	r := credential.BuildRevocation(target)

	// sign
	if err = c.generateRevocationProof(&r, kid, key); err != nil {
		return nil, fmt.Errorf("failed to generate revocation proof: %w", err)
	}

	// do same validation as network nodes
	if err := credential.ValidateRevocation(r); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	payload, _ := json.Marshal(r)

	_, err = c.network.CreateTransaction(revocationDocumentType, payload, key, false, r.Date, []hash.SHA256Hash{})
	if err != nil {
		return nil, fmt.Errorf("failed to publish revocation: %w", err)
	}

	logging.Log().Infof("Verifiable Credential revoked (id=%s)", target.ID)

	return &r, nil
}

func (c *vcr) Trust(credentialType ssi.URI, issuer ssi.URI) error {
	err := c.trustConfig.AddTrust(credentialType, issuer)
	if err != nil {
		logging.Log().Infof("Added trust for Verifiable Credential issuer (type=%s, issuer=%s)", credentialType, issuer)
	}
	return err
}

func (c *vcr) Untrust(credentialType ssi.URI, issuer ssi.URI) error {
	err := c.trustConfig.RemoveTrust(credentialType, issuer)
	if err != nil {
		logging.Log().Infof("Untrusted for Verifiable Credential issuer (type=%s, issuer=%s)", credentialType, issuer)
	}
	return err
}

func (c *vcr) Trusted(credentialType ssi.URI) ([]ssi.URI, error) {
	concepts := c.registry.Concepts()

	for _, concept := range concepts {
		if concept.CredentialType == credentialType.String() {
			return c.trustConfig.List(credentialType), nil
		}
	}

	logging.Log().Warnf("No credential with type %s configured", credentialType.String())

	return nil, ErrInvalidCredential
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
	err := collection.IndexIterate(query, func(key []byte, value []byte) error {
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
			logging.Log().Warnf("No index with field 'issuer' found for %s", credentialType.String())

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

	// finding a VC that backs a concept always occurs in the present, so no resolveTime needs to be passed.
	vcs, err := c.Search(q, nil)
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
		qs[tq.CredentialType()] = q
	}

	return qs
}

func (c *vcr) generateProof(credential *vc.VerifiableCredential, kid ssi.URI, key crypto.Key) error {
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

	sig, err := crypto.SignJWS(challenge, detachedJWSHeaders(), key.Signer())
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

func (c *vcr) generateRevocationProof(r *credential.Revocation, kid ssi.URI, key crypto.Key) error {
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

	sig, err := crypto.SignJWS(challenge, detachedJWSHeaders(), key.Signer())
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
