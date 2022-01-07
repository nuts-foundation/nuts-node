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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/nuts-foundation/nuts-node/vcr/assets"
	"github.com/nuts-foundation/nuts-node/vcr/presentation"
	proofs "github.com/nuts-foundation/nuts-node/vcr/proof"
	"io/fs"
	"os"
	"path"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"github.com/nuts-foundation/nuts-node/vcr/trust"
	doc2 "github.com/nuts-foundation/nuts-node/vdr/doc"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

const (
	maxSkew = 5 * time.Second
)

var (
	timeFunc = time.Now

	// noSync is used to disable bbolt syncing on go-leia during tests
	noSync bool
)

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
	registry        concept.Registry
	config          Config
	keyStore        crypto.KeyStore
	docResolver     vdr.DocResolver
	keyResolver     vdr.KeyResolver
	ambassador      Ambassador
	network         network.Transactions
	trustConfig     *trust.Config
	credentialStore CredentialStoreBackend
}

func (c *vcr) Configure(config core.ServerConfig) error {
	var err error

	//  store config parameters for use in Start()
	c.config = Config{strictMode: config.Strictmode, datadir: config.Datadir}

	tcPath := path.Join(config.Datadir, "vcr", "trusted_issuers.yaml")

	// load VC concept templates
	if err = c.loadTemplates(); err != nil {
		return err
	}

	// load trusted issuers
	c.trustConfig = trust.NewConfig(tcPath)

	return c.trustConfig.Load()
}

func (c *vcr) credentialsDBPath() string {
	return path.Join(c.config.datadir, "vcr", "credentials.db")
}

func (c *vcr) Migrate() error {
	// the migration to go-leia V2 needs a fresh DB
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

	if c.credentialStore, err = NewLeiaStore(c.registry.Concepts(), c.credentialsDBPath(), noSync); err != nil {
		return err
	}

	// start listening for new credentials
	c.ambassador.Configure()

	return nil
}

func (c *vcr) Shutdown() error {
	return c.credentialStore.Close()
}

func (c *vcr) loadTemplates() error {
	list, err := fs.Glob(assets.Assets, "**/*.config.yaml")
	if err != nil {
		return err
	}

	for _, f := range list {
		bytes, err := assets.Assets.ReadFile(f)
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

func (c *vcr) Name() string {
	return moduleName
}

func (c *vcr) Config() interface{} {
	return &c.config
}

func (c *vcr) Issue(template vc.VerifiableCredential) (*vc.VerifiableCredential, error) {
	if len(template.Type) != 1 {
		return nil, errors.New("can only issue credential with 1 type")
	}
	validator, builder := credential.FindValidatorAndBuilder(template)

	templateType := template.Type[0]
	templateTypeString := templateType.String()
	conceptConfig := c.registry.FindByType(templateTypeString)
	if conceptConfig == nil {
		if c.config.strictMode {
			return nil, errors.New("cannot issue non-predefined credential types in strict mode")
		}
		// non-strictmode, add the credential type to the registry
		conceptConfig = &concept.Config{
			Concept:        templateTypeString,
			CredentialType: templateTypeString,
		}
		c.registry.Add(*conceptConfig)
	}

	verifiableCredential := vc.VerifiableCredential{
		Type:              template.Type,
		CredentialSubject: template.CredentialSubject,
		Issuer:            template.Issuer,
		ExpirationDate:    template.ExpirationDate,
	}

	// find issuer
	issuer, err := did.ParseDID(verifiableCredential.Issuer.String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse issuer: %w", err)
	}
	// find did document/metadata for originating TXs
	doc, meta, err := c.docResolver.Resolve(*issuer, nil)
	if err != nil {
		return nil, err
	}

	// resolve an assertionMethod key for issuer
	kid, err := doc2.ExtractAssertionKeyID(*doc)
	if err != nil {
		return nil, fmt.Errorf("invalid issuer: %w", err)
	}

	key, err := c.keyStore.Resolve(kid.String())
	if err != nil {
		return nil, fmt.Errorf("could not resolve kid: %w", err)
	}

	// set defaults
	builder.Fill(&verifiableCredential)
	// set the json-ld context for the signature.
	verifiableCredential.Context = append(verifiableCredential.Context, *credential.Jws2020ContextURI)

	// sign
	if err := c.generateProof(&verifiableCredential, kid, key); err != nil {
		return nil, fmt.Errorf("failed to generate credential proof: %w", err)
	}

	// do same validation as network nodes
	if err := validator.Validate(verifiableCredential); err != nil {
		return nil, err
	}

	// create participants list
	participants := make([]did.DID, 0)
	if !conceptConfig.Public {
		var (
			base                []credential.BaseCredentialSubject
			credentialSubjectID *did.DID
		)
		err = verifiableCredential.UnmarshalCredentialSubject(&base)
		if err == nil {
			if len(base) != 1 {
				return nil, errors.New("could not unmarshal credentialSubject")
			}
			credentialSubjectID, err = did.ParseDID(base[0].ID) // earlier validation made sure length == 1 and ID is present
		}
		if err != nil {
			return nil, fmt.Errorf("failed to determine credentialSubject.ID: %w", err)
		}

		// participants are the issuer and the credentialSubject.id
		participants = append(participants, *issuer)
		participants = append(participants, *credentialSubjectID)
	}

	payload, _ := json.Marshal(verifiableCredential)
	tx := network.TransactionTemplate(vcDocumentType, payload, key).
		WithTimestamp(verifiableCredential.IssuanceDate).
		WithAdditionalPrevs(meta.SourceTransactions).
		WithPrivate(participants)
	_, err = c.network.CreateTransaction(tx)
	if err != nil {
		return nil, fmt.Errorf("failed to publish credential: %w", err)
	}
	log.Logger().Infof("Verifiable Credential published (id=%s,type=%s)", verifiableCredential.ID, templateType)

	if !c.trustConfig.IsTrusted(templateType, issuer.URI()) {
		log.Logger().Debugf("Issuer not yet trusted, adding trust (did=%s,type=%s)", *issuer, templateType)
		if err := c.Trust(templateType, issuer.URI()); err != nil {
			return &verifiableCredential, fmt.Errorf("failed to trust issuer after issuing VC (did=%s,type=%s): %w", *issuer, templateType, err)
		}
	} else {
		log.Logger().Debugf("Issuer already trusted (did=%s,type=%s)", *issuer, templateType)
	}

	return &verifiableCredential, nil
}

func (c *vcr) ResolveCredential(ID ssi.URI, resolveTime *time.Time) (*vc.VerifiableCredential, error) {
	credential, err := c.credentialStore.GetCredential(ID)
	if err != nil {
		return nil, err
	}

	// we don't have to check the signature, it's coming from our own store.
	if err = c.ValidateCredential(credential, false, false, resolveTime); err != nil {
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

func (c *vcr) StoreCredential(credential vc.VerifiableCredential, validAt *time.Time) error {
	// verify first
	if err := c.Verify(credential, validAt); err != nil {
		return err
	}

	return c.credentialStore.WriteCredential(credential)
}

func (c *vcr) StoreRevocation(r credential.Revocation) error {
	// verify first
	if err := c.verifyRevocation(r); err != nil {
		return err
	}

	return c.credentialStore.WriteRevocation(r)
}

func (c *vcr) ValidateCredential(credential vc.VerifiableCredential, allowUntrusted bool, checkSignature bool, validAt *time.Time) error {
	revoked, err := c.credentialStore.IsCredentialRevoked(*credential.ID)
	if revoked {
		return ErrRevoked
	}
	if err != nil {
		return err
	}

	if !allowUntrusted {
		trusted := c.isTrusted(credential)
		if !trusted {
			return ErrUntrusted
		}
	}

	if checkSignature {
		return c.Verify(credential, validAt)
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

	if credential.IssuanceDate.After(at.Add(maxSkew)) {
		return ErrInvalidPeriod
	}

	if credential.ExpirationDate != nil && credential.ExpirationDate.Add(maxSkew).Before(at) {
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
	challenge := fmt.Sprintf("%s.%s", splittedJws[0], payload)
	if err = verifier.Verify([]byte(challenge), sig, pk); err != nil {
		return err
	}

	// next check trusted/period and revocation
	return c.validate(subject, at)
}

func (c *vcr) Revoke(ID ssi.URI) (*credential.Revocation, error) {
	// first find it using a query on id.
	target, err := c.credentialStore.GetCredential(ID)
	if err != nil {
		// not found and other errors
		return nil, err
	}

	// already revoked, return error
	conflict, err := c.credentialStore.IsCredentialRevoked(ID)
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
	// find did document/metadata for originating TXs
	doc, meta, err := c.docResolver.Resolve(*issuer, nil)
	if err != nil {
		return nil, err
	}

	// resolve an assertionMethod key for issuer
	kid, err := doc2.ExtractAssertionKeyID(*doc)
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

	tx := network.TransactionTemplate(revocationDocumentType, payload, key).
		WithTimestamp(r.Date).
		WithAdditionalPrevs(meta.SourceTransactions)
	_, err = c.network.CreateTransaction(tx)
	if err != nil {
		return nil, fmt.Errorf("failed to publish revocation: %w", err)
	}

	log.Logger().Infof("Verifiable Credential revoked (id=%s)", target.ID)

	return &r, nil
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
	concepts := c.registry.Concepts()

	for _, concept := range concepts {
		if concept.CredentialType == credentialType.String() {
			return c.trustConfig.List(credentialType), nil
		}
	}

	log.Logger().Warnf("No credential with type %s configured", credentialType.String())

	return nil, ErrInvalidCredential
}

func (c *vcr) Untrusted(credentialType ssi.URI) ([]ssi.URI, error) {
	trustMap := make(map[string]bool)
	untrusted := make([]ssi.URI, 0)
	for _, trusted := range c.trustConfig.List(credentialType) {
		trustMap[trusted.String()] = true
	}

	issuers, err := c.credentialStore.CredentialIssuers(credentialType)
	if err != nil {
		return nil, err
	}

	for _, issuer := range issuers {
		if _, ok := trustMap[issuer.String()]; !ok {
			untrusted = append(untrusted, issuer)
		}
	}

	return untrusted, nil
}

func (c *vcr) Get(conceptName string, allowUntrusted bool, subject string) (concept.Concept, error) {
	q, err := c.registry.QueryFor(conceptName)
	if err != nil {
		return nil, err
	}

	q.AddClause(concept.Eq(concept.SubjectField, subject))

	ctx, cancel := context.WithTimeout(context.Background(), maxFindExecutionTime)
	defer cancel()
	// finding a VC that backs a concept always occurs in the present, so no resolveTime needs to be passed.
	unvalidatedVCs, err := c.credentialStore.SearchCredential(ctx, q)
	if err != nil {
		return nil, err
	}

	vcs := []vc.VerifiableCredential{}
	for _, foundCredential := range unvalidatedVCs {
		if err = c.ValidateCredential(foundCredential, allowUntrusted, false, nil); err == nil {
			vcs = append(vcs, foundCredential)
		}
	}

	if len(vcs) == 0 {
		return nil, ErrNotFound
	}

	// multiple valids, use first one
	return c.registry.Transform(conceptName, vcs[0])
}

func (c *vcr) Search(ctx context.Context, conceptName string, allowUntrusted bool, queryParams map[string]string) ([]concept.Concept, error) {
	query, err := c.registry.QueryFor(conceptName)
	if err != nil {
		return nil, err
	}

	for key, value := range queryParams {
		query.AddClause(concept.Prefix(key, value))
	}

	unvalidatedVCs, err := c.credentialStore.SearchCredential(ctx, query)
	if err != nil {
		return nil, err
	}
	results := []vc.VerifiableCredential{}
	for _, foundCredential := range unvalidatedVCs {
		if err = c.ValidateCredential(foundCredential, allowUntrusted, allowUntrusted, nil); err == nil {
			results = append(results, foundCredential)
		}
	}

	var transformedResults = make([]concept.Concept, len(results))
	for i, result := range results {
		transformedResult, err := c.registry.Transform(conceptName, result)
		if err != nil {
			return nil, err
		}
		transformedResults[i] = transformedResult
	}
	return transformedResults, nil
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
	challenge := fmt.Sprintf("%s.%s", splittedJws[0], payload)
	if err = verifier.Verify([]byte(challenge), sig, pk); err != nil {
		return err
	}

	return nil
}

// VerifyPresentation checks the signature and validity of the presentation.
func (c *vcr) VerifyPresentation(verifiablePresentation presentation.VerifiablePresentation) error {
	// TODO: Add test to check for context contains credential and type is "VerifiablePresentation"
	rawProof := verifiablePresentation.Proof

	ldProof := proofs.LDProof{}
	proofBytes, err := json.Marshal(rawProof)
	if err != nil {
		return fmt.Errorf("unable to marshal rawProof into bytes")
	}
	if err := json.Unmarshal(proofBytes, &ldProof); err != nil {
		return fmt.Errorf("unable to marshal raw proof into LDProof struct")
	}

	if ldProof.Type != ssi.JsonWebSignature2020 {
		return fmt.Errorf("unknown proof type: %s", ldProof.Type)
	}

	return nil
}

func (c *vcr) BuildVerifiablePresentation(credentials []vc.VerifiableCredential, proofOptions proofs.ProofOptions, holderID did.DID, validateVC bool) (*presentation.VerifiablePresentation, error) {
	kid, err := c.keyResolver.ResolveAssertionKeyID(holderID)
	key, err := c.keyStore.Resolve(kid.String())
	if err != nil {
		return nil, fmt.Errorf("could not resolve kid: %w", err)
	}

	if validateVC {
		for _, cred := range credentials {
			if err := c.ValidateCredential(cred, false, true, nil); err != nil {
				return nil, core.InvalidInputError("invalid credential with id: %s, error: %w", cred.ID, err)
			}
		}
	}

	signerInput := &presentation.VerifiablePresentation{
		Context:              []string{"https://www.w3.org/2018/credentials/v1"},
		Type:                 []string{"VerifiablePresentation"},
		VerifiableCredential: &credentials,
	}

	// TODO: choose between different proof types (JWT or LD-Proof)
	ldProofSigner, err := proofs.NewLDProofBuilder(signerInput, proofOptions)
	if err != nil {
		return nil, fmt.Errorf("unable create json-ld proof builder: %w", err)
	}
	signerOutput, err := ldProofSigner.Sign(key)
	if err != nil {
		return nil, fmt.Errorf("unable to sign ldProof: %w", err)
	}

	signedVP := &presentation.VerifiablePresentation{}
	b, _ := json.Marshal(signerOutput)
	_ = json.Unmarshal(b, signedVP)

	return signedVP, nil
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

	sums := append(hash.SHA256Sum(prJSON).Slice(), hash.SHA256Sum(payload).Slice()...)
	tbs := base64.RawURLEncoding.EncodeToString(sums)

	return []byte(tbs), nil
}

func generateRevocationChallenge(r credential.Revocation) []byte {
	// without JWS
	proof := r.Proof.Proof

	// payload
	r.Proof = nil
	payload, _ := json.Marshal(r)

	// proof
	prJSON, _ := json.Marshal(proof)

	sums := append(hash.SHA256Sum(prJSON).Slice(), hash.SHA256Sum(payload).Slice()...)
	tbs := base64.RawURLEncoding.EncodeToString(sums)

	return []byte(tbs)
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
