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
 */

package oauth

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/nuts-foundation/nuts-node/didman"

	vc2 "github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/credential"

	"github.com/lestrrat-go/jwx/jwt"
	"github.com/nuts-foundation/go-did/did"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
	"github.com/nuts-foundation/nuts-node/vdr/doc"
	"github.com/nuts-foundation/nuts-node/vdr/types"

	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/auth/services"
)

const errInvalidIssuerFmt = "invalid jwt.issuer: %w"
const errInvalidIssuerKeyFmt = "invalid jwt.issuer key ID: %w"
const errInvalidSubjectFmt = "invalid jwt.subject: %w"
const errInvalidOrganizationVC = "actor has invalid organization VC: %w"
const errInvalidVCClaim = "invalid jwt.vcs: %w"

const vcClaim = "vcs"
const subjectIDClaim = "sid"
const purposeOfUseClaim = "purposeOfUseClaim"
const userIdentityClaim = "usi"

type service struct {
	docResolver     types.DocResolver
	conceptFinder   vcr.ConceptFinder
	vcValidator     vcr.Validator
	keyResolver     types.KeyResolver
	privateKeyStore nutsCrypto.KeyStore
	contractClient  services.ContractClient
	serviceResolver didman.ServiceResolver
}

type validationContext struct {
	rawJwtBearerToken          string
	jwtBearerToken             jwt.Token
	kid                        string
	actorName                  string
	actorCity                  string
	purposeOfUse               string
	credentialIDs              []string
	contractVerificationResult *contract.VPVerificationResult
}

func (c validationContext) subjectID() *string {
	return c.stringVal(subjectIDClaim)
}

func (c validationContext) userIdentity() *string {
	return c.stringVal(userIdentityClaim)
}

func (c validationContext) stringVal(claim string) *string {
	val, ok := c.jwtBearerToken.Get(claim)
	if !ok {
		return nil
	}
	stringVal, ok := val.(string)
	if !ok {
		return nil
	}

	return &stringVal
}

func (c validationContext) verifiableCredentials() ([]vc2.VerifiableCredential, error) {
	vcs := make([]vc2.VerifiableCredential, 0)
	claim, ok := c.jwtBearerToken.Get(vcClaim)

	// If no credentials then OK
	if !ok || claim == nil {
		return vcs, nil
	}

	// vcs should contain a slice of map[string]interface{}
	vcMaps, ok := claim.([]interface{})
	if !ok {
		return vcs, errors.New("field does not contain an array of credentials")
	}

	// convert from map to bytes
	rawVCs := make([][]byte, len(vcMaps))
	for i, vcMap := range vcMaps {
		rawVC, _ := json.Marshal(vcMap)
		rawVCs[i] = rawVC
	}

	// filter on authorization credentials
	vcs = make([]vc2.VerifiableCredential, len(rawVCs))
	for i, rawVC := range rawVCs {
		vc := vc2.VerifiableCredential{}
		if err := json.Unmarshal(rawVC, &vc); err != nil {
			return vcs[:0], fmt.Errorf("cannot unmarshal authorization credential: %w", err)
		}
		vcs[i] = vc
	}
	return vcs, nil
}

// NewOAuthService accepts a vendorID, and several Nuts engines and returns an implementation of services.OAuthClient
func NewOAuthService(store types.Store, conceptFinder vcr.ConceptFinder, vcValidator vcr.Validator, serviceResolver didman.ServiceResolver, privateKeyStore nutsCrypto.KeyStore, contractClient services.ContractClient) services.OAuthClient {
	return &service{
		docResolver:     doc.Resolver{Store: store},
		keyResolver:     doc.KeyResolver{Store: store},
		serviceResolver: serviceResolver,
		contractClient:  contractClient,
		conceptFinder:   conceptFinder,
		vcValidator:     vcValidator,
		privateKeyStore: privateKeyStore,
	}
}

// OauthBearerTokenMaxValidity is the number of seconds that a bearer token is valid
const OauthBearerTokenMaxValidity = 5

// Configure the service
func (s *service) Configure() error {
	return nil
}

// CreateAccessToken extracts the claims out of the request, checks the validity and builds the access token
func (s *service) CreateAccessToken(request services.CreateAccessTokenRequest) (*services.AccessTokenResult, error) {
	context := validationContext{
		rawJwtBearerToken: request.RawJwtBearerToken,
	}

	// extract the JwtBearerToken, validates according to RFC003 §5.2.1.1
	// also check if used algorithms are according to spec (ES*** and PS***)
	// and checks basic validity. Set jwtBearerTokenClaims in validationContext
	if err := s.parseAndValidateJwtBearerToken(&context); err != nil {
		return nil, fmt.Errorf("jwt bearer token validation failed: %w", err)
	}

	// check the maximum validity, according to RFC003 §5.2.1.4
	if context.jwtBearerToken.Expiration().Sub(context.jwtBearerToken.IssuedAt()).Seconds() > OauthBearerTokenMaxValidity {
		return nil, errors.New("JWT validity too long")
	}

	// check the actor against the registry, according to RFC003 §5.2.1.3
	// checks signing certificate and sets vendor, actorName in validationContext
	if err := s.validateIssuer(&context); err != nil {
		return nil, err
	}

	// check if the custodian is registered by this vendor, according to RFC003 §5.2.1.8
	if err := s.validateSubject(&context); err != nil {
		return nil, err
	}

	// Validate the AuthTokenContainer, according to RFC003 §5.2.1.5
	var err error

	usi := context.userIdentity()
	if usi != nil {
		var decoded []byte

		if decoded, err = base64.StdEncoding.DecodeString(*usi); err != nil {
			return nil, fmt.Errorf("failed to decode base64 usi field: %w", err)
		}

		if context.contractVerificationResult, err = s.contractClient.VerifyVP(decoded, nil); err != nil {
			return nil, fmt.Errorf("identity verification failed: %w", err)
		}

		if context.contractVerificationResult.Validity != contract.Valid {
			return nil, errors.New("identity validation failed")
		}

		// checks if the name from the login contract matches with the registered name of the issuer.
		if err := s.validateActor(&context); err != nil {
			return nil, err
		}
	}

	// validate the endpoint in aud, according to RFC003 §5.2.1.9
	if err := s.validatePurposeOfUse(&context); err != nil {
		return nil, err
	}

	// validate the endpoint in aud, according to RFC003 §5.2.1.6
	if err := s.validateAudience(&context); err != nil {
		return nil, err
	}

	// validate the legal base, according to RFC003 §5.2.1.7
	if err = s.validateAuthorizationCredentials(&context); err != nil {
		return nil, err
	}

	accessToken, err := s.buildAccessToken(&context)
	if err != nil {
		return nil, err
	}

	return &services.AccessTokenResult{AccessToken: accessToken}, nil
}

// checks if the name from the login contract matches with the registered name of the issuer.
func (s *service) validateActor(context *validationContext) error {
	if context.contractVerificationResult.ContractAttributes[contract.LegalEntityAttr] != context.actorName || context.contractVerificationResult.ContractAttributes[contract.LegalEntityCityAttr] != context.actorCity {
		return errors.New("legal entity mismatch")
	}
	return nil
}

// check if the purposeOfUser is filled and adds it to the validationContext
func (s *service) validatePurposeOfUse(context *validationContext) error {
	purposeOfUse := context.stringVal(purposeOfUseClaim)
	if purposeOfUse == nil {
		return errors.New("no purposeOfUse given")
	}

	context.purposeOfUse = *purposeOfUse

	return nil
}

// check if the aud service identifier matches the oauth endpoint of the requested service
func (s *service) validateAudience(context *validationContext) error {
	if len(context.jwtBearerToken.Audience()) != 1 {
		return errors.New("aud does not contain a single URI")
	}

	// parsing is already done in a previous check
	subject, _ := did.ParseDID(context.jwtBearerToken.Subject())

	endpointURL, err := s.serviceResolver.GetCompoundServiceEndpoint(*subject, context.purposeOfUse, services.OAuthEndpointType, true)
	if err != nil {
		return err
	}
	if context.jwtBearerToken.Audience()[0] != endpointURL {
		return errors.New("aud does not contain correct endpoint URL")
	}
	return nil
}

// check the actor against the registry, according to RFC003 §5.2.1.3
// - the signing key (KID) must be present as assertionMethod in the issuer's DID.
// - the actor name/city which must match the login contract.
func (s *service) validateIssuer(context *validationContext) error {
	if _, err := did.ParseDID(context.jwtBearerToken.Issuer()); err != nil {
		return fmt.Errorf(errInvalidIssuerFmt, err)
	}

	validationTime := context.jwtBearerToken.IssuedAt()
	if _, err := s.keyResolver.ResolveSigningKey(context.kid, &validationTime); err != nil {
		return fmt.Errorf(errInvalidIssuerKeyFmt, err)
	}

	// organization credentials MUST come from a trusted source
	orgConcept, err := s.conceptFinder.Get(concept.OrganizationConcept, false, context.jwtBearerToken.Issuer())
	if err != nil {
		return fmt.Errorf(errInvalidIssuerFmt, err)
	}

	if context.actorName, err = orgConcept.GetString(concept.OrganizationName); err != nil {
		return fmt.Errorf(errInvalidIssuerFmt, fmt.Errorf(errInvalidOrganizationVC, err))
	}
	if context.actorCity, err = orgConcept.GetString(concept.OrganizationCity); err != nil {
		return fmt.Errorf(errInvalidIssuerFmt, fmt.Errorf(errInvalidOrganizationVC, err))
	}

	return nil
}

// check if the custodian is registered by this vendor, according to RFC003 §5.2.1.8
func (s *service) validateSubject(context *validationContext) error {
	subject, err := did.ParseDID(context.jwtBearerToken.Subject())
	if err != nil {
		return fmt.Errorf(errInvalidSubjectFmt, err)
	}

	iat := context.jwtBearerToken.IssuedAt()
	signingKeyID, err := s.keyResolver.ResolveSigningKeyID(*subject, &iat)
	if err != nil {
		return err
	}
	if !s.privateKeyStore.Exists(signingKeyID) {
		return fmt.Errorf("subject.vendor: %s is not managed by this node", subject)
	}

	return nil
}

// validate the authorization credentials according to §5.2.1.7
func (s *service) validateAuthorizationCredentials(context *validationContext) error {
	// filter on authorization credentials
	vcs, err := context.verifiableCredentials()
	if err != nil {
		return fmt.Errorf(errInvalidVCClaim, err)
	}
	j := 0
	// also add all cred IDs to validationContext
	context.credentialIDs = make([]string, len(vcs))
	for i, vc := range vcs {
		context.credentialIDs[i] = vc.ID.String()
		if vc.IsType(*credential.NutsAuthorizationCredentialTypeURI) {
			vcs[j] = vc
			j++
		}
	}

	vcs = vcs[:j]

	// no auth creds, return
	if len(vcs) == 0 {
		return nil
	}

	iat := context.jwtBearerToken.IssuedAt()
	iss := context.jwtBearerToken.Issuer()
	sub := context.jwtBearerToken.Subject()

	for _, authCred := range vcs {
		// first check if the VC is valid
		if err := s.vcValidator.Validate(authCred, true, &iat); err != nil {
			return fmt.Errorf(errInvalidVCClaim, err)
		}

		//The credential issuer equals the sub field of the JWT.
		if authCred.Issuer.String() != sub {
			return fmt.Errorf("issuer %s of authorization credential with ID: %s does not match jwt.sub: %s", authCred.Issuer.String(), authCred.ID.String(), sub)
		}

		//The credential credentialSubject.id equals the iss field of the JWT.
		authCredSubjects := make([]credential.NutsAuthorizationCredentialSubject, 0)
		if err := authCred.UnmarshalCredentialSubject(&authCredSubjects); err != nil {
			return fmt.Errorf(errInvalidVCClaim, err)
		}
		// should be only 1 credentialSubject, but we do the range just to make sure and to avoid [0] specific code.
		for _, authCredSubject := range authCredSubjects {
			if authCredSubject.ID != iss {
				return fmt.Errorf("credentialSubject.ID %s of authorization credential with ID: %s does not match jwt.iss: %s", authCredSubject.ID, authCred.ID.String(), iss)
			}
		}
	}

	return nil
}

// GetOAuthEndpointURL returns the oauth2 endpoint URL of the custodian for a service
func (s *service) GetOAuthEndpointURL(service string, custodian did.DID) (url.URL, error) {
	endpointURL, err := s.serviceResolver.GetCompoundServiceEndpoint(custodian, service, services.OAuthEndpointType, true)
	if err != nil {
		return url.URL{}, fmt.Errorf("failed to resolve OAuth endpoint URL: %w", err)
	}

	parsedURL, err := url.Parse(endpointURL)
	if err != nil {
		return url.URL{}, fmt.Errorf("failed to parse OAuth endpoint URL: %w", err)
	}

	return *parsedURL, nil
}

// CreateJwtGrant creates a JWT Grant from the given CreateJwtGrantRequest
func (s *service) CreateJwtGrant(request services.CreateJwtGrantRequest) (*services.JwtBearerTokenResult, error) {
	actor, err := did.ParseDID(request.Actor)
	if err != nil {
		return nil, err
	}

	// todo add checks for missing values?
	custodian, err := did.ParseDID(request.Custodian)
	if err != nil {
		return nil, err
	}

	for _, verifiableCredential := range request.Credentials {
		validator, _ := credential.FindValidatorAndBuilder(verifiableCredential)
		if validator == nil {
			if err := credential.Validate(verifiableCredential); err != nil {
				return nil, fmt.Errorf("invalid VerifiableCredential: %w", err)
			}

			continue
		}

		if err := validator.Validate(verifiableCredential); err != nil {
			return nil, fmt.Errorf("invalid VerifiableCredential: %w", err)
		}
	}

	endpointURL, err := s.serviceResolver.GetCompoundServiceEndpoint(*custodian, request.Service, services.OAuthEndpointType, true)
	if err != nil {
		return nil, err
	}

	keyVals := claimsFromRequest(request, endpointURL)

	now := time.Now()
	signingKeyID, err := s.keyResolver.ResolveSigningKeyID(*actor, &now)
	if err != nil {
		return nil, err
	}
	signingString, err := s.privateKeyStore.SignJWT(keyVals, signingKeyID)
	if err != nil {
		return nil, err
	}

	return &services.JwtBearerTokenResult{BearerToken: signingString}, nil
}

var timeFunc = time.Now

// standalone func for easier testing
func claimsFromRequest(request services.CreateJwtGrantRequest, audience string) map[string]interface{} {
	result := map[string]interface{}{}
	result[jwt.AudienceKey] = audience
	result[jwt.ExpirationKey] = timeFunc().Add(OauthBearerTokenMaxValidity * time.Second).Unix()
	result[jwt.IssuedAtKey] = timeFunc().Unix()
	result[jwt.IssuerKey] = request.Actor
	result[jwt.NotBeforeKey] = 0
	result[jwt.SubjectKey] = request.Custodian
	result[purposeOfUseClaim] = request.Service
	if request.IdentityToken != nil {
		result[userIdentityClaim] = *request.IdentityToken
	}
	if request.Subject != nil {
		result[subjectIDClaim] = *request.Subject
	}
	result[vcClaim] = request.Credentials

	return result
}

// parseAndValidateJwtBearerToken validates the jwt signature and returns the containing claims
func (s *service) parseAndValidateJwtBearerToken(context *validationContext) error {
	var kidHdr string
	token, err := nutsCrypto.ParseJWT(context.rawJwtBearerToken, func(kid string) (crypto.PublicKey, error) {
		kidHdr = kid
		return s.keyResolver.ResolveSigningKey(kid, nil)
	})
	if err != nil {
		return err
	}

	// this should be ok since it has already succeeded before
	context.jwtBearerToken = token
	context.kid = kidHdr
	return nil
}

// IntrospectAccessToken fills the fields in NutsAccessToken from the given Jwt Access Token
func (s *service) IntrospectAccessToken(accessToken string) (*services.NutsAccessToken, error) {
	token, err := nutsCrypto.ParseJWT(accessToken, func(kid string) (crypto.PublicKey, error) {
		if !s.privateKeyStore.Exists(kid) {
			return nil, fmt.Errorf("JWT signing key not present on this node (kid=%s)", kid)
		}
		return s.keyResolver.ResolveSigningKey(kid, nil)
	})
	if err != nil {
		return nil, err
	}

	result := &services.NutsAccessToken{}

	if err := result.FromMap(token.PrivateClaims()); err != nil {
		return nil, err
	}

	result.Subject = token.Subject()
	result.Issuer = token.Issuer()
	result.IssuedAt = token.IssuedAt().Unix()
	result.Expiration = token.Expiration().Unix()

	return result, err
}

// todo split this func for easier testing
// BuildAccessToken builds an access token based on the oauth claims and the identity of the user provided by the identityValidationResult
// The token gets signed with the custodians private key and returned as a string.
func (s *service) buildAccessToken(context *validationContext) (string, error) {
	if context.contractVerificationResult != nil {
		if context.contractVerificationResult.Validity != contract.Valid {
			return "", fmt.Errorf("could not build accessToken: %w", errors.New("invalid contract"))
		}
	}

	if context.jwtBearerToken.Subject() == "" {
		return "", fmt.Errorf("could not build accessToken: %w", errors.New("subject is missing"))
	}

	issuer, err := did.ParseDID(context.jwtBearerToken.Subject())
	if err != nil {
		return "", fmt.Errorf("could not build accessToken, subject is invalid (subject=%s): %w", context.jwtBearerToken.Subject(), err)
	}

	issueTime := time.Now()

	at := services.NutsAccessToken{
		SubjectID:  context.subjectID(),
		Service:    context.purposeOfUse,
		Expiration: time.Now().Add(time.Minute * 15).UTC().Unix(), // Expires in 15 minutes
		IssuedAt:   issueTime.UTC().Unix(),
		Issuer:     issuer.String(),
		Subject:    context.jwtBearerToken.Issuer(),
	}

	if context.contractVerificationResult != nil {
		disclosedAttributes := context.contractVerificationResult.DisclosedAttributes

		// based on
		// https://privacybydesign.foundation/attribute-index/en/pbdf.gemeente.personalData.html
		// https://privacybydesign.foundation/attribute-index/en/pbdf.pbdf.email.html
		// and
		// https://openid.net/specs/openid-connect-basic-1_0.html#StandardClaims
		at.FamilyName = toStrPtr(disclosedAttributes["gemeente.personalData.familyname"])
		at.GivenName = toStrPtr(disclosedAttributes["gemeente.personalData.firstnames"])
		at.Prefix = toStrPtr(disclosedAttributes["gemeente.personalData.prefix"])
		at.Name = toStrPtr(disclosedAttributes["gemeente.personalData.fullname"])
		at.Email = toStrPtr(disclosedAttributes["sidn-pbdf.email.email"])
	}

	if len(context.credentialIDs) > 0 {
		at.Credentials = context.credentialIDs
	}

	var keyVals map[string]interface{}

	data, _ := json.Marshal(at)

	if err := json.Unmarshal(data, &keyVals); err != nil {
		return "", err
	}

	// Sign with the private key of the issuer
	signingKeyID, err := s.keyResolver.ResolveSigningKeyID(*issuer, &issueTime)
	if err != nil {
		return "", err
	}
	token, err := s.privateKeyStore.SignJWT(keyVals, signingKeyID)
	if err != nil {
		return token, fmt.Errorf("could not build accessToken: %w", err)
	}

	return token, err
}

func toStrPtr(value string) *string {
	return &value
}
