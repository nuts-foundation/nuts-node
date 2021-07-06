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
	"time"

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

type service struct {
	docResolver     types.DocResolver
	conceptFinder   vcr.ConceptFinder
	keyResolver     types.KeyResolver
	privateKeyStore nutsCrypto.KeyStore
	contractClient  services.ContractClient
}

type validationContext struct {
	rawJwtBearerToken          string
	jwtBearerToken             jwt.Token
	jwtBearerTokenClaims       *services.NutsJwtBearerToken
	actorName                  string
	actorCity                  string
	contractVerificationResult *contract.VPVerificationResult
}

// NewOAuthService accepts a vendorID, and several Nuts engines and returns an implementation of services.OAuthClient
func NewOAuthService(store types.Store, conceptFinder vcr.ConceptFinder, privateKeyStore nutsCrypto.KeyStore, contractClient services.ContractClient) services.OAuthClient {
	return &service{
		docResolver:     doc.Resolver{Store: store},
		keyResolver:     doc.KeyResolver{Store: store},
		contractClient:  contractClient,
		conceptFinder:   conceptFinder,
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
	if context.jwtBearerTokenClaims.UserIdentity != nil {
		var decoded []byte
		if decoded, err = base64.StdEncoding.DecodeString(*context.jwtBearerTokenClaims.UserIdentity); err != nil {
			return nil, fmt.Errorf("failed to decode base64 usi field: %w", err)
		}
		if context.contractVerificationResult, err = s.contractClient.VerifyVP(decoded, nil); err != nil {
			return nil, fmt.Errorf("identity verification failed: %w", err)
		}
	}
	if context.contractVerificationResult.Validity == contract.Invalid {
		return nil, errors.New("identity validation failed")
	}
	// checks if the name from the login contract matches with the registered name of the issuer.
	if err := s.validateActor(&context); err != nil {
		return nil, err
	}

	// validate the endpoint in aud, according to RFC003 §5.2.1.6
	if err := s.validateAudience(&context); err != nil {
		return nil, err
	}

	// validate the legal base, according to RFC003 §5.2.1.7 if sid is present
	if err = s.validateLegalBase(context.jwtBearerTokenClaims); err != nil {
		return nil, err
	}

	accessToken, err := s.buildAccessToken(&context)
	if err != nil {
		return nil, err
	}

	return &services.AccessTokenResult{AccessToken: accessToken}, nil
}

// ErrLegalEntityNotProvided indicates that the legalEntity is missing
var ErrLegalEntityNotProvided = errors.New("legalEntity not provided")

// checks if the name from the login contract matches with the registered name of the issuer.
func (s *service) validateActor(context *validationContext) error {
	if context.contractVerificationResult.ContractAttributes[contract.LegalEntityAttr] != context.actorName || context.contractVerificationResult.ContractAttributes[contract.LegalEntityCityAttr] != context.actorCity {
		return errors.New("legal entity mismatch")
	}
	return nil
}

// check if the aud service identifier matches the oauth endpoint of the requested service
func (s *service) validateAudience(context *validationContext) error {
	if len(context.jwtBearerToken.Audience()) != 1 {
		return errors.New("aud does not contain a single URI")
	}
	audience := context.jwtBearerToken.Audience()[0]
	service := context.jwtBearerTokenClaims.Service
	// parsing is already done in a previous check
	subject, _ := did.ParseDID(context.jwtBearerToken.Subject())
	iat := context.jwtBearerToken.IssuedAt()

	uri, _, err := services.ResolveCompoundServiceURL(s.docResolver, *subject, service, services.OAuthEndpointType, &iat)
	if err != nil {
		return err
	}

	if audience != uri.String() {
		return errors.New("aud does not contain correct endpoint identifier for subject")
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
	if _, err := s.keyResolver.ResolveSigningKey(context.jwtBearerTokenClaims.KeyID, &validationTime); err != nil {
		return fmt.Errorf(errInvalidIssuerKeyFmt, err)
	}

	orgConcept, err := s.conceptFinder.Get(concept.OrganizationConcept, context.jwtBearerToken.Issuer())
	if err != nil {
		return fmt.Errorf(errInvalidIssuerFmt, err)
	}
	ok := false
	if context.actorName, ok = orgConcept.GetValue(concept.OrganizationName).(string); !ok {
		return fmt.Errorf(errInvalidIssuerFmt, errors.New("actor has invalid organization VC"))
	}
	if context.actorCity, ok = orgConcept.GetValue(concept.OrganizationCity).(string); !ok {
		return fmt.Errorf(errInvalidIssuerFmt, errors.New("actor has invalid organization VC"))
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

// validate the legal base, according to RFC003 §5.2.1.7 if sid is present
// use consent store
func (s *service) validateLegalBase(jwtBearerToken *services.NutsJwtBearerToken) error {
	// TODO: Implement this (https://github.com/nuts-foundation/nuts-node/issues/94)
	//if jwtBearerTokenClaims.SubjectID != nil && *jwtBearerTokenClaims.SubjectID != "" {
	//
	// validationTime := time.Unix(jwtBearerTokenClaims.IssuedAt, 0)
	//legalBase, err := s.consentResolver.QueryConsent(context.Background(), &jwtBearerTokenClaims.Issuer, &jwtBearerTokenClaims.Subject, jwtBearerTokenClaims.SubjectID, &validationTime)
	//if err != nil {
	//	return fmt.Errorf("legal base validation failed: %w", err)
	//}
	//if len(legalBase) == 0 {
	//	return errors.New("subject scope requested but no legal base present")
	//}
	//}
	return nil
}

// CreateJwtBearerToken creates a JwtBearerToken from the given CreateJwtGrantRequest
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

	endpointID, _, err := services.ResolveCompoundServiceURL(s.docResolver, *custodian, request.Service, services.OAuthEndpointType, nil)
	if err != nil {
		return nil, err
	}

	keyVals := claimsFromRequest(request, endpointID.String())

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
	token := services.NutsJwtBearerToken{
		UserIdentity: request.IdentityToken,
		SubjectID:    request.Subject,
	}
	result, _ := token.AsMap()
	result[jwt.AudienceKey] = audience
	result[jwt.ExpirationKey] = timeFunc().Add(OauthBearerTokenMaxValidity * time.Second).Unix()
	result[jwt.IssuedAtKey] = timeFunc().Unix()
	result[jwt.IssuerKey] = request.Actor
	result[jwt.NotBeforeKey] = 0
	result[jwt.SubjectKey] = request.Custodian
	result[services.JWTService] = request.Service
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
	context.jwtBearerTokenClaims = &services.NutsJwtBearerToken{KeyID: kidHdr}
	return context.jwtBearerTokenClaims.FromMap(token.PrivateClaims())
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
	var result services.NutsAccessToken
	if err := result.FromMap(token.PrivateClaims()); err != nil {
		return nil, err
	}
	return &result, err
}

// todo split this func for easier testing
// BuildAccessToken builds an access token based on the oauth claims and the identity of the user provided by the identityValidationResult
// The token gets signed with the custodians private key and returned as a string.
func (s *service) buildAccessToken(context *validationContext) (string, error) {
	identityValidationResult := context.contractVerificationResult
	bearerTokenClaims := context.jwtBearerTokenClaims
	bearerToken := context.jwtBearerToken

	if identityValidationResult.Validity != contract.Valid {
		return "", fmt.Errorf("could not build accessToken: %w", errors.New("invalid contract"))
	}

	if bearerToken.Subject() == "" {
		return "", fmt.Errorf("could not build accessToken: %w", errors.New("subject is missing"))
	}

	issuer, err := did.ParseDID(bearerToken.Subject())
	if err != nil {
		return "", fmt.Errorf("could not build accessToken, subject is invalid (subject=%s): %w", bearerToken.Subject(), err)
	}

	disclosedAttributes := identityValidationResult.DisclosedAttributes
	issueTime := time.Now()
	at := services.NutsAccessToken{
		SubjectID: bearerTokenClaims.SubjectID,
		Service:   bearerTokenClaims.Service,
		// based on
		// https://privacybydesign.foundation/attribute-index/en/pbdf.gemeente.personalData.html
		// https://privacybydesign.foundation/attribute-index/en/pbdf.pbdf.email.html
		// and
		// https://openid.net/specs/openid-connect-basic-1_0.html#StandardClaims
		FamilyName: disclosedAttributes["gemeente.personalData.familyname"],
		GivenName:  disclosedAttributes["gemeente.personalData.firstnames"],
		Prefix:     disclosedAttributes["gemeente.personalData.prefix"],
		Name:       disclosedAttributes["gemeente.personalData.fullname"],
		Email:      disclosedAttributes["sidn-pbdf.email.email"],
		Expiration: time.Now().Add(time.Minute * 15).UTC().Unix(), // Expires in 15 minutes
		IssuedAt:   issueTime.UTC().Unix(),
		Issuer:     issuer.String(),
		Subject:    bearerToken.Issuer(),
	}
	var keyVals map[string]interface{}
	inrec, _ := json.Marshal(at)
	if err := json.Unmarshal(inrec, &keyVals); err != nil {
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
