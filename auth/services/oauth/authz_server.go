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
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nuts-foundation/go-did/did"
	vc2 "github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/auth/log"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/nuts-foundation/nuts-node/core"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/didman"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/verifier"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
)

const errInvalidIssuerFmt = "invalid jwt.issuer: %w"
const errInvalidIssuerKeyFmt = "invalid jwt.issuer key ID: %w"
const errInvalidSubjectFmt = "invalid jwt.subject: %w"
const errInvalidVCClaim = "invalid jwt.vcs: %w"

const vcClaim = "vcs"
const purposeOfUseClaimDeprecated = "purposeOfUseClaim"
const purposeOfUseClaim = "purposeOfUse"
const userIdentityClaim = "usi"

// RFC003, §5.3 Access token: Tokens MUST NOT be valid for more than 60 seconds.
const secureAccessTokenLifeSpan = time.Minute

var _ AuthorizationServer = (*authzServer)(nil)

type authzServer struct {
	vcFinder            vcr.Finder
	vcVerifier          verifier.Verifier
	keyResolver         resolver.KeyResolver
	privateKeyStore     nutsCrypto.KeyStore
	contractNotary      services.ContractNotary
	serviceResolver     didman.CompoundServiceResolver
	jsonldManager       jsonld.JSONLD
	secureMode          bool
	clockSkew           time.Duration
	accessTokenLifeSpan time.Duration
}

type validationContext struct {
	rawJwtBearerToken               string
	jwtBearerToken                  jwt.Token
	authorizer                      *did.DID
	kid                             string
	requester                       *did.DID
	requesterOrganizationIdentities []organizationIdentity
	purposeOfUse                    string
	credentialIDs                   []string
	contractVerificationResult      contract.VPVerificationResult
}

type organizationIdentity struct {
	name string
	city string
}

func (c validationContext) userIdentity() (*vc2.VerifiablePresentation, error) {
	claim, ok := c.jwtBearerToken.Get(userIdentityClaim)
	// If no credentials then OK
	if !ok || claim == nil {
		return nil, nil
	}

	// identity should contain a map[string]interface{}, so we just marshal it
	rawVP, _ := json.Marshal(claim)
	vp := vc2.VerifiablePresentation{}
	if err := json.Unmarshal(rawVP, &vp); err != nil {
		return nil, fmt.Errorf("cannot unmarshal identity presentation: %w", err)
	}
	return &vp, nil
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

// NewAuthorizationServer accepts a vendorID, and several Nuts engines and returns an implementation of services.OAuthAuthorizationServer
func NewAuthorizationServer(
	didResolver resolver.DIDResolver, vcFinder vcr.Finder, vcVerifier verifier.Verifier,
	serviceResolver didman.CompoundServiceResolver, privateKeyStore nutsCrypto.KeyStore,
	contractNotary services.ContractNotary, jsonldManager jsonld.JSONLD, accessTokenLifeSpan time.Duration) AuthorizationServer {
	return &authzServer{
		keyResolver:         resolver.DIDKeyResolver{Resolver: didResolver},
		serviceResolver:     serviceResolver,
		contractNotary:      contractNotary,
		jsonldManager:       jsonldManager,
		vcFinder:            vcFinder,
		vcVerifier:          vcVerifier,
		privateKeyStore:     privateKeyStore,
		accessTokenLifeSpan: accessTokenLifeSpan,
	}
}

// BearerTokenMaxValidity is the number of seconds that a bearer token is valid
const BearerTokenMaxValidity = 5

// Configure the service
func (s *authzServer) Configure(clockSkewInMilliseconds int, secureMode bool) error {
	s.clockSkew = time.Duration(clockSkewInMilliseconds) * time.Millisecond
	s.secureMode = secureMode
	if secureMode && s.accessTokenLifeSpan != secureAccessTokenLifeSpan {
		log.Logger().Warnf("Access Token life span changed to %s in strictmode", secureAccessTokenLifeSpan)
		s.accessTokenLifeSpan = secureAccessTokenLifeSpan
	}
	return nil
}

// CreateAccessToken extracts the claims out of the request, checks the validity and builds the access token
func (s *authzServer) CreateAccessToken(ctx context.Context, request services.CreateAccessTokenRequest) (*oauth.TokenResponse, *oauth.ErrorResponse) {
	var oauthError *oauth.ErrorResponse
	var result *oauth.TokenResponse

	validationCtx, err := s.validateAccessTokenRequest(ctx, request.RawJwtBearerToken)
	if err != nil {
		errStr := err.Error()
		oauthError = &oauth.ErrorResponse{Error: "invalid_request", Description: &errStr}
	} else {
		var accessToken string
		var rawToken services.NutsAccessToken
		accessToken, rawToken, err = s.buildAccessToken(ctx, *validationCtx.requester, *validationCtx.authorizer, validationCtx.purposeOfUse, validationCtx.contractVerificationResult, validationCtx.credentialIDs)
		if err == nil {
			expires := int(rawToken.Expiration - rawToken.IssuedAt)
			result = &oauth.TokenResponse{
				AccessToken: accessToken,
				ExpiresIn:   &expires,
			}
		} else {
			oauthError = &oauth.ErrorResponse{Error: "server_error"}
			if !s.secureMode {
				// Only set details when secure mode is disabled
				errStr := err.Error()
				oauthError.Description = &errStr
			}
		}
	}

	if err != nil {
		var requesterDID, authorizerDID string
		if validationCtx.jwtBearerToken != nil {
			requesterDID = validationCtx.jwtBearerToken.Issuer()
			authorizerDID = validationCtx.jwtBearerToken.Subject()
		}
		log.Logger().
			WithField(core.LogFieldRequesterDID, requesterDID).
			WithField(core.LogFieldAuthorizerDID, authorizerDID).
			WithError(err).
			Warn("Unable to create access token, probably due to JWT grant token validation")
	}

	if oauthError == nil {
		return result, nil
	}
	return nil, oauthError
}

func (s *authzServer) validateAccessTokenRequest(ctx context.Context, bearerToken string) (*validationContext, error) {
	validationCtx := &validationContext{rawJwtBearerToken: bearerToken}

	// extract the JwtBearerToken, validates according to RFC003 §5.2.1.1
	// also check if used algorithms are according to spec (ES*** and PS***)
	// and checks basic validity. Set jwtBearerTokenClaims in validationContext
	if err := s.parseAndValidateJwtBearerToken(validationCtx); err != nil {
		return validationCtx, fmt.Errorf("jwt bearer token validation failed: %w", err)
	}

	// check the maximum validity, according to RFC003 §5.2.1.4
	if validationCtx.jwtBearerToken.Expiration().Sub(validationCtx.jwtBearerToken.IssuedAt()).Seconds() > BearerTokenMaxValidity {
		return validationCtx, errors.New("JWT validity too long")
	}

	// check the requester against the registry, according to RFC003 §5.2.1.3
	// checks signing certificate and sets vendor, requesterName in validationContext
	if err := s.validateIssuer(validationCtx); err != nil {
		return validationCtx, err
	}

	// check if the authorizer is registered by this vendor, according to RFC003 §5.2.1.8
	if err := s.validateSubject(ctx, validationCtx); err != nil {
		return validationCtx, err
	}

	// Validate the AuthTokenContainer, according to RFC003 §5.2.1.5
	usi, err := validationCtx.userIdentity()
	if err != nil {
		return validationCtx, err
	}
	if usi != nil {
		if validationCtx.contractVerificationResult, err = s.contractNotary.VerifyVP(*usi, nil); err != nil {
			return validationCtx, fmt.Errorf("identity verification failed: %w", err)
		}

		if validationCtx.contractVerificationResult.Validity() != contract.Valid {
			return validationCtx, fmt.Errorf("identity validation failed: %s", validationCtx.contractVerificationResult.Reason())
		}

		// checks if the name from the login contract matches with the registered name of the issuer.
		if err := s.validateRequester(validationCtx); err != nil {
			return validationCtx, err
		}
	}

	// validate the endpoint in aud, according to RFC003 §5.2.1.9
	if err := s.validatePurposeOfUse(validationCtx); err != nil {
		return validationCtx, err
	}

	// validate the endpoint in aud, according to RFC003 §5.2.1.6
	if err := s.validateAudience(validationCtx); err != nil {
		return validationCtx, err
	}

	// validate the legal base, according to RFC003 §5.2.1.7
	if err = s.validateAuthorizationCredentials(validationCtx); err != nil {
		return validationCtx, err
	}

	return validationCtx, nil
}

// checks if the name from the login contract matches with the registered name of the issuer.
func (s *authzServer) validateRequester(context *validationContext) error {
	actualName := context.contractVerificationResult.ContractAttribute(contract.LegalEntityAttr)
	actualCity := context.contractVerificationResult.ContractAttribute(contract.LegalEntityCityAttr)
	found := false
	for _, identity := range context.requesterOrganizationIdentities {
		if actualName == identity.name && actualCity == identity.city {
			found = true
			break
		}
	}
	if !found {
		log.Logger().Warn("Token request validation failed, requester does not have any credential that match the organization name and city in the contract.")
		return errors.New("legal entity mismatch")
	}
	return nil
}

// check if the purposeOfUse is filled and adds it to the validationContext
func (s *authzServer) validatePurposeOfUse(context *validationContext) error {
	purposeOfUse := context.stringVal(purposeOfUseClaim)
	if purposeOfUse == nil {
		purposeOfUse = context.stringVal(purposeOfUseClaimDeprecated)
		if purposeOfUse == nil {
			return errors.New("no purposeOfUse given")
		}
	}

	context.purposeOfUse = *purposeOfUse

	return nil
}

// check if the aud service identifier matches the oauth endpoint of the requested service
func (s *authzServer) validateAudience(context *validationContext) error {
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

// check the requester against the registry, according to RFC003 §5.2.1.3
// - the signing key (KID) must be present as assertionMethod in the issuer's DID.
// - the requester name/city which must match the login contract.
func (s *authzServer) validateIssuer(vContext *validationContext) error {
	if requester, err := did.ParseDID(vContext.jwtBearerToken.Issuer()); err != nil {
		return fmt.Errorf(errInvalidIssuerFmt, err)
	} else {
		vContext.requester = requester
	}

	validationTime := vContext.jwtBearerToken.IssuedAt()
	if _, err := s.keyResolver.ResolveKeyByID(vContext.kid, &validationTime, resolver.NutsSigningKeyType); err != nil {
		return fmt.Errorf(errInvalidIssuerKeyFmt, err)
	}

	searchTerms := []vcr.SearchTerm{
		{IRIPath: jsonld.CredentialSubjectPath, Value: vContext.jwtBearerToken.Issuer()},
		{IRIPath: jsonld.OrganizationNamePath, Type: vcr.NotNil},
		{IRIPath: jsonld.OrganizationCityPath, Type: vcr.NotNil},
	}
	vcs, err := s.vcFinder.Search(context.Background(), searchTerms, false, &validationTime)
	if err != nil {
		return fmt.Errorf(errInvalidIssuerFmt, err)
	}

	if len(vcs) == 0 {
		return errors.New("requester has no trusted organization VC")
	}

	reader := jsonld.Reader{
		DocumentLoader:           s.jsonldManager.DocumentLoader(),
		AllowUndefinedProperties: true,
	}
	for _, vc := range vcs {
		document, err := reader.Read(vc)
		if err != nil {
			return fmt.Errorf("could not expand credential to JSON-LD: %w", err)
		}
		orgNames := document.ValueAt(jsonld.OrganizationNamePath)
		orgCities := document.ValueAt(jsonld.OrganizationCityPath)
		vContext.requesterOrganizationIdentities = append(vContext.requesterOrganizationIdentities, organizationIdentity{
			// must exist because we queried it that way
			name: orgNames[0].String(),
			city: orgCities[0].String(),
		})
	}

	return nil
}

// check if the authorizer is registered by this vendor, according to RFC003 §5.2.1.8
func (s *authzServer) validateSubject(ctx context.Context, validationCtx *validationContext) error {
	if validationCtx.jwtBearerToken.Subject() == "" {
		return fmt.Errorf(errInvalidSubjectFmt, errors.New("missing"))
	}

	subject, err := did.ParseDID(validationCtx.jwtBearerToken.Subject())
	if err != nil {
		return fmt.Errorf(errInvalidSubjectFmt, err)
	}
	validationCtx.authorizer = subject

	iat := validationCtx.jwtBearerToken.IssuedAt()
	signingKeyID, _, err := s.keyResolver.ResolveKey(*subject, &iat, resolver.NutsSigningKeyType)
	if err != nil {
		return err
	}
	if !s.privateKeyStore.Exists(ctx, signingKeyID.String()) {
		return fmt.Errorf("subject.vendor: %s is not managed by this node", subject)
	}

	return nil
}

// validate the authorization credentials according to §5.2.1.7
func (s *authzServer) validateAuthorizationCredentials(context *validationContext) error {
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
		// first check if the VC is valid and if the signature is correct
		if err := s.vcVerifier.Verify(authCred, true, true, &iat); err != nil {
			return fmt.Errorf(errInvalidVCClaim, err)
		}

		// The credential issuer equals the sub field of the JWT.
		if authCred.Issuer.String() != sub {
			return fmt.Errorf("issuer %s of authorization credential with ID: %s does not match jwt.sub: %s", authCred.Issuer.String(), authCred.ID.String(), sub)
		}

		// The credential credentialSubject.id equals the iss field of the JWT.
		subjectDID, err := authCred.SubjectDID()
		if err != nil {
			return fmt.Errorf(errInvalidVCClaim, err)
		}
		if subjectDID.String() != iss {
			return fmt.Errorf("credentialSubject.ID %s of authorization credential with ID: %s does not match jwt.iss: %s", subjectDID, authCred.ID.String(), iss)
		}
	}

	return nil
}

// parseAndValidateJwtBearerToken validates the jwt signature and returns the containing claims
func (s *authzServer) parseAndValidateJwtBearerToken(context *validationContext) error {
	var kidHdr string
	token, err := nutsCrypto.ParseJWT(context.rawJwtBearerToken, func(kid string) (crypto.PublicKey, error) {
		kidHdr = kid
		return s.keyResolver.ResolveKeyByID(kid, nil, resolver.NutsSigningKeyType)
	}, jwt.WithAcceptableSkew(s.clockSkew))
	if err != nil {
		return err
	}

	// this should be ok since it has already succeeded before
	context.jwtBearerToken = token
	context.kid = kidHdr
	return nil
}

// IntrospectAccessToken fills the fields in NutsAccessToken from the given Jwt Access Token
func (s *authzServer) IntrospectAccessToken(ctx context.Context, accessToken string) (*services.NutsAccessToken, error) {
	token, err := nutsCrypto.ParseJWT(accessToken, func(kid string) (crypto.PublicKey, error) {
		if !s.privateKeyStore.Exists(ctx, kid) {
			return nil, fmt.Errorf("JWT signing key not present on this node (kid=%s)", kid)
		}
		return s.keyResolver.ResolveKeyByID(kid, nil, resolver.NutsSigningKeyType)
	}, jwt.WithAcceptableSkew(s.clockSkew))
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
// The token gets signed with the authorizers private key and returned as a string.
// it also returns the claims in the form of a services.NutsAccessToken
// It performs no additional validation, it just uses the values in the given validationContext
func (s *authzServer) buildAccessToken(ctx context.Context, requester did.DID, authorizer did.DID, purposeOfUse string, userIdentity contract.VPVerificationResult, credentialIDs []string) (string, services.NutsAccessToken, error) {
	accessToken := services.NutsAccessToken{}
	issueTime := time.Now()

	accessToken.Service = purposeOfUse
	accessToken.Expiration = time.Now().Add(s.accessTokenLifeSpan).UTC().Unix()
	accessToken.IssuedAt = issueTime.UTC().Unix()
	accessToken.Issuer = authorizer.String()
	accessToken.Subject = requester.String()

	if userIdentity != nil {
		disclosedAttributeFn := userIdentity.DisclosedAttribute

		// based on https://openid.net/specs/openid-connect-basic-1_0.html#StandardClaims
		accessToken.Initials = toStrPtr(disclosedAttributeFn(services.InitialsTokenClaim))
		accessToken.FamilyName = toStrPtr(disclosedAttributeFn(services.FamilyNameTokenClaim))
		accessToken.Prefix = toStrPtr(disclosedAttributeFn(services.PrefixTokenClaim))
		accessToken.Email = toStrPtr(disclosedAttributeFn(services.EmailTokenClaim))
		accessToken.AssuranceLevel = toStrPtr(disclosedAttributeFn(services.AssuranceLevelClaim))
		accessToken.UserRole = toStrPtr(disclosedAttributeFn(services.UserRoleClaim))
		accessToken.Username = toStrPtr(disclosedAttributeFn(services.UsernameClaim))
	}

	if len(credentialIDs) > 0 {
		accessToken.Credentials = credentialIDs
	}

	var keyVals map[string]interface{}

	data, _ := json.Marshal(accessToken)

	if err := json.Unmarshal(data, &keyVals); err != nil {
		return "", accessToken, err
	}

	// Sign with the private key of the issuer
	signingKeyID, _, err := s.keyResolver.ResolveKey(authorizer, &issueTime, resolver.NutsSigningKeyType)
	if err != nil {
		return "", accessToken, err
	}
	token, err := s.privateKeyStore.SignJWT(ctx, keyVals, nil, signingKeyID.String())
	if err != nil {
		return token, accessToken, fmt.Errorf("could not build accessToken: %w", err)
	}

	return token, accessToken, err
}

func toStrPtr(value string) *string {
	return &value
}
