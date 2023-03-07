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
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/auth/api/v1/client"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/jwt"
	"github.com/nuts-foundation/go-did/did"
	vc2 "github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/auth/log"
	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/nuts-foundation/nuts-node/core"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/didman"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/verifier"
	"github.com/nuts-foundation/nuts-node/vdr/didservice"
	"github.com/nuts-foundation/nuts-node/vdr/didstore"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

const errInvalidIssuerFmt = "invalid jwt.issuer: %w"
const errInvalidIssuerKeyFmt = "invalid jwt.issuer key ID: %w"
const errInvalidSubjectFmt = "invalid jwt.subject: %w"
const errInvalidVCClaim = "invalid jwt.vcs: %w"

const vcClaim = "vcs"
const purposeOfUseClaim = "purposeOfUseClaim"
const userIdentityClaim = "usi"

// ErrorResponse models an error returned from an OAuth flow according to RFC6749 (https://tools.ietf.org/html/rfc6749#page-45)
type ErrorResponse struct {
	Description error
	Code        string
}

// Error returns the error detail, if any. If there's no detailed error message, it returns a generic error message.
// This aids hiding internal errors from clients.
func (e ErrorResponse) Error() string {
	if e.Description != nil {
		return e.Description.Error()
	}
	return "failed"
}

type service struct {
	docResolver       types.DocResolver
	vcFinder          vcr.Finder
	vcVerifier        verifier.Verifier
	keyResolver       types.KeyResolver
	privateKeyStore   nutsCrypto.KeyStore
	contractNotary    services.ContractNotary
	serviceResolver   didman.CompoundServiceResolver
	jsonldManager     jsonld.JSONLD
	secureMode        bool
	clockSkew         time.Duration
	httpClientTimeout time.Duration
	httpClientTLS     *tls.Config
}

func (s *service) RequestAccessToken(ctx context.Context, jwtGrantToken string, authorizationServerEndpoint string) (*services.AccessTokenResult, error) {
	if s.secureMode && !strings.HasPrefix(strings.ToLower(authorizationServerEndpoint), "https://") {
		return nil, fmt.Errorf("authorization server endpoint must be HTTPS when in strict mode: %s", authorizationServerEndpoint)
	}
	httpClient := &http.Client{}
	if s.httpClientTLS != nil {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: s.httpClientTLS,
		}
	}
	authClient, err := client.NewHTTPClient("", s.httpClientTimeout, client.WithHTTPClient(httpClient), client.WithRequestEditorFn(core.UserAgentRequestEditor))
	if err != nil {
		return nil, fmt.Errorf("unable to create HTTP client: %w", err)
	}
	authServerEndpoint, err := url.Parse(authorizationServerEndpoint)
	if err != nil {
		return nil, err
	}
	accessTokenResponse, err := authClient.CreateAccessToken(ctx, *authServerEndpoint, jwtGrantToken)
	if err != nil {
		return nil, fmt.Errorf("remote server/nuts node returned error creating access token: %w", err)
	}
	return accessTokenResponse, nil
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

// NewOAuthService accepts a vendorID, and several Nuts engines and returns an implementation of services.Client
func NewOAuthService(
	store didstore.Store, vcFinder vcr.Finder, vcVerifier verifier.Verifier,
	serviceResolver didman.CompoundServiceResolver, privateKeyStore nutsCrypto.KeyStore,
	contractNotary services.ContractNotary, jsonldManager jsonld.JSONLD,
	httpClientTimeout time.Duration, httpClientTLS *tls.Config) Client {
	return &service{
		docResolver:       didservice.Resolver{Store: store},
		keyResolver:       didservice.KeyResolver{Store: store},
		serviceResolver:   serviceResolver,
		contractNotary:    contractNotary,
		jsonldManager:     jsonldManager,
		vcFinder:          vcFinder,
		vcVerifier:        vcVerifier,
		privateKeyStore:   privateKeyStore,
		httpClientTimeout: httpClientTimeout,
		httpClientTLS:     httpClientTLS,
	}
}

// BearerTokenMaxValidity is the number of seconds that a bearer token is valid
const BearerTokenMaxValidity = 5

// Configure the service
func (s *service) Configure(clockSkewInMilliseconds int, secureMode bool) error {
	s.clockSkew = time.Duration(clockSkewInMilliseconds) * time.Millisecond
	s.secureMode = secureMode
	return nil
}

// CreateAccessToken extracts the claims out of the request, checks the validity and builds the access token
func (s *service) CreateAccessToken(ctx context.Context, request services.CreateAccessTokenRequest) (*services.AccessTokenResult, *ErrorResponse) {
	var oauthError *ErrorResponse
	var result *services.AccessTokenResult

	validationCtx, err := s.validateAccessTokenRequest(request.RawJwtBearerToken)
	if err != nil {
		oauthError = &ErrorResponse{Code: "invalid_request", Description: err}
	} else {
		var accessToken string
		var rawToken services.NutsAccessToken
		accessToken, rawToken, err = s.buildAccessToken(ctx, *validationCtx.requester, *validationCtx.authorizer, validationCtx.purposeOfUse, validationCtx.contractVerificationResult, validationCtx.credentialIDs)
		if err == nil {
			result = &services.AccessTokenResult{
				AccessToken: accessToken,
				ExpiresIn:   int(rawToken.Expiration - rawToken.IssuedAt),
			}
		} else {
			oauthError = &ErrorResponse{Code: "server_error"}
			if !s.secureMode {
				// Only set details when secure mode is disabled
				oauthError.Description = err
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

func (s *service) validateAccessTokenRequest(bearerToken string) (*validationContext, error) {
	ctx := &validationContext{rawJwtBearerToken: bearerToken}

	// extract the JwtBearerToken, validates according to RFC003 §5.2.1.1
	// also check if used algorithms are according to spec (ES*** and PS***)
	// and checks basic validity. Set jwtBearerTokenClaims in validationContext
	if err := s.parseAndValidateJwtBearerToken(ctx); err != nil {
		return ctx, fmt.Errorf("jwt bearer token validation failed: %w", err)
	}

	// check the maximum validity, according to RFC003 §5.2.1.4
	if ctx.jwtBearerToken.Expiration().Sub(ctx.jwtBearerToken.IssuedAt()).Seconds() > BearerTokenMaxValidity {
		return ctx, errors.New("JWT validity too long")
	}

	// check the requester against the registry, according to RFC003 §5.2.1.3
	// checks signing certificate and sets vendor, requesterName in validationContext
	if err := s.validateIssuer(ctx); err != nil {
		return ctx, err
	}

	// check if the authorizer is registered by this vendor, according to RFC003 §5.2.1.8
	if err := s.validateSubject(ctx); err != nil {
		return ctx, err
	}

	// Validate the AuthTokenContainer, according to RFC003 §5.2.1.5
	usi, err := ctx.userIdentity()
	if err != nil {
		return ctx, err
	}
	if usi != nil {
		if ctx.contractVerificationResult, err = s.contractNotary.VerifyVP(*usi, nil); err != nil {
			return ctx, fmt.Errorf("identity verification failed: %w", err)
		}

		if ctx.contractVerificationResult.Validity() != contract.Valid {
			return ctx, fmt.Errorf("identity validation failed: %s", ctx.contractVerificationResult.Reason())
		}

		// checks if the name from the login contract matches with the registered name of the issuer.
		if err := s.validateRequester(ctx); err != nil {
			return ctx, err
		}
	}

	// validate the endpoint in aud, according to RFC003 §5.2.1.9
	if err := s.validatePurposeOfUse(ctx); err != nil {
		return ctx, err
	}

	// validate the endpoint in aud, according to RFC003 §5.2.1.6
	if err := s.validateAudience(ctx); err != nil {
		return ctx, err
	}

	// validate the legal base, according to RFC003 §5.2.1.7
	if err = s.validateAuthorizationCredentials(ctx); err != nil {
		return ctx, err
	}

	return ctx, nil
}

// checks if the name from the login contract matches with the registered name of the issuer.
func (s *service) validateRequester(context *validationContext) error {
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

// check the requester against the registry, according to RFC003 §5.2.1.3
// - the signing key (KID) must be present as assertionMethod in the issuer's DID.
// - the requester name/city which must match the login contract.
func (s *service) validateIssuer(vContext *validationContext) error {
	if requester, err := did.ParseDID(vContext.jwtBearerToken.Issuer()); err != nil {
		return fmt.Errorf(errInvalidIssuerFmt, err)
	} else {
		vContext.requester = requester
	}

	validationTime := vContext.jwtBearerToken.IssuedAt()
	if _, err := s.keyResolver.ResolveSigningKey(vContext.kid, &validationTime); err != nil {
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
func (s *service) validateSubject(context *validationContext) error {
	if context.jwtBearerToken.Subject() == "" {
		return fmt.Errorf(errInvalidSubjectFmt, errors.New("missing"))
	}

	subject, err := did.ParseDID(context.jwtBearerToken.Subject())
	if err != nil {
		return fmt.Errorf(errInvalidSubjectFmt, err)
	}
	context.authorizer = subject

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
		// first check if the VC is valid and if the signature is correct
		if err := s.vcVerifier.Verify(authCred, true, true, &iat); err != nil {
			return fmt.Errorf(errInvalidVCClaim, err)
		}

		// The credential issuer equals the sub field of the JWT.
		if authCred.Issuer.String() != sub {
			return fmt.Errorf("issuer %s of authorization credential with ID: %s does not match jwt.sub: %s", authCred.Issuer.String(), authCred.ID.String(), sub)
		}

		// The credential credentialSubject.id equals the iss field of the JWT.
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

// GetOAuthEndpointURL returns the oauth2 endpoint URL of the authorizer for a service
func (s *service) GetOAuthEndpointURL(service string, authorizer did.DID) (url.URL, error) {
	endpointURL, err := s.serviceResolver.GetCompoundServiceEndpoint(authorizer, service, services.OAuthEndpointType, true)
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
func (s *service) CreateJwtGrant(ctx context.Context, request services.CreateJwtGrantRequest) (*services.JwtBearerTokenResult, error) {
	requester, err := did.ParseDID(request.Requester)
	if err != nil {
		return nil, err
	}

	// todo add checks for missing values?
	authorizer, err := did.ParseDID(request.Authorizer)
	if err != nil {
		return nil, err
	}

	for _, verifiableCredential := range request.Credentials {
		validator := credential.FindValidator(verifiableCredential)
		if err := validator.Validate(verifiableCredential); err != nil {
			return nil, fmt.Errorf("invalid VerifiableCredential: %w", err)
		}
	}

	endpointURL, err := s.serviceResolver.GetCompoundServiceEndpoint(*authorizer, request.Service, services.OAuthEndpointType, true)
	if err != nil {
		return nil, fmt.Errorf("could not fetch authorizer's 'oauth' endpoint from compound service: %w", err)
	}

	keyVals := claimsFromRequest(request, endpointURL)

	now := time.Now()
	signingKeyID, err := s.keyResolver.ResolveSigningKeyID(*requester, &now)
	if err != nil {
		return nil, err
	}
	signingString, err := s.privateKeyStore.SignJWT(ctx, keyVals, signingKeyID)
	if err != nil {
		return nil, err
	}

	return &services.JwtBearerTokenResult{BearerToken: signingString, AuthorizationServerEndpoint: endpointURL}, nil
}

var timeFunc = time.Now

// standalone func for easier testing
func claimsFromRequest(request services.CreateJwtGrantRequest, audience string) map[string]interface{} {
	result := map[string]interface{}{}
	result[jwt.AudienceKey] = audience
	result[jwt.ExpirationKey] = timeFunc().Add(BearerTokenMaxValidity * time.Second).Unix()
	result[jwt.IssuedAtKey] = timeFunc().Unix()
	result[jwt.IssuerKey] = request.Requester
	result[jwt.NotBeforeKey] = 0
	result[jwt.SubjectKey] = request.Authorizer
	result[purposeOfUseClaim] = request.Service
	if request.IdentityVP != nil {
		result[userIdentityClaim] = *request.IdentityVP
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
func (s *service) IntrospectAccessToken(accessToken string) (*services.NutsAccessToken, error) {
	token, err := nutsCrypto.ParseJWT(accessToken, func(kid string) (crypto.PublicKey, error) {
		if !s.privateKeyStore.Exists(kid) {
			return nil, fmt.Errorf("JWT signing key not present on this node (kid=%s)", kid)
		}
		return s.keyResolver.ResolveSigningKey(kid, nil)
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
func (s *service) buildAccessToken(ctx context.Context, requester did.DID, authorizer did.DID, purposeOfUse string, userIdentity contract.VPVerificationResult, credentialIDs []string) (string, services.NutsAccessToken, error) {
	accessToken := services.NutsAccessToken{}
	issueTime := time.Now()

	accessToken.Service = purposeOfUse
	accessToken.Expiration = time.Now().Add(time.Minute * 15).UTC().Unix() // Expires in 15 minutes
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
		accessToken.EidasIAL = toStrPtr(disclosedAttributeFn(services.EidasIALClaim))
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
	signingKeyID, err := s.keyResolver.ResolveSigningKeyID(authorizer, &issueTime)
	if err != nil {
		return "", accessToken, err
	}
	token, err := s.privateKeyStore.SignJWT(ctx, keyVals, signingKeyID)
	if err != nil {
		return token, accessToken, fmt.Errorf("could not build accessToken: %w", err)
	}

	return token, accessToken, err
}

func toStrPtr(value string) *string {
	return &value
}
