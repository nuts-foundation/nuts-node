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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/didman"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	vcrTypes "github.com/nuts-foundation/nuts-node/vcr/types"
	verifier2 "github.com/nuts-foundation/nuts-node/vcr/verifier"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

var requesterSigningKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
var authorizerSigningKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

var requesterDID = vdr.TestDIDB
var authorizerDID = vdr.TestDIDA
var authorizerDIDDocument = getAuthorizerDIDDocument()
var requesterSigningKeyID = getRequesterSigningKey()
var authorizerSigningKeyID = getAuthorizerSigningKey()

const expectedService = "unit-test"
const expectedAudience = "http://oauth"

func getRequesterSigningKey() ssi.URI {
	return ssi.MustParseURI(requesterDID.String() + "#signing-key")
}

func getAuthorizerSigningKey() ssi.URI {
	return ssi.MustParseURI(authorizerDID.String() + "#signing-key")
}

func getAuthorizerDIDDocument() *did.Document {
	id := authorizerDID
	serviceID := ssi.MustParseURI(id.String() + "#service-id")

	doc := did.Document{
		ID: id,
	}
	signingKeyID := did.DIDURL{DID: id}
	signingKeyID.Fragment = "signing-key"
	key, err := did.NewVerificationMethod(signingKeyID, ssi.JsonWebKey2020, id, authorizerSigningKey.Public())
	if err != nil {
		panic(err)
	}
	doc.AddAssertionMethod(key)
	doc.AddCapabilityInvocation(key)
	doc.Service = append(doc.Service, did.Service{
		ID:   serviceID,
		Type: "oauth",
	})
	doc.Service = append(doc.Service, did.Service{
		Type: "service",
		ServiceEndpoint: map[string]string{
			"oauth": fmt.Sprintf("%s?type=oauth", id.String()),
		},
	})
	return &doc
}

func TestAuth_CreateAccessToken(t *testing.T) {
	searchTerms := []vcr.SearchTerm{
		{IRIPath: jsonld.CredentialSubjectPath, Value: requesterDID.String()},
		{IRIPath: jsonld.OrganizationNamePath, Type: vcr.NotNil},
		{IRIPath: jsonld.OrganizationCityPath, Type: vcr.NotNil},
	}

	testCredential := vc.VerifiableCredential{}
	_ = json.Unmarshal([]byte(jsonld.TestOrganizationCredential), &testCredential)
	t.Run("invalid jwt", func(t *testing.T) {
		ctx := createContext(t)

		response, err := ctx.oauthService.CreateAccessToken(ctx.audit, services.CreateAccessTokenRequest{RawJwtBearerToken: "foo"})

		assert.Nil(t, response)
		require.ErrorContains(t, err, "jwt bearer token validation failed")
	})

	t.Run("broken identity token", func(t *testing.T) {
		ctx := createContext(t)

		ctx.nameResolver.EXPECT().Search(context.Background(), searchTerms, false, gomock.Any()).Return([]vc.VerifiableCredential{testCredential}, nil)
		ctx.contractNotary.EXPECT().VerifyVP(gomock.Any(), nil).Return(nil, errors.New("identity validation failed"))
		ctx.keyResolver.EXPECT().ResolveKeyByID(requesterSigningKeyID.String(), gomock.Any(), resolver.NutsSigningKeyType).MinTimes(1).Return(requesterSigningKey.Public(), nil)
		ctx.keyResolver.EXPECT().ResolveKey(authorizerDID, gomock.Any(), resolver.NutsSigningKeyType).MinTimes(1).Return(authorizerSigningKeyID, authorizerSigningKey, nil)
		ctx.keyStore.EXPECT().Exists(ctx.audit, authorizerSigningKeyID.String()).Return(true)
		tokenCtx := validContext()
		signToken(tokenCtx)

		response, err := ctx.oauthService.CreateAccessToken(ctx.audit, services.CreateAccessTokenRequest{RawJwtBearerToken: tokenCtx.rawJwtBearerToken})

		assert.Nil(t, response)
		require.ErrorContains(t, err, "identity validation failed")
	})

	t.Run("JWT validity too long", func(t *testing.T) {
		ctx := createContext(t)

		ctx.keyResolver.EXPECT().ResolveKeyByID(requesterSigningKeyID.String(), nil, resolver.NutsSigningKeyType).MinTimes(1).Return(requesterSigningKey.Public(), nil)

		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Set(jwt.ExpirationKey, time.Now().Add(10*time.Second))
		signToken(tokenCtx)

		response, err := ctx.oauthService.CreateAccessToken(ctx.audit, services.CreateAccessTokenRequest{RawJwtBearerToken: tokenCtx.rawJwtBearerToken})

		assert.Nil(t, response)
		assert.ErrorContains(t, err, "JWT validity too long")
	})

	t.Run("invalid identity token", func(t *testing.T) {
		ctx := createContext(t)

		ctx.nameResolver.EXPECT().Search(context.Background(), searchTerms, false, gomock.Any()).Return([]vc.VerifiableCredential{testCredential}, nil)
		ctx.keyStore.EXPECT().Exists(ctx.audit, authorizerSigningKeyID.String()).Return(true)
		ctx.keyResolver.EXPECT().ResolveKeyByID(requesterSigningKeyID.String(), gomock.Any(), resolver.NutsSigningKeyType).MinTimes(1).Return(requesterSigningKey.Public(), nil)
		ctx.keyResolver.EXPECT().ResolveKey(authorizerDID, gomock.Any(), resolver.NutsSigningKeyType).MinTimes(1).Return(authorizerSigningKeyID, authorizerSigningKey, nil)
		ctx.contractNotary.EXPECT().VerifyVP(gomock.Any(), nil).Return(services.TestVPVerificationResult{Val: contract.Invalid, FailureReason: "because of reasons"}, nil)

		tokenCtx := validContext()
		signToken(tokenCtx)

		response, err := ctx.oauthService.CreateAccessToken(ctx.audit, services.CreateAccessTokenRequest{RawJwtBearerToken: tokenCtx.rawJwtBearerToken})

		assert.Nil(t, response)
		assert.ErrorContains(t, err, "identity validation failed: because of reasons")
	})

	t.Run("error detail masking", func(t *testing.T) {
		setup := func(ctx *testContext) *testContext {
			ctx.keyResolver.EXPECT().ResolveKeyByID(requesterSigningKeyID.String(), gomock.Any(), resolver.NutsSigningKeyType).MinTimes(1).Return(requesterSigningKey.Public(), nil).AnyTimes()
			ctx.keyResolver.EXPECT().ResolveKey(authorizerDID, gomock.Any(), gomock.Any()).MinTimes(1).Return(authorizerSigningKeyID, authorizerSigningKey, nil).AnyTimes()
			ctx.nameResolver.EXPECT().Search(context.Background(), searchTerms, false, gomock.Any()).Return([]vc.VerifiableCredential{testCredential}, nil).AnyTimes()
			ctx.didResolver.EXPECT().Resolve(authorizerDID, gomock.Any()).Return(getAuthorizerDIDDocument(), nil, nil).AnyTimes()
			ctx.serviceResolver.EXPECT().GetCompoundServiceEndpoint(authorizerDID, expectedService, services.OAuthEndpointType, true).Return(expectedAudience, nil).AnyTimes()
			ctx.keyStore.EXPECT().Exists(ctx.audit, authorizerSigningKeyID.String()).Return(true).AnyTimes()
			ctx.verifier.EXPECT().Verify(gomock.Any(), true, true, gomock.Any()).Return(nil).AnyTimes()
			ctx.contractNotary.EXPECT().VerifyVP(gomock.Any(), nil).Return(services.TestVPVerificationResult{
				Val:         contract.Valid,
				DAttributes: map[string]string{"name": "Henk de Vries"},
				CAttributes: map[string]string{"legal_entity": "CareBears", "legal_entity_city": "Caretown"},
			}, nil)
			return ctx
		}

		t.Run("return internal errors when secureMode=false", func(t *testing.T) {
			ctx := setup(createContext(t))
			ctx.oauthService.secureMode = false
			ctx.keyStore.EXPECT().SignJWT(ctx.audit, gomock.Any(), nil, gomock.Any()).Return("", errors.New("signing error"))
			tokenCtx := validContext()
			signToken(tokenCtx)

			response, err := ctx.oauthService.CreateAccessToken(ctx.audit, services.CreateAccessTokenRequest{RawJwtBearerToken: tokenCtx.rawJwtBearerToken})

			require.Error(t, err)
			assert.Nil(t, response)
			assert.EqualError(t, err, "could not build accessToken: signing error")
		})
		t.Run("mask internal errors when secureMode=true", func(t *testing.T) {
			ctx := setup(createContext(t))
			ctx.oauthService.secureMode = true
			ctx.keyStore.EXPECT().SignJWT(gomock.Any(), gomock.Any(), nil, gomock.Any()).Return("", errors.New("signing error"))
			tokenCtx := validContext()
			signToken(tokenCtx)

			response, err := ctx.oauthService.CreateAccessToken(ctx.audit, services.CreateAccessTokenRequest{RawJwtBearerToken: tokenCtx.rawJwtBearerToken})

			require.Error(t, err)
			assert.Nil(t, response)
			assert.EqualError(t, err, "failed")
		})
	})

	t.Run("valid - without user identity", func(t *testing.T) {
		testCtx := createContext(t)

		testCtx.keyResolver.EXPECT().ResolveKeyByID(requesterSigningKeyID.String(), gomock.Any(), resolver.NutsSigningKeyType).MinTimes(1).Return(requesterSigningKey.Public(), nil)
		testCtx.keyResolver.EXPECT().ResolveKey(authorizerDID, gomock.Any(), resolver.NutsSigningKeyType).MinTimes(1).Return(authorizerSigningKeyID, authorizerSigningKey, nil)
		testCtx.nameResolver.EXPECT().Search(context.Background(), searchTerms, false, gomock.Any()).Return([]vc.VerifiableCredential{testCredential}, nil)
		testCtx.didResolver.EXPECT().Resolve(authorizerDID, gomock.Any()).Return(getAuthorizerDIDDocument(), nil, nil).AnyTimes()
		testCtx.serviceResolver.EXPECT().GetCompoundServiceEndpoint(authorizerDID, expectedService, services.OAuthEndpointType, true).Return(expectedAudience, nil)
		testCtx.keyStore.EXPECT().Exists(testCtx.audit, authorizerSigningKeyID.String()).Return(true)
		testCtx.keyStore.EXPECT().SignJWT(gomock.Any(), gomock.Any(), nil, authorizerSigningKeyID.String()).Return("expectedAccessToken", nil)
		testCtx.verifier.EXPECT().Verify(gomock.Any(), true, true, gomock.Any()).Return(nil)

		ctx := validContext()
		ctx.jwtBearerToken.Remove(userIdentityClaim)
		signToken(ctx)

		response, err := testCtx.oauthService.CreateAccessToken(testCtx.audit, services.CreateAccessTokenRequest{RawJwtBearerToken: ctx.rawJwtBearerToken})

		require.Nil(t, err) // using NoError casts it to error, weirdly causing it to be non-nil
		assert.Equal(t, "expectedAccessToken", response.AccessToken)
	})

	t.Run("valid - all fields", func(t *testing.T) {
		ctx := createContext(t)

		ctx.keyResolver.EXPECT().ResolveKeyByID(requesterSigningKeyID.String(), gomock.Any(), resolver.NutsSigningKeyType).MinTimes(1).Return(requesterSigningKey.Public(), nil)
		ctx.keyResolver.EXPECT().ResolveKey(authorizerDID, gomock.Any(), resolver.NutsSigningKeyType).MinTimes(1).Return(authorizerSigningKeyID, authorizerSigningKey, nil)
		ctx.nameResolver.EXPECT().Search(context.Background(), searchTerms, false, gomock.Any()).Return([]vc.VerifiableCredential{testCredential}, nil)
		ctx.didResolver.EXPECT().Resolve(authorizerDID, gomock.Any()).Return(getAuthorizerDIDDocument(), nil, nil).AnyTimes()
		ctx.serviceResolver.EXPECT().GetCompoundServiceEndpoint(authorizerDID, expectedService, services.OAuthEndpointType, true).Return(expectedAudience, nil)
		ctx.keyStore.EXPECT().Exists(ctx.audit, authorizerSigningKeyID.String()).Return(true)
		ctx.keyStore.EXPECT().SignJWT(gomock.Any(), gomock.Any(), nil, authorizerSigningKeyID.String()).Return("expectedAT", nil)
		ctx.contractNotary.EXPECT().VerifyVP(gomock.Any(), nil).Return(services.TestVPVerificationResult{
			Val:         contract.Valid,
			DAttributes: map[string]string{"name": "Henk de Vries"},
			CAttributes: map[string]string{"legal_entity": "CareBears", "legal_entity_city": "Caretown"},
		}, nil)
		ctx.verifier.EXPECT().Verify(gomock.Any(), true, true, gomock.Any()).Return(nil)

		tokenCtx := validContext()
		signToken(tokenCtx)

		response, err := ctx.oauthService.CreateAccessToken(ctx.audit, services.CreateAccessTokenRequest{RawJwtBearerToken: tokenCtx.rawJwtBearerToken})
		require.Nil(t, err) // using NoError casts it to error, weirdly causing it to be non-nil
		assert.Equal(t, "expectedAT", response.AccessToken)
	})

	t.Run("missing organization credential", func(t *testing.T) {
		ctx := createContext(t)

		ctx.keyResolver.EXPECT().ResolveKeyByID(requesterSigningKeyID.String(), gomock.Any(), resolver.NutsSigningKeyType).MinTimes(1).Return(requesterSigningKey.Public(), nil)
		ctx.nameResolver.EXPECT().Search(context.Background(), searchTerms, false, gomock.Any()).Return([]vc.VerifiableCredential{}, nil)
		ctx.didResolver.EXPECT().Resolve(authorizerDID, gomock.Any()).Return(getAuthorizerDIDDocument(), nil, nil).AnyTimes()

		tokenCtx := validContext()
		signToken(tokenCtx)

		_, err := ctx.oauthService.CreateAccessToken(ctx.audit, services.CreateAccessTokenRequest{RawJwtBearerToken: tokenCtx.rawJwtBearerToken})
		require.Error(t, err)
	})
}

func TestService_validateIssuer(t *testing.T) {
	searchTerms := []vcr.SearchTerm{
		{IRIPath: jsonld.CredentialSubjectPath, Value: requesterDID.String()},
		{IRIPath: jsonld.OrganizationNamePath, Type: vcr.NotNil},
		{IRIPath: jsonld.OrganizationCityPath, Type: vcr.NotNil},
	}
	testCredential := vc.VerifiableCredential{}
	_ = json.Unmarshal([]byte(jsonld.TestOrganizationCredential), &testCredential)

	t.Run("ok", func(t *testing.T) {
		ctx := createContext(t)

		tokenCtx := validContext()
		ctx.keyResolver.EXPECT().ResolveKeyByID(requesterSigningKeyID.String(), gomock.Any(), resolver.NutsSigningKeyType).MinTimes(1).Return(requesterSigningKey.Public(), nil)
		ctx.nameResolver.EXPECT().Search(context.Background(), searchTerms, false, gomock.Any()).Return([]vc.VerifiableCredential{testCredential}, nil)

		err := ctx.oauthService.validateIssuer(tokenCtx)
		require.NoError(t, err)
		require.Len(t, tokenCtx.requesterOrganizationIdentities, 1)
		assert.Equal(t, "CareBears", tokenCtx.requesterOrganizationIdentities[0].name)
	})
	t.Run("ok - multiple creds", func(t *testing.T) {
		ctx := createContext(t)

		tokenCtx := validContext()
		ctx.keyResolver.EXPECT().ResolveKeyByID(requesterSigningKeyID.String(), gomock.Any(), resolver.NutsSigningKeyType).MinTimes(1).Return(requesterSigningKey.Public(), nil)
		ctx.nameResolver.EXPECT().Search(context.Background(), searchTerms, false, gomock.Any()).Return([]vc.VerifiableCredential{testCredential, testCredential}, nil)

		err := ctx.oauthService.validateIssuer(tokenCtx)
		require.NoError(t, err)
		assert.Len(t, tokenCtx.requesterOrganizationIdentities, 2)
	})
	t.Run("invalid issuer", func(t *testing.T) {
		ctx := createContext(t)

		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Set(jwt.IssuerKey, "not a urn")

		err := ctx.oauthService.validateIssuer(tokenCtx)
		assert.ErrorIs(t, err, did.ErrInvalidDID)
	})
	t.Run("unable to resolve credential", func(t *testing.T) {
		ctx := createContext(t)

		tokenCtx := validContext()
		ctx.keyResolver.EXPECT().ResolveKeyByID(requesterSigningKeyID.String(), gomock.Any(), resolver.NutsSigningKeyType).Return(requesterSigningKey.Public(), nil)
		ctx.nameResolver.EXPECT().Search(context.Background(), searchTerms, false, gomock.Any()).Return(nil, errors.New("error occurred"))

		err := ctx.oauthService.validateIssuer(tokenCtx)
		assert.EqualError(t, err, "invalid jwt.issuer: error occurred")
	})
	t.Run("no matching credential", func(t *testing.T) {
		ctx := createContext(t)

		tokenCtx := validContext()
		ctx.keyResolver.EXPECT().ResolveKeyByID(requesterSigningKeyID.String(), gomock.Any(), resolver.NutsSigningKeyType).Return(requesterSigningKey.Public(), nil)
		ctx.nameResolver.EXPECT().Search(context.Background(), searchTerms, false, gomock.Any()).Return([]vc.VerifiableCredential{}, nil)

		err := ctx.oauthService.validateIssuer(tokenCtx)
		assert.EqualError(t, err, "requester has no trusted organization VC")
	})
	t.Run("unable to resolve key", func(t *testing.T) {
		ctx := createContext(t)

		tokenCtx := validContext()

		ctx.keyResolver.EXPECT().ResolveKeyByID(requesterSigningKeyID.String(), gomock.Any(), resolver.NutsSigningKeyType).MinTimes(1).Return(nil, fmt.Errorf("not found"))

		err := ctx.oauthService.validateIssuer(tokenCtx)
		assert.EqualError(t, err, "invalid jwt.issuer key ID: not found")
	})
}

func TestService_validateSubject(t *testing.T) {
	t.Run("subject managed", func(t *testing.T) {
		ctx := createContext(t)

		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Set(jwt.SubjectKey, authorizerDID.String())

		ctx.keyResolver.EXPECT().ResolveKey(authorizerDID, gomock.Any(), resolver.NutsSigningKeyType).MinTimes(1).Return(authorizerSigningKeyID, authorizerSigningKey, nil)
		ctx.keyStore.EXPECT().Exists(ctx.audit, authorizerSigningKeyID.String()).Return(true)

		err := ctx.oauthService.validateSubject(ctx.audit, tokenCtx)
		assert.NoError(t, err)
	})
	t.Run("missing subject", func(t *testing.T) {
		ctx := createContext(t)

		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Remove("sub")

		err := ctx.oauthService.validateSubject(ctx.audit, tokenCtx)
		assert.EqualError(t, err, "invalid jwt.subject: missing")
	})
	t.Run("invalid subject", func(t *testing.T) {
		ctx := createContext(t)

		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Set(jwt.SubjectKey, "not a urn")

		err := ctx.oauthService.validateSubject(ctx.audit, tokenCtx)
		assert.ErrorIs(t, err, did.ErrInvalidDID)
	})
	t.Run("subject not managed by this node", func(t *testing.T) {
		ctx := createContext(t)

		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Set(jwt.SubjectKey, authorizerDID.String())

		ctx.keyResolver.EXPECT().ResolveKey(authorizerDID, gomock.Any(), resolver.NutsSigningKeyType).MinTimes(1).Return(authorizerSigningKeyID, authorizerSigningKey, nil)
		ctx.keyStore.EXPECT().Exists(ctx.audit, authorizerSigningKeyID.String()).Return(false)

		err := ctx.oauthService.validateSubject(ctx.audit, tokenCtx)

		assert.ErrorContains(t, err, "is not managed by this node")
	})
}

func TestService_validatePurposeOfUse(t *testing.T) {
	t.Run("error - no purposeOfUse", func(t *testing.T) {
		ctx := createContext(t)
		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Remove(purposeOfUseClaimDeprecated)
		tokenCtx.jwtBearerToken.Remove(purposeOfUseClaim)

		err := ctx.oauthService.validatePurposeOfUse(tokenCtx)

		assert.EqualError(t, err, "no purposeOfUse given")
	})

	t.Run("ok - only deprecated claim", func(t *testing.T) {
		ctx := createContext(t)
		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Remove(purposeOfUseClaim)

		err := ctx.oauthService.validatePurposeOfUse(tokenCtx)

		assert.NoError(t, err)
	})

	t.Run("ok - only correct claim", func(t *testing.T) {
		ctx := createContext(t)
		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Remove(purposeOfUseClaimDeprecated)

		err := ctx.oauthService.validatePurposeOfUse(tokenCtx)

		assert.NoError(t, err)
	})
}

func TestService_validateAud(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctx := createContext(t)
		tokenCtx := validContext()
		ctx.didResolver.EXPECT().Resolve(authorizerDID, gomock.Any()).Return(getAuthorizerDIDDocument(), nil, nil).AnyTimes()
		ctx.serviceResolver.EXPECT().GetCompoundServiceEndpoint(authorizerDID, expectedService, services.OAuthEndpointType, true).Return(expectedAudience, nil)

		err := ctx.oauthService.validateAudience(tokenCtx)

		assert.NoError(t, err)
	})

	t.Run("error - no audience", func(t *testing.T) {
		ctx := createContext(t)
		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Set(jwt.AudienceKey, []string{})

		err := ctx.oauthService.validateAudience(tokenCtx)

		assert.EqualError(t, err, "aud does not contain a single URI")
	})

	t.Run("error - endpoint resolve returns error", func(t *testing.T) {
		ctx := createContext(t)
		tokenCtx := validContext()
		ctx.serviceResolver.EXPECT().GetCompoundServiceEndpoint(authorizerDID, expectedService, services.OAuthEndpointType, true).Return("", resolver.ErrNotFound)

		err := ctx.oauthService.validateAudience(tokenCtx)

		assert.Equal(t, resolver.ErrNotFound, err)
	})

	t.Run("error - wrong audience", func(t *testing.T) {
		ctx := createContext(t)
		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Set(jwt.AudienceKey, []string{"not_the_right_audience"})
		ctx.serviceResolver.EXPECT().GetCompoundServiceEndpoint(authorizerDID, expectedService, services.OAuthEndpointType, true).Return(expectedAudience, nil)

		err := ctx.oauthService.validateAudience(tokenCtx)

		assert.EqualError(t, err, "aud does not contain correct endpoint URL")
	})
}

func TestService_validateAuthorizationCredentials(t *testing.T) {
	ctx := createContext(t)

	t.Run("ok", func(t *testing.T) {
		tokenCtx := validContext()
		signToken(tokenCtx)

		ctx.verifier.EXPECT().Verify(gomock.Any(), true, true, gomock.Any()).Return(nil)
		err := ctx.oauthService.validateAuthorizationCredentials(tokenCtx)

		require.NoError(t, err)

		assert.NotNil(t, tokenCtx.credentialIDs)
		assert.Equal(t, "did:nuts:GvkzxsezHvEc8nGhgz6Xo3jbqkHwswLmWw3CYtCm7hAW#38E90E8C-F7E5-4333-B63A-F9DD155A0272", tokenCtx.credentialIDs[0])
	})

	t.Run("ok - no authorization credentials", func(t *testing.T) {
		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Remove(vcClaim)
		signToken(tokenCtx)

		err := ctx.oauthService.validateAuthorizationCredentials(tokenCtx)

		assert.NoError(t, err)
	})

	t.Run("ok - empty list", func(t *testing.T) {
		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Set(vcClaim, []interface{}{})
		signToken(tokenCtx)

		err := ctx.oauthService.validateAuthorizationCredentials(tokenCtx)

		assert.NoError(t, err)
	})

	t.Run("error - wrong vcs contents", func(t *testing.T) {
		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Set(vcClaim, "not a vc")
		signToken(tokenCtx)

		err := ctx.oauthService.validateAuthorizationCredentials(tokenCtx)

		assert.EqualError(t, err, "invalid jwt.vcs: field does not contain an array of credentials")
	})

	t.Run("error - wrong vcs contents 2", func(t *testing.T) {
		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Set(vcClaim, []interface{}{"}"})
		signToken(tokenCtx)

		err := ctx.oauthService.validateAuthorizationCredentials(tokenCtx)

		assert.EqualError(t, err, "invalid jwt.vcs: cannot unmarshal authorization credential: invalid JWT")
	})

	t.Run("error - jwt.iss <> credentialSubject.ID mismatch", func(t *testing.T) {
		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Set(jwt.IssuerKey, "unknown")
		signToken(tokenCtx)
		ctx.verifier.EXPECT().Verify(gomock.Any(), true, true, gomock.Any()).Return(nil)

		err := ctx.oauthService.validateAuthorizationCredentials(tokenCtx)

		assert.EqualError(t, err, "credentialSubject.ID did:nuts:B8PUHs2AUHbFF1xLLK4eZjgErEcMXHxs68FteY7NDtCY of authorization credential with ID: did:nuts:GvkzxsezHvEc8nGhgz6Xo3jbqkHwswLmWw3CYtCm7hAW#38E90E8C-F7E5-4333-B63A-F9DD155A0272 does not match jwt.iss: unknown")
	})

	t.Run("error - jwt.sub <> issuer mismatch", func(t *testing.T) {
		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Set(jwt.SubjectKey, "unknown")
		signToken(tokenCtx)
		ctx.verifier.EXPECT().Verify(gomock.Any(), true, true, gomock.Any()).Return(nil)

		err := ctx.oauthService.validateAuthorizationCredentials(tokenCtx)

		assert.EqualError(t, err, "issuer did:nuts:GvkzxsezHvEc8nGhgz6Xo3jbqkHwswLmWw3CYtCm7hAW of authorization credential with ID: did:nuts:GvkzxsezHvEc8nGhgz6Xo3jbqkHwswLmWw3CYtCm7hAW#38E90E8C-F7E5-4333-B63A-F9DD155A0272 does not match jwt.sub: unknown")
	})

	t.Run("error - invalid credential", func(t *testing.T) {
		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Set(jwt.SubjectKey, "unknown")
		signToken(tokenCtx)
		ctx.verifier.EXPECT().Verify(gomock.Any(), true, true, gomock.Any()).Return(vcrTypes.ErrRevoked)

		err := ctx.oauthService.validateAuthorizationCredentials(tokenCtx)

		assert.EqualError(t, err, "invalid jwt.vcs: credential is revoked")
	})
}

func TestService_parseAndValidateJwtBearerToken(t *testing.T) {
	ctx := createContext(t)

	t.Run("malformed JWTs", func(t *testing.T) {
		tokenCtx := &validationContext{
			rawJwtBearerToken: "foo",
		}
		err := ctx.oauthService.parseAndValidateJwtBearerToken(tokenCtx)
		assert.Nil(t, tokenCtx.jwtBearerToken)
		assert.Equal(t, "invalid compact serialization format: invalid number of segments", err.Error())

		tokenCtx2 := &validationContext{
			rawJwtBearerToken: "123.456.787",
		}
		err = ctx.oauthService.parseAndValidateJwtBearerToken(tokenCtx2)
		assert.Nil(t, tokenCtx.jwtBearerToken)
		assert.Equal(t, "failed to parse JOSE headers: invalid character '×' looking for beginning of value", err.Error())
	})

	t.Run("wrong signing algorithm", func(t *testing.T) {
		privateKey, _ := rsa.GenerateKey(rand.Reader, 512)

		keyID := "did:nuts:somedid#key-id"

		ctx.keyResolver.EXPECT().ResolveKeyByID(keyID, nil, resolver.NutsSigningKeyType).Return(privateKey.Public(), nil)

		// alg: RS256
		token := jwt.New()
		hdrs := jws.NewHeaders()
		hdrs.Set(jws.KeyIDKey, keyID)
		signedToken, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, privateKey, jws.WithProtectedHeaders(hdrs)))
		require.NoError(t, err)

		tokenCtx := &validationContext{
			rawJwtBearerToken: string(signedToken),
		}
		err = ctx.oauthService.parseAndValidateJwtBearerToken(tokenCtx)
		assert.Nil(t, tokenCtx.jwtBearerToken)
		assert.Equal(t, "token signing algorithm is not supported: RS256", err.Error())
	})

	t.Run("valid token", func(t *testing.T) {
		tokenCtx := validContext()
		signToken(tokenCtx)

		ctx.keyResolver.EXPECT().ResolveKeyByID(requesterSigningKeyID.String(), nil, resolver.NutsSigningKeyType).Return(requesterSigningKey.PublicKey, nil)

		err := ctx.oauthService.parseAndValidateJwtBearerToken(tokenCtx)
		assert.NoError(t, err)
		assert.Equal(t, requesterDID.String(), tokenCtx.jwtBearerToken.Issuer())
		assert.Equal(t, requesterSigningKeyID.String(), tokenCtx.kid)
	})

	t.Run("valid token with clock diff", func(t *testing.T) {
		// a token created 10 minutes ago, valid until 4 minutes ago. But due to clock skew of 5 minutes, it should still be valid.
		ctx := createContext(t)
		ctx.oauthService.clockSkew = 5 * time.Minute
		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Set(jwt.IssuedAtKey, time.Now().Add(-10*time.Minute))
		tokenCtx.jwtBearerToken.Set(jwt.ExpirationKey, time.Now().Add(-4*time.Minute))
		signToken(tokenCtx)

		ctx.keyResolver.EXPECT().ResolveKeyByID(requesterSigningKeyID.String(), nil, resolver.NutsSigningKeyType).Return(requesterSigningKey.PublicKey, nil)

		err := ctx.oauthService.parseAndValidateJwtBearerToken(tokenCtx)
		assert.NoError(t, err)
	})

	t.Run("expired token", func(t *testing.T) {
		// a token created 10 minutes ago, valid until 4 minutes ago. Just a very small clock skew allowed, so it should be expired.
		ctx := createContext(t)
		ctx.oauthService.clockSkew = 1 * time.Millisecond // because 0 multiplied by 0 equals 0, rather use 1 millisecond (small clock skew), better test.
		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Set(jwt.IssuedAtKey, time.Now().Add(-10*time.Minute))
		tokenCtx.jwtBearerToken.Set(jwt.ExpirationKey, time.Now().Add(-4*time.Minute))
		signToken(tokenCtx)

		ctx.keyResolver.EXPECT().ResolveKeyByID(requesterSigningKeyID.String(), nil, resolver.NutsSigningKeyType).Return(requesterSigningKey.PublicKey, nil)

		err := ctx.oauthService.parseAndValidateJwtBearerToken(tokenCtx)
		assert.EqualError(t, err, "\"exp\" not satisfied")
	})
}

func TestService_buildAccessToken(t *testing.T) {
	t.Run("build an access token", func(t *testing.T) {
		ctx := createContext(t)
		ctx.oauthService.accessTokenLifeSpan = secureAccessTokenLifeSpan * 10 // ignored by secureMode == true
		ctx.oauthService.Configure(5000, true)

		ctx.keyResolver.EXPECT().ResolveKey(authorizerDID, gomock.Any(), resolver.NutsSigningKeyType).MinTimes(1).Return(authorizerSigningKeyID, authorizerSigningKey, nil)

		var actualClaims map[string]interface{}
		ctx.keyStore.EXPECT().SignJWT(gomock.Any(), gomock.Any(), nil, gomock.Any()).
			DoAndReturn(func(_ context.Context, inputClaims map[string]interface{}, headers map[string]interface{}, kid string) (token string, err error) {
				actualClaims = inputClaims
				return "expectedAT", nil
			})

		presentation := services.TestVPVerificationResult{
			Val: contract.Valid,
			DAttributes: map[string]string{
				services.AssuranceLevelClaim:  "low",
				services.InitialsTokenClaim:   "T.",
				services.FamilyNameTokenClaim: "Tester",
				services.UserRoleClaim:        "Developer",
				services.UsernameClaim:        "1234567890",
			},
		}
		token, accessToken, err := ctx.oauthService.buildAccessToken(audit.TestContext(), requesterDID, authorizerDID, "", &presentation, []string{"credential"})

		assert.Nil(t, err)
		assert.Equal(t, "expectedAT", token)
		assert.Equal(t, secureAccessTokenLifeSpan, time.Duration(accessToken.Expiration-accessToken.IssuedAt)*time.Second)
		assert.Equal(t, authorizerDID.String(), actualClaims["iss"])
		assert.Equal(t, "low", actualClaims["assurance_level"])
		assert.Equal(t, "T.", actualClaims["initials"])
		assert.Equal(t, "Tester", actualClaims["family_name"])
		assert.Equal(t, "Developer", actualClaims["user_role"])
		assert.Equal(t, "1234567890", actualClaims["username"])
		actualCredentials, ok := actualClaims["vcs"].([]interface{})
		require.True(t, ok)
		assert.Equal(t, "credential", actualCredentials[0])
	})
}

func TestService_IntrospectAccessToken(t *testing.T) {
	t.Run("validate access token", func(t *testing.T) {
		ctx := createContext(t)

		ctx.keyResolver.EXPECT().ResolveKeyByID(requesterSigningKeyID.String(), nil, resolver.NutsSigningKeyType).MinTimes(1).Return(requesterSigningKey.Public(), nil)
		ctx.keyStore.EXPECT().Exists(ctx.audit, requesterSigningKeyID.String()).Return(true)

		// First build an access token
		tokenCtx := validAccessToken()
		signToken(tokenCtx)

		// Then validate it
		claims, err := ctx.oauthService.IntrospectAccessToken(ctx.audit, tokenCtx.rawJwtBearerToken)
		require.NoError(t, err)
		require.NotNil(t, claims)

		assert.Equal(t, tokenCtx.jwtBearerToken.Subject(), claims.Subject)
		assert.Equal(t, tokenCtx.jwtBearerToken.Issuer(), claims.Issuer)
		assert.Equal(t, tokenCtx.jwtBearerToken.IssuedAt().Unix(), claims.IssuedAt)
		assert.Equal(t, tokenCtx.jwtBearerToken.Expiration().Unix(), claims.Expiration)
	})

	t.Run("invalid signature", func(t *testing.T) {
		ctx := createContext(t)

		ctx.keyResolver.EXPECT().ResolveKeyByID(requesterSigningKeyID.String(), nil, resolver.NutsSigningKeyType).MinTimes(1).Return(requesterSigningKey.Public(), nil)
		ctx.keyStore.EXPECT().Exists(ctx.audit, requesterSigningKeyID.String()).Return(true)

		// First build an access token
		tokenCtx := validAccessToken()
		signingKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		signTokenWithKey(tokenCtx, signingKey)

		// Then validate it
		claims, err := ctx.oauthService.IntrospectAccessToken(ctx.audit, tokenCtx.rawJwtBearerToken)

		require.EqualError(t, err, "could not verify message using any of the signatures or keys")
		require.Nil(t, claims)
	})

	t.Run("private key not present", func(t *testing.T) {
		ctx := createContext(t)

		ctx.keyStore.EXPECT().Exists(ctx.audit, requesterSigningKeyID.String()).Return(false)

		// First build an access token
		tokenCtx := validContext()
		signToken(tokenCtx)

		// Then validate it
		_, err := ctx.oauthService.IntrospectAccessToken(ctx.audit, tokenCtx.rawJwtBearerToken)
		assert.Error(t, err)
	})

	t.Run("key not present on DID", func(t *testing.T) {
		ctx := createContext(t)

		ctx.keyStore.EXPECT().Exists(ctx.audit, requesterSigningKeyID.String()).Return(true)
		ctx.keyResolver.EXPECT().ResolveKeyByID(requesterSigningKeyID.String(), nil, resolver.NutsSigningKeyType).MinTimes(1).Return(nil, resolver.ErrNotFound)

		// First build an access token
		tokenCtx := validContext()
		signToken(tokenCtx)

		// Then validate it
		_, err := ctx.oauthService.IntrospectAccessToken(ctx.audit, tokenCtx.rawJwtBearerToken)
		assert.Error(t, err)
	})
}

func TestAuth_Configure(t *testing.T) {
	t.Run("ok - config valid", func(t *testing.T) {
		ctx := createContext(t)

		err := ctx.oauthService.Configure(1000*60, true)

		assert.NoError(t, err)
		assert.Equal(t, time.Minute, ctx.oauthService.clockSkew)
		assert.True(t, ctx.oauthService.secureMode)
	})
}

func validContext() *validationContext {
	usi := vc.VerifiablePresentation{Type: []ssi.URI{ssi.MustParseURI("TestPresentation")}}

	cred := credential.ValidNutsAuthorizationCredential()
	credString, _ := json.Marshal(cred)
	credMap := map[string]interface{}{}
	_ = json.Unmarshal(credString, &credMap)

	claims := map[string]interface{}{
		jwt.AudienceKey:             expectedAudience,
		jwt.ExpirationKey:           time.Now().Add(5 * time.Second).Unix(),
		jwt.JwtIDKey:                "a005e81c-6749-4967-b01c-495228fcafb4",
		jwt.IssuedAtKey:             time.Now().UTC(),
		jwt.IssuerKey:               requesterDID.String(),
		jwt.NotBeforeKey:            0,
		jwt.SubjectKey:              authorizerDID.String(),
		userIdentityClaim:           usi,
		purposeOfUseClaimDeprecated: expectedService,
		purposeOfUseClaim:           expectedService,
		vcClaim:                     []interface{}{credMap},
	}
	token := jwt.New()
	for k, v := range claims {
		if err := token.Set(k, v); err != nil {
			panic(err)
		}
	}
	return &validationContext{
		jwtBearerToken: token,
		kid:            requesterSigningKeyID.String(),
		purposeOfUse:   expectedService,
	}
}

func validAccessToken() *validationContext {
	usi := vc.VerifiablePresentation{Type: []ssi.URI{ssi.MustParseURI("TestPresentation")}}

	claims := map[string]interface{}{
		jwt.AudienceKey:             expectedAudience,
		jwt.ExpirationKey:           time.Now().Add(5 * time.Second).Unix(),
		jwt.JwtIDKey:                "a005e81c-6749-4967-b01c-495228fcafb4",
		jwt.IssuedAtKey:             time.Now().UTC(),
		jwt.SubjectKey:              requesterDID.String(),
		jwt.NotBeforeKey:            0,
		jwt.IssuerKey:               authorizerDID.String(),
		userIdentityClaim:           usi,
		purposeOfUseClaimDeprecated: expectedService,
		vcClaim:                     []string{"credential"},
	}
	token := jwt.New()
	for k, v := range claims {
		if err := token.Set(k, v); err != nil {
			panic(err)
		}
	}
	return &validationContext{
		jwtBearerToken: token,
		kid:            requesterSigningKeyID.String(),
		purposeOfUse:   expectedService,
	}
}

func signToken(context *validationContext) {
	signTokenWithKey(context, requesterSigningKey)
}

func signTokenWithKey(context *validationContext, key *ecdsa.PrivateKey) {
	hdrs := jws.NewHeaders()
	err := hdrs.Set(jws.KeyIDKey, requesterSigningKeyID.String())
	if err != nil {
		panic(err)
	}
	signedToken, err := jwt.Sign(context.jwtBearerToken, jwt.WithKey(jwa.ES256, key, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		panic(err)
	}
	context.rawJwtBearerToken = string(signedToken)
}

type testContext struct {
	ctrl            *gomock.Controller
	contractNotary  *services.MockContractNotary
	keyStore        *crypto.MockKeyStore
	nameResolver    *vcr.MockFinder
	didResolver     *resolver.MockDIDResolver
	keyResolver     *resolver.MockKeyResolver
	serviceResolver *didman.MockCompoundServiceResolver
	oauthService    *authzServer
	verifier        *verifier2.MockVerifier
	audit           context.Context
}

var createContext = func(t *testing.T) *testContext {
	ctrl := gomock.NewController(t)

	contractNotaryMock := services.NewMockContractNotary(ctrl)
	privateKeyStore := crypto.NewMockKeyStore(ctrl)
	nameResolver := vcr.NewMockFinder(ctrl)
	keyResolver := resolver.NewMockKeyResolver(ctrl)
	serviceResolver := didman.NewMockCompoundServiceResolver(ctrl)
	didResolver := resolver.NewMockDIDResolver(ctrl)
	verifier := verifier2.NewMockVerifier(ctrl)

	return &testContext{
		ctrl:            ctrl,
		contractNotary:  contractNotaryMock,
		keyStore:        privateKeyStore,
		keyResolver:     keyResolver,
		nameResolver:    nameResolver,
		serviceResolver: serviceResolver,
		verifier:        verifier,
		didResolver:     didResolver,
		oauthService: &authzServer{
			keyResolver:     keyResolver,
			contractNotary:  contractNotaryMock,
			privateKeyStore: privateKeyStore,
			vcFinder:        nameResolver,
			serviceResolver: serviceResolver,
			vcVerifier:      verifier,
			jsonldManager:   jsonld.NewTestJSONLDManager(t),
		},
		audit: audit.TestContext(),
	}
}
