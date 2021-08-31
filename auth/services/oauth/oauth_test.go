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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/didman"
	"github.com/nuts-foundation/nuts-node/vcr/credential"

	"net/url"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/vdr/doc"

	"testing"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/types"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/stretchr/testify/assert"
)

var actorSigningKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
var custodianSigningKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

var actorDID = *vdr.TestDIDB
var custodianDID = *vdr.TestDIDA
var custodianDIDDocument = getCustodianDIDDocument()
var actorSigningKeyID = getActorSigningKey()
var custodianSigningKeyID = getCustodianSigningKey()
var orgConceptName = concept.Concept{"organization": concept.Concept{"name": "Carebears", "city": "Caretown"}}

const expectedService = "unit-test"
const expectedAudience = "http://oauth"

func getActorSigningKey() *ssi.URI {
	serviceID, _ := ssi.ParseURI(actorDID.String() + "#signing-key")

	return serviceID
}

func getCustodianSigningKey() *ssi.URI {
	keyID, _ := ssi.ParseURI(custodianDID.String() + "#signing-key")

	return keyID
}

func getCustodianDIDDocument() *did.Document {
	id := custodianDID
	serviceID, _ := ssi.ParseURI(id.String() + "#service-id")

	doc := did.Document{
		ID: id,
	}
	signingKeyID := id
	signingKeyID.Fragment = "signing-key"
	key, err := did.NewVerificationMethod(signingKeyID, ssi.JsonWebKey2020, id, custodianSigningKey.Public())
	if err != nil {
		panic(err)
	}
	doc.AddAssertionMethod(key)
	doc.AddCapabilityInvocation(key)
	doc.Service = append(doc.Service, did.Service{
		ID:   *serviceID,
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
	t.Run("invalid jwt", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		response, err := ctx.oauthService.CreateAccessToken(services.CreateAccessTokenRequest{RawJwtBearerToken: "foo"})
		assert.Nil(t, response)
		if assert.NotNil(t, err) {
			assert.Contains(t, err.Error(), "jwt bearer token validation failed")
		}
	})

	t.Run("broken identity token", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()
		ctx.nameResolver.EXPECT().Get(concept.OrganizationConcept, false, actorDID.String()).MinTimes(1).Return(orgConceptName, nil)
		ctx.contractClientMock.EXPECT().VerifyVP(gomock.Any(), nil).Return(nil, errors.New("identity validation failed"))
		ctx.keyResolver.EXPECT().ResolveSigningKey(actorSigningKeyID.String(), gomock.Any()).MinTimes(1).Return(actorSigningKey.Public(), nil)
		ctx.keyResolver.EXPECT().ResolveSigningKeyID(custodianDID, gomock.Any()).MinTimes(1).Return(custodianSigningKeyID.String(), nil)
		ctx.privateKeyStore.EXPECT().Exists(custodianSigningKeyID.String()).Return(true)

		tokenCtx := validContext()
		signToken(tokenCtx)

		response, err := ctx.oauthService.CreateAccessToken(services.CreateAccessTokenRequest{RawJwtBearerToken: tokenCtx.rawJwtBearerToken})

		assert.Nil(t, response)
		if assert.NotNil(t, err) {
			assert.Contains(t, err.Error(), "identity validation failed")
		}
	})

	t.Run("JWT validity too long", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		ctx.keyResolver.EXPECT().ResolveSigningKey(actorSigningKeyID.String(), gomock.Any()).MinTimes(1).Return(actorSigningKey.Public(), nil)

		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Set(jwt.ExpirationKey, time.Now().Add(10*time.Second))
		signToken(tokenCtx)

		response, err := ctx.oauthService.CreateAccessToken(services.CreateAccessTokenRequest{RawJwtBearerToken: tokenCtx.rawJwtBearerToken})
		assert.Nil(t, response)
		if assert.NotNil(t, err) {
			assert.Contains(t, err.Error(), "JWT validity too long")
		}
	})

	t.Run("invalid identity token", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		ctx.nameResolver.EXPECT().Get(concept.OrganizationConcept, false, actorDID.String()).MinTimes(1).Return(orgConceptName, nil)
		ctx.privateKeyStore.EXPECT().Exists(custodianSigningKeyID.String()).Return(true)
		ctx.keyResolver.EXPECT().ResolveSigningKey(actorSigningKeyID.String(), gomock.Any()).MinTimes(1).Return(actorSigningKey.Public(), nil)
		ctx.keyResolver.EXPECT().ResolveSigningKeyID(custodianDID, gomock.Any()).MinTimes(1).Return(custodianSigningKeyID.String(), nil)
		ctx.contractClientMock.EXPECT().VerifyVP(gomock.Any(), nil).Return(&contract.VPVerificationResult{Validity: contract.Invalid}, nil)

		tokenCtx := validContext()
		signToken(tokenCtx)

		response, err := ctx.oauthService.CreateAccessToken(services.CreateAccessTokenRequest{RawJwtBearerToken: tokenCtx.rawJwtBearerToken})
		assert.Nil(t, response)
		if assert.NotNil(t, err) {
			assert.Contains(t, err.Error(), "identity validation failed")
		}
	})

	t.Run("valid - without user identity", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		ctx.keyResolver.EXPECT().ResolveSigningKey(actorSigningKeyID.String(), gomock.Any()).MinTimes(1).Return(actorSigningKey.Public(), nil)
		ctx.keyResolver.EXPECT().ResolveSigningKeyID(custodianDID, gomock.Any()).MinTimes(1).Return(custodianSigningKeyID.String(), nil)
		ctx.nameResolver.EXPECT().Get(concept.OrganizationConcept, false, actorDID.String()).MinTimes(1).Return(orgConceptName, nil)
		ctx.didResolver.EXPECT().Resolve(custodianDID, gomock.Any()).Return(getCustodianDIDDocument(), nil, nil).AnyTimes()
		ctx.serviceResolver.EXPECT().GetCompoundServiceEndpoint(custodianDID, expectedService, services.OAuthEndpointType, true).Return(expectedAudience, nil)
		ctx.privateKeyStore.EXPECT().Exists(custodianSigningKeyID.String()).Return(true)
		ctx.privateKeyStore.EXPECT().SignJWT(gomock.Any(), custodianSigningKeyID.String()).Return("expectedAccessToken", nil)
		ctx.vcValidator.EXPECT().Validate(gomock.Any(), true, gomock.Any()).Return(nil)

		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Remove(userIdentityClaim)
		signToken(tokenCtx)

		response, err := ctx.oauthService.CreateAccessToken(services.CreateAccessTokenRequest{RawJwtBearerToken: tokenCtx.rawJwtBearerToken})
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, "expectedAccessToken", response.AccessToken)
	})

	t.Run("valid - all fields", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		ctx.keyResolver.EXPECT().ResolveSigningKey(actorSigningKeyID.String(), gomock.Any()).MinTimes(1).Return(actorSigningKey.Public(), nil)
		ctx.keyResolver.EXPECT().ResolveSigningKeyID(custodianDID, gomock.Any()).MinTimes(1).Return(custodianSigningKeyID.String(), nil)
		ctx.nameResolver.EXPECT().Get(concept.OrganizationConcept, false, actorDID.String()).MinTimes(1).Return(orgConceptName, nil)
		ctx.didResolver.EXPECT().Resolve(custodianDID, gomock.Any()).Return(getCustodianDIDDocument(), nil, nil).AnyTimes()
		ctx.serviceResolver.EXPECT().GetCompoundServiceEndpoint(custodianDID, expectedService, services.OAuthEndpointType, true).Return(expectedAudience, nil)
		ctx.privateKeyStore.EXPECT().Exists(custodianSigningKeyID.String()).Return(true)
		ctx.privateKeyStore.EXPECT().SignJWT(gomock.Any(), custodianSigningKeyID.String()).Return("expectedAT", nil)
		ctx.contractClientMock.EXPECT().VerifyVP(gomock.Any(), nil).Return(&contract.VPVerificationResult{
			Validity:            contract.Valid,
			DisclosedAttributes: map[string]string{"name": "Henk de Vries"},
			ContractAttributes:  map[string]string{"legal_entity": "Carebears", "legal_entity_city": "Caretown"},
		}, nil)
		ctx.vcValidator.EXPECT().Validate(gomock.Any(), true, gomock.Any()).Return(nil)

		tokenCtx := validContext()
		signToken(tokenCtx)

		response, err := ctx.oauthService.CreateAccessToken(services.CreateAccessTokenRequest{RawJwtBearerToken: tokenCtx.rawJwtBearerToken})
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, "expectedAT", response.AccessToken)
	})
}

func TestService_validateIssuer(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		tokenCtx := validContext()
		ctx.keyResolver.EXPECT().ResolveSigningKey(actorSigningKeyID.String(), gomock.Any()).MinTimes(1).Return(actorSigningKey.Public(), nil)
		ctx.nameResolver.EXPECT().Get(concept.OrganizationConcept, false, actorDID.String()).Return(orgConceptName, nil)

		err := ctx.oauthService.validateIssuer(tokenCtx)
		assert.NoError(t, err)
		assert.Equal(t, "Carebears", tokenCtx.actorName)
	})
	t.Run("invalid issuer", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Set(jwt.IssuerKey, "not a urn")

		err := ctx.oauthService.validateIssuer(tokenCtx)
		assert.ErrorIs(t, err, did.ErrInvalidDID)
	})
	t.Run("unable to resolve name", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		tokenCtx := validContext()
		ctx.keyResolver.EXPECT().ResolveSigningKey(actorSigningKeyID.String(), gomock.Any()).MinTimes(1).Return(actorSigningKey.Public(), nil)
		ctx.nameResolver.EXPECT().Get(concept.OrganizationConcept, false, actorDID.String()).Return(nil, errors.New("failed"))

		err := ctx.oauthService.validateIssuer(tokenCtx)
		assert.EqualError(t, err, "invalid jwt.issuer: failed")
	})
	t.Run("unable to resolve name from credential", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()
		falseConceptName := concept.Concept{"no org": concept.Concept{"name": "Carebears"}}

		tokenCtx := validContext()
		ctx.keyResolver.EXPECT().ResolveSigningKey(actorSigningKeyID.String(), gomock.Any()).Return(actorSigningKey.Public(), nil)
		ctx.nameResolver.EXPECT().Get(concept.OrganizationConcept, false, actorDID.String()).Return(falseConceptName, nil)

		err := ctx.oauthService.validateIssuer(tokenCtx)
		assert.EqualError(t, err, "invalid jwt.issuer: actor has invalid organization VC: no value for given path")
	})
	t.Run("unable to resolve key", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		tokenCtx := validContext()

		ctx.keyResolver.EXPECT().ResolveSigningKey(actorSigningKeyID.String(), gomock.Any()).MinTimes(1).Return(nil, fmt.Errorf("not found"))

		err := ctx.oauthService.validateIssuer(tokenCtx)
		assert.EqualError(t, err, "invalid jwt.issuer key ID: not found")
	})
}

func TestService_validateSubject(t *testing.T) {
	t.Run("subject managed", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Set(jwt.SubjectKey, custodianDID.String())

		ctx.keyResolver.EXPECT().ResolveSigningKeyID(custodianDID, gomock.Any()).MinTimes(1).Return(custodianSigningKeyID.String(), nil)
		ctx.privateKeyStore.EXPECT().Exists(custodianSigningKeyID.String()).Return(true)

		err := ctx.oauthService.validateSubject(tokenCtx)
		assert.NoError(t, err)
	})
	t.Run("invalid subject", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Set(jwt.SubjectKey, "not a urn")

		err := ctx.oauthService.validateSubject(tokenCtx)
		assert.ErrorIs(t, err, did.ErrInvalidDID)
	})
	t.Run("subject not managed by this node", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Set(jwt.SubjectKey, custodianDID.String())

		ctx.keyResolver.EXPECT().ResolveSigningKeyID(custodianDID, gomock.Any()).MinTimes(1).Return(custodianSigningKeyID.String(), nil)
		ctx.privateKeyStore.EXPECT().Exists(custodianSigningKeyID.String()).Return(false)

		err := ctx.oauthService.validateSubject(tokenCtx)
		if assert.NotNil(t, err) {
			assert.Contains(t, err.Error(), "is not managed by this node")
		}
	})
}

func TestService_validatePurposeOfUse(t *testing.T) {
	t.Run("error - no purposeOfUser", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()
		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Remove(purposeOfUseClaim)

		err := ctx.oauthService.validatePurposeOfUse(tokenCtx)

		if !assert.Error(t, err) {
			return
		}

		assert.EqualError(t, err, "no purposeOfUse given")
	})
}

func TestService_validateAud(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()
		tokenCtx := validContext()
		ctx.didResolver.EXPECT().Resolve(custodianDID, gomock.Any()).Return(getCustodianDIDDocument(), nil, nil).AnyTimes()
		ctx.serviceResolver.EXPECT().GetCompoundServiceEndpoint(custodianDID, expectedService, services.OAuthEndpointType, true).Return(expectedAudience, nil)

		err := ctx.oauthService.validateAudience(tokenCtx)

		assert.NoError(t, err)
	})

	t.Run("error - no audience", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()
		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Set(jwt.AudienceKey, []string{})

		err := ctx.oauthService.validateAudience(tokenCtx)

		if !assert.Error(t, err) {
			return
		}

		assert.EqualError(t, err, "aud does not contain a single URI")
	})

	t.Run("error - endpoint resolve returns error", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()
		tokenCtx := validContext()
		ctx.serviceResolver.EXPECT().GetCompoundServiceEndpoint(custodianDID, expectedService, services.OAuthEndpointType, true).Return("", types.ErrNotFound)

		err := ctx.oauthService.validateAudience(tokenCtx)

		if !assert.Error(t, err) {
			return
		}

		assert.Equal(t, types.ErrNotFound, err)
	})

	t.Run("error - wrong audience", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()
		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Set(jwt.AudienceKey, []string{"not_the_right_audience"})
		ctx.serviceResolver.EXPECT().GetCompoundServiceEndpoint(custodianDID, expectedService, services.OAuthEndpointType, true).Return(expectedAudience, nil)

		err := ctx.oauthService.validateAudience(tokenCtx)

		if !assert.Error(t, err) {
			return
		}

		assert.EqualError(t, err, "aud does not contain correct endpoint URL")
	})
}

func TestService_validateAuthorizationCredentials(t *testing.T) {
	ctx := createContext(t)
	defer ctx.ctrl.Finish()

	t.Run("ok - no authorization credentials", func(t *testing.T) {
		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Remove(vcClaim)
		signToken(tokenCtx)

		err := ctx.oauthService.validateAuthorizationCredentials(*tokenCtx)

		assert.NoError(t, err)
	})

	t.Run("ok - empty list", func(t *testing.T) {
		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Set(vcClaim, []interface{}{})
		signToken(tokenCtx)

		err := ctx.oauthService.validateAuthorizationCredentials(*tokenCtx)

		assert.NoError(t, err)
	})

	t.Run("error - wrong vcs contents", func(t *testing.T) {
		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Set(vcClaim, "not a vc")
		signToken(tokenCtx)

		err := ctx.oauthService.validateAuthorizationCredentials(*tokenCtx)

		if !assert.Error(t, err) {
			return
		}
		assert.EqualError(t, err, "invalid jwt.vcs: field does not contain an array of credentials")
	})

	t.Run("error - wrong vcs contents 2", func(t *testing.T) {
		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Set(vcClaim, []interface{}{"}"})
		signToken(tokenCtx)

		err := ctx.oauthService.validateAuthorizationCredentials(*tokenCtx)

		if !assert.Error(t, err) {
			return
		}
		assert.EqualError(t, err, "invalid jwt.vcs: cannot unmarshal authorization credential: json: cannot unmarshal string into Go value of type map[string]interface {}")
	})

	t.Run("error - jwt.iss <> credentialSubject.ID mismatch", func(t *testing.T) {
		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Set(jwt.IssuerKey, "unknown")
		signToken(tokenCtx)
		ctx.vcValidator.EXPECT().Validate(gomock.Any(), true, gomock.Any()).Return(nil)

		err := ctx.oauthService.validateAuthorizationCredentials(*tokenCtx)

		if !assert.Error(t, err) {
			return
		}
		assert.EqualError(t, err, "credentialSubject.ID did:nuts:B8PUHs2AUHbFF1xLLK4eZjgErEcMXHxs68FteY7NDtCY of authorization credential with ID: did:nuts:GvkzxsezHvEc8nGhgz6Xo3jbqkHwswLmWw3CYtCm7hAW#1 does not match jwt.iss: unknown")
	})

	t.Run("error - jwt.sub <> issuer mismatch", func(t *testing.T) {
		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Set(jwt.SubjectKey, "unknown")
		signToken(tokenCtx)
		ctx.vcValidator.EXPECT().Validate(gomock.Any(), true, gomock.Any()).Return(nil)

		err := ctx.oauthService.validateAuthorizationCredentials(*tokenCtx)

		if !assert.Error(t, err) {
			return
		}
		assert.EqualError(t, err, "issuer did:nuts:GvkzxsezHvEc8nGhgz6Xo3jbqkHwswLmWw3CYtCm7hAW of authorization credential with ID: did:nuts:GvkzxsezHvEc8nGhgz6Xo3jbqkHwswLmWw3CYtCm7hAW#1 does not match jwt.sub: unknown")
	})

	t.Run("error - invalid credential", func(t *testing.T) {
		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Set(jwt.SubjectKey, "unknown")
		signToken(tokenCtx)
		ctx.vcValidator.EXPECT().Validate(gomock.Any(), true, gomock.Any()).Return(vcr.ErrRevoked)

		err := ctx.oauthService.validateAuthorizationCredentials(*tokenCtx)

		if !assert.Error(t, err) {
			return
		}
		assert.EqualError(t, err, "invalid jwt.vcs: credential is revoked")
	})
}

func TestService_parseAndValidateJwtBearerToken(t *testing.T) {
	ctx := createContext(t)
	defer ctx.ctrl.Finish()

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

		ctx.keyResolver.EXPECT().ResolveSigningKey(keyID, gomock.Any()).Return(privateKey.Public(), nil)

		// alg: RS256
		token := jwt.New()
		hdrs := jws.NewHeaders()
		hdrs.Set(jws.KeyIDKey, keyID)
		signedToken, err := jwt.Sign(token, jwa.RS256, privateKey, jwt.WithHeaders(hdrs))
		if !assert.NoError(t, err) {
			return
		}

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

		ctx.keyResolver.EXPECT().ResolveSigningKey(actorSigningKeyID.String(), gomock.Any()).Return(actorSigningKey.PublicKey, nil)

		err := ctx.oauthService.parseAndValidateJwtBearerToken(tokenCtx)
		assert.NoError(t, err)
		assert.Equal(t, actorDID.String(), tokenCtx.jwtBearerToken.Issuer())
		assert.Equal(t, actorSigningKeyID.String(), tokenCtx.kid)
	})
}

func TestService_buildAccessToken(t *testing.T) {
	t.Run("missing subject", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		tokenCtx := &validationContext{
			contractVerificationResult: &contract.VPVerificationResult{Validity: contract.Valid},
			jwtBearerToken:             jwt.New(),
		}

		token, err := ctx.oauthService.buildAccessToken(tokenCtx)
		assert.Empty(t, token)
		assert.EqualError(t, err, "could not build accessToken: subject is missing")
	})

	t.Run("build an access token", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		ctx.keyResolver.EXPECT().ResolveSigningKeyID(custodianDID, gomock.Any()).MinTimes(1).Return(custodianSigningKeyID.String(), nil)

		ctx.privateKeyStore.EXPECT().SignJWT(gomock.Any(), gomock.Any()).Return("expectedAT", nil)

		tokenCtx := &validationContext{
			contractVerificationResult: &contract.VPVerificationResult{Validity: contract.Valid},
			jwtBearerToken:             jwt.New(),
		}
		tokenCtx.jwtBearerToken.Set(jwt.SubjectKey, custodianDID.String())

		token, err := ctx.oauthService.buildAccessToken(tokenCtx)

		assert.Nil(t, err)
		assert.Equal(t, "expectedAT", token)
	})

	// todo some extra tests needed for claims generation
}

func TestService_CreateJwtBearerToken(t *testing.T) {
	sid := "789"
	usi := "irma identity token"

	request := services.CreateJwtGrantRequest{
		Custodian:     custodianDID.String(),
		Actor:         actorDID.String(),
		Subject:       &sid,
		IdentityToken: &usi,
		Service:       expectedService,
	}

	validCredential := vc.VerifiableCredential{
		Context:      []ssi.URI{vc.VCContextV1URI(), *credential.NutsContextURI},
		ID:           &ssi.URI{},
		Type:         []ssi.URI{*credential.NutsAuthorizationCredentialTypeURI, vc.VerifiableCredentialTypeV1URI()},
		Issuer:       vdr.TestDIDA.URI(),
		IssuanceDate: time.Now(),
		CredentialSubject: []interface{}{credential.NutsAuthorizationCredentialSubject{
			ID: vdr.TestDIDB.String(),
			LegalBase: credential.LegalBase{
				ConsentType: "implied",
			},
			PurposeOfUse: "eTransfer",
			Resources: []credential.Resource{
				{
					Path:        "/composition/1",
					Operations:  []string{"read"},
					UserContext: true,
				},
			},
		}},
		Proof: []interface{}{vc.Proof{}},
	}

	t.Run("create a JwtBearerToken", func(t *testing.T) {
		ctx := createContext(t)

		ctx.didResolver.EXPECT().Resolve(custodianDID, gomock.Any()).Return(custodianDIDDocument, nil, nil).AnyTimes()
		ctx.serviceResolver.EXPECT().GetCompoundServiceEndpoint(custodianDID, expectedService, services.OAuthEndpointType, true).Return(expectedAudience, nil)
		ctx.keyResolver.EXPECT().ResolveSigningKeyID(actorDID, gomock.Any()).MinTimes(1).Return(actorSigningKeyID.String(), nil)
		ctx.privateKeyStore.EXPECT().SignJWT(gomock.Any(), actorSigningKeyID.String()).Return("token", nil)

		token, err := ctx.oauthService.CreateJwtGrant(request)

		if !assert.Nil(t, err) || !assert.NotEmpty(t, token.BearerToken) {
			t.FailNow()
		}

		assert.Equal(t, "token", token.BearerToken)
	})

	t.Run("create a JwtBearerToken with valid credentials", func(t *testing.T) {
		ctx := createContext(t)

		ctx.didResolver.EXPECT().Resolve(custodianDID, gomock.Any()).Return(custodianDIDDocument, nil, nil).AnyTimes()
		ctx.serviceResolver.EXPECT().GetCompoundServiceEndpoint(custodianDID, expectedService, services.OAuthEndpointType, true).Return(expectedAudience, nil)
		ctx.keyResolver.EXPECT().ResolveSigningKeyID(actorDID, gomock.Any()).MinTimes(1).Return(actorSigningKeyID.String(), nil)
		ctx.privateKeyStore.EXPECT().SignJWT(gomock.Any(), actorSigningKeyID.String()).Return("token", nil)

		validRequest := request
		validRequest.Credentials = []vc.VerifiableCredential{validCredential}

		token, err := ctx.oauthService.CreateJwtGrant(validRequest)

		assert.NoError(t, err)
		assert.Equal(t, "token", token.BearerToken)
	})

	t.Run("create a JwtBearerToken with invalid credentials fails", func(t *testing.T) {
		ctx := createContext(t)

		invalidCredential := validCredential
		invalidCredential.Type = []ssi.URI{}

		invalidRequest := request
		invalidRequest.Credentials = []vc.VerifiableCredential{invalidCredential}

		ctx.didResolver.EXPECT().Resolve(custodianDID, gomock.Any()).Return(custodianDIDDocument, nil, nil).AnyTimes()

		token, err := ctx.oauthService.CreateJwtGrant(invalidRequest)

		assert.Error(t, err)
		assert.Empty(t, token)
	})

	t.Run("custodian without endpoint", func(t *testing.T) {
		ctx := createContext(t)
		document := getCustodianDIDDocument()
		document.Service = []did.Service{}

		ctx.serviceResolver.EXPECT().GetCompoundServiceEndpoint(custodianDID, expectedService, services.OAuthEndpointType, true).Return("", didman.ErrServiceNotFound)

		token, err := ctx.oauthService.CreateJwtGrant(request)

		assert.Empty(t, token)
		assert.ErrorIs(t, err, didman.ErrServiceNotFound)
	})

	t.Run("request without custodian", func(t *testing.T) {
		ctx := createContext(t)

		request := services.CreateJwtGrantRequest{
			Actor:         actorDID.String(),
			Subject:       &sid,
			IdentityToken: &usi,
		}

		token, err := ctx.oauthService.CreateJwtGrant(request)

		assert.Empty(t, token)
		assert.NotNil(t, err)
	})

	t.Run("signing error", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		ctx.didResolver.EXPECT().Resolve(custodianDID, gomock.Any()).Return(custodianDIDDocument, nil, nil).AnyTimes()
		ctx.serviceResolver.EXPECT().GetCompoundServiceEndpoint(custodianDID, expectedService, services.OAuthEndpointType, true).Return(expectedAudience, nil)
		ctx.keyResolver.EXPECT().ResolveSigningKeyID(actorDID, gomock.Any()).MinTimes(1).Return(actorSigningKeyID.String(), nil)
		ctx.privateKeyStore.EXPECT().SignJWT(gomock.Any(), actorSigningKeyID.String()).Return("", errors.New("boom!"))

		token, err := ctx.oauthService.CreateJwtGrant(request)

		assert.Error(t, err)
		assert.Empty(t, token)
	})
}

func Test_claimsFromRequest(t *testing.T) {
	ctx := createContext(t)
	defer ctx.ctrl.Finish()
	sid := "789"
	usi := "irma identity token"

	t.Run("ok", func(t *testing.T) {
		request := services.CreateJwtGrantRequest{
			Custodian:     custodianDID.String(),
			Actor:         actorDID.String(),
			Subject:       &sid,
			IdentityToken: &usi,
			Service:       "service",
		}
		audience := "aud"
		timeFunc = func() time.Time {
			return time.Unix(10, 0)
		}
		defer func() {
			timeFunc = time.Now
		}()

		claims := claimsFromRequest(request, audience)

		assert.Equal(t, audience, claims[jwt.AudienceKey])
		assert.Equal(t, int64(15), claims[jwt.ExpirationKey])
		assert.Equal(t, int64(10), claims[jwt.IssuedAtKey])
		assert.Equal(t, request.Actor, claims[jwt.IssuerKey])
		assert.Equal(t, 0, claims[jwt.NotBeforeKey])
		assert.Equal(t, request.Custodian, claims[jwt.SubjectKey])
		assert.Equal(t, *request.IdentityToken, claims["usi"])
		assert.Equal(t, *request.Subject, claims["sid"])
		assert.Equal(t, request.Service, claims[purposeOfUseClaim])
	})

	t.Run("ok - minimal", func(t *testing.T) {
		request := services.CreateJwtGrantRequest{
			Custodian: custodianDID.String(),
			Actor:     actorDID.String(),
			Service:   "service",
		}
		audience := "aud"
		claims := claimsFromRequest(request, audience)

		assert.Equal(t, audience, claims[jwt.AudienceKey])
		assert.Equal(t, request.Actor, claims[jwt.IssuerKey])
		assert.Equal(t, request.Custodian, claims[jwt.SubjectKey])
		assert.Equal(t, request.Service, claims[purposeOfUseClaim])
	})
}

func TestService_IntrospectAccessToken(t *testing.T) {
	t.Run("validate access token", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		ctx.keyResolver.EXPECT().ResolveSigningKey(actorSigningKeyID.String(), gomock.Any()).MinTimes(1).Return(actorSigningKey.Public(), nil)
		ctx.privateKeyStore.EXPECT().Exists(actorSigningKeyID.String()).Return(true)

		// First build an access token
		tokenCtx := validContext()
		signToken(tokenCtx)

		// Then validate it
		claims, err := ctx.oauthService.IntrospectAccessToken(tokenCtx.rawJwtBearerToken)
		if !assert.NoError(t, err) || !assert.NotNil(t, claims) {
			t.FailNow()
		}
	})

	t.Run("private key not present", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		ctx.privateKeyStore.EXPECT().Exists(actorSigningKeyID.String()).Return(false)

		// First build an access token
		tokenCtx := validContext()
		signToken(tokenCtx)

		// Then validate it
		_, err := ctx.oauthService.IntrospectAccessToken(tokenCtx.rawJwtBearerToken)
		assert.Error(t, err)
	})

	t.Run("key not present on DID", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		ctx.privateKeyStore.EXPECT().Exists(actorSigningKeyID.String()).Return(true)
		ctx.keyResolver.EXPECT().ResolveSigningKey(actorSigningKeyID.String(), gomock.Any()).MinTimes(1).Return(nil, types.ErrNotFound)

		// First build an access token
		tokenCtx := validContext()
		signToken(tokenCtx)

		// Then validate it
		_, err := ctx.oauthService.IntrospectAccessToken(tokenCtx.rawJwtBearerToken)
		assert.Error(t, err)
	})
}

func TestAuth_Configure(t *testing.T) {
	t.Run("ok - config valid", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		assert.NoError(t, ctx.oauthService.Configure())
	})
}

func TestAuth_GetOAuthEndpointURL(t *testing.T) {
	t.Run("returns_error_when_resolve_compound_service_fails", func(t *testing.T) {
		ctx := createContext(t)

		ctx.serviceResolver.EXPECT().GetCompoundServiceEndpoint(*vdr.TestDIDA, expectedService, services.OAuthEndpointType, true).Return("", didman.ErrServiceNotFound)

		parsedURL, err := ctx.oauthService.GetOAuthEndpointURL(expectedService, *vdr.TestDIDA)

		assert.ErrorIs(t, err, didman.ErrServiceNotFound)
		assert.Empty(t, parsedURL)
	})

	t.Run("returns_parsed_endpoint_url", func(t *testing.T) {
		ctx := createContext(t)
		keyID, _ := did.ParseDIDURL("did:nuts:123#key-1")
		currentDIDDocument := &did.Document{
			Service: []did.Service{
				{
					Type: "test-service",
					ServiceEndpoint: map[string]string{
						"oauth": fmt.Sprintf("%s?type=oauth", vdr.TestDIDA),
					},
				},
				{
					Type:            "oauth",
					ServiceEndpoint: "http://localhost",
				},
			},
		}
		currentDIDDocument.AddCapabilityInvocation(&did.VerificationMethod{ID: *keyID})
		expectedURL, _ := url.Parse("http://localhost")
		ctx.serviceResolver.EXPECT().GetCompoundServiceEndpoint(*vdr.TestDIDA, expectedService, services.OAuthEndpointType, true).Return(expectedURL.String(), nil)

		parsedURL, err := ctx.oauthService.GetOAuthEndpointURL(expectedService, *vdr.TestDIDA)

		assert.NoError(t, err)
		assert.Equal(t, *expectedURL, parsedURL)
	})
}

func validContext() *validationContext {
	sid := "subject"
	usi := base64.StdEncoding.EncodeToString([]byte("irma identity token"))

	cred := credential.ValidExplicitNutsAuthorizationCredential()
	credString, _ := json.Marshal(cred)
	credMap := map[string]interface{}{}
	_ = json.Unmarshal(credString, &credMap)

	claims := map[string]interface{}{
		jwt.AudienceKey:   expectedAudience,
		jwt.ExpirationKey: time.Now().Add(5 * time.Second).Unix(),
		jwt.JwtIDKey:      "a005e81c-6749-4967-b01c-495228fcafb4",
		jwt.IssuedAtKey:   time.Now().UTC(),
		jwt.IssuerKey:     actorDID.String(),
		jwt.NotBeforeKey:  0,
		jwt.SubjectKey:    custodianDID.String(),
		userIdentityClaim: usi,
		subjectIDClaim:    sid,
		purposeOfUseClaim: expectedService,
		vcClaim:           []interface{}{credMap},
	}
	token := jwt.New()
	for k, v := range claims {
		if err := token.Set(k, v); err != nil {
			panic(err)
		}
	}
	return &validationContext{
		jwtBearerToken: token,
		kid:            actorSigningKeyID.String(),
		purposeOfUse:   expectedService,
	}
}

func signToken(context *validationContext) {
	hdrs := jws.NewHeaders()
	err := hdrs.Set(jws.KeyIDKey, actorSigningKeyID.String())
	if err != nil {
		panic(err)
	}
	signedToken, err := jwt.Sign(context.jwtBearerToken, jwa.ES256, actorSigningKey, jwt.WithHeaders(hdrs))
	if err != nil {
		panic(err)
	}
	context.rawJwtBearerToken = string(signedToken)
}

type testContext struct {
	ctrl               *gomock.Controller
	contractClientMock *services.MockContractClient
	privateKeyStore    *crypto.MockKeyStore
	nameResolver       *vcr.MockConceptFinder
	vcValidator        *vcr.MockValidator
	didResolver        *types.MockStore
	keyResolver        *types.MockKeyResolver
	serviceResolver    *didman.MockServiceResolver
	oauthService       *service
}

var createContext = func(t *testing.T) *testContext {
	ctrl := gomock.NewController(t)

	contractClientMock := services.NewMockContractClient(ctrl)
	privateKeyStore := crypto.NewMockKeyStore(ctrl)
	nameResolver := vcr.NewMockConceptFinder(ctrl)
	vcValidator := vcr.NewMockValidator(ctrl)
	keyResolver := types.NewMockKeyResolver(ctrl)
	serviceResolver := didman.NewMockServiceResolver(ctrl)
	didResolver := types.NewMockStore(ctrl)

	return &testContext{
		ctrl:               ctrl,
		contractClientMock: contractClientMock,
		privateKeyStore:    privateKeyStore,
		keyResolver:        keyResolver,
		nameResolver:       nameResolver,
		serviceResolver:    serviceResolver,
		vcValidator:        vcValidator,
		didResolver:        didResolver,
		oauthService: &service{
			docResolver:     doc.Resolver{Store: didResolver},
			keyResolver:     keyResolver,
			contractClient:  contractClientMock,
			privateKeyStore: privateKeyStore,
			conceptFinder:   nameResolver,
			serviceResolver: serviceResolver,
			vcValidator:     vcValidator,
		},
	}
}
