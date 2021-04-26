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
	"errors"
	"fmt"

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

var actorDID = *vdr.TestDIDA
var custodianDID = *vdr.TestDIDB
var custodianDIDDocument = getCustodianDIDDocument()
var actorSigningKeyID = getActorSigningKey()
var custodianSigningKeyID = getCustodianSigningKey()
var orgConceptName = concept.Concept{"organization": concept.Concept{"name": "Carebears", "city": "Caretown"}}

func getActorSigningKey() *ssi.URI {
	serviceID, _ := ssi.ParseURI(actorDID.String() + "#signing-key")

	return serviceID
}

func getCustodianSigningKey() *ssi.URI {
	keyID, _ := ssi.ParseURI(custodianDID.String() + "#signing-key")

	return keyID
}

func getCustodianDIDDocument() *did.Document {
	id := *vdr.TestDIDB
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
		ctx.nameResolver.EXPECT().Get(concept.OrganizationConcept, actorDID.String()).MinTimes(1).Return(orgConceptName, nil)
		ctx.contractClientMock.EXPECT().VerifyVP(gomock.Any(), nil).Return(nil, errors.New("identity validation failed"))
		ctx.keyResolver.EXPECT().ResolveSigningKey(actorSigningKeyID.String(), gomock.Any()).MinTimes(1).Return(actorSigningKey.Public(), nil)
		ctx.keyResolver.EXPECT().ResolveSigningKeyID(custodianDID, gomock.Any()).MinTimes(1).Return(custodianSigningKeyID.String(), nil)
		ctx.privateKeyStore.EXPECT().PrivateKeyExists(custodianSigningKeyID.String()).Return(true)

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

		ctx.nameResolver.EXPECT().Get(concept.OrganizationConcept, actorDID.String()).MinTimes(1).Return(orgConceptName, nil)
		ctx.privateKeyStore.EXPECT().PrivateKeyExists(custodianSigningKeyID.String()).Return(true)
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

	t.Run("valid - with legal base", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		ctx.keyResolver.EXPECT().ResolveSigningKey(actorSigningKeyID.String(), gomock.Any()).MinTimes(1).Return(actorSigningKey.Public(), nil)
		ctx.keyResolver.EXPECT().ResolveSigningKeyID(custodianDID, gomock.Any()).MinTimes(1).Return(custodianSigningKeyID.String(), nil)
		ctx.nameResolver.EXPECT().Get(concept.OrganizationConcept, actorDID.String()).MinTimes(1).Return(orgConceptName, nil)
		ctx.didResolver.EXPECT().Resolve(custodianDID, gomock.Any()).Return(getCustodianDIDDocument(), nil, nil).AnyTimes()
		ctx.privateKeyStore.EXPECT().PrivateKeyExists(custodianSigningKeyID.String()).Return(true)
		ctx.privateKeyStore.EXPECT().SignJWT(gomock.Any(), custodianSigningKeyID.String()).Return("expectedAT", nil)
		ctx.contractClientMock.EXPECT().VerifyVP(gomock.Any(), nil).Return(&contract.VPVerificationResult{
			Validity:            contract.Valid,
			DisclosedAttributes: map[string]string{"name": "Henk de Vries"},
			ContractAttributes:  map[string]string{"legal_entity": "Carebears", "legal_entity_city": "Caretown"},
		}, nil)

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
		ctx.nameResolver.EXPECT().Get(concept.OrganizationConcept, actorDID.String()).Return(orgConceptName, nil)

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
		if assert.NotNil(t, err) {
			assert.Contains(t, err.Error(), "invalid jwt.issuer: input does not begin with 'did:' prefix")
		}
	})
	t.Run("unable to resolve name", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		tokenCtx := validContext()
		ctx.keyResolver.EXPECT().ResolveSigningKey(actorSigningKeyID.String(), gomock.Any()).MinTimes(1).Return(actorSigningKey.Public(), nil)
		ctx.nameResolver.EXPECT().Get(concept.OrganizationConcept, actorDID.String()).Return(nil, errors.New("failed"))

		err := ctx.oauthService.validateIssuer(tokenCtx)
		assert.EqualError(t, err, "invalid jwt.issuer: failed")
	})
	t.Run("unable to resolve name from credential", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()
		falseConceptName := concept.Concept{"no org": concept.Concept{"name": "Carebears"}}

		tokenCtx := validContext()
		ctx.keyResolver.EXPECT().ResolveSigningKey(actorSigningKeyID.String(), gomock.Any()).Return(actorSigningKey.Public(), nil)
		ctx.nameResolver.EXPECT().Get(concept.OrganizationConcept, actorDID.String()).Return(falseConceptName, nil)

		err := ctx.oauthService.validateIssuer(tokenCtx)
		assert.EqualError(t, err, "invalid jwt.issuer: actor has invalid organization VC")
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
		ctx.privateKeyStore.EXPECT().PrivateKeyExists(custodianSigningKeyID.String()).Return(true)

		err := ctx.oauthService.validateSubject(tokenCtx)
		assert.NoError(t, err)
	})
	t.Run("invalid subject", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Set(jwt.SubjectKey, "not a urn")

		err := ctx.oauthService.validateSubject(tokenCtx)
		if assert.NotNil(t, err) {
			assert.Contains(t, err.Error(), "invalid jwt.subject: input does not begin with 'did:' prefix")
		}
	})
	t.Run("subject not managed by this node", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Set(jwt.SubjectKey, custodianDID.String())

		ctx.keyResolver.EXPECT().ResolveSigningKeyID(custodianDID, gomock.Any()).MinTimes(1).Return(custodianSigningKeyID.String(), nil)
		ctx.privateKeyStore.EXPECT().PrivateKeyExists(custodianSigningKeyID.String()).Return(false)

		err := ctx.oauthService.validateSubject(tokenCtx)
		if assert.NotNil(t, err) {
			assert.Contains(t, err.Error(), "is not managed by this node")
		}
	})
}

func TestService_validateAud(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()
		tokenCtx := validContext()
		ctx.didResolver.EXPECT().Resolve(custodianDID, gomock.Any()).Return(getCustodianDIDDocument(), nil, nil).AnyTimes()

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

	t.Run("error - resolve returns error", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()
		tokenCtx := validContext()
		ctx.didResolver.EXPECT().Resolve(custodianDID, gomock.Any()).Return(nil, nil, types.ErrNotFound)

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
		ctx.didResolver.EXPECT().Resolve(custodianDID, gomock.Any()).Return(getCustodianDIDDocument(), nil, nil).AnyTimes()

		err := ctx.oauthService.validateAudience(tokenCtx)

		if !assert.Error(t, err) {
			return
		}

		assert.EqualError(t, err, "aud does not contain correct endpoint identifier for subject")
	})
}

func TestOAuthService_parseAndValidateJwtBearerToken(t *testing.T) {
	ctx := createContext(t)
	defer ctx.ctrl.Finish()

	t.Run("malformed JWTs", func(t *testing.T) {
		tokenCtx := &validationContext{
			rawJwtBearerToken: "foo",
		}
		err := ctx.oauthService.parseAndValidateJwtBearerToken(tokenCtx)
		assert.Nil(t, tokenCtx.jwtBearerTokenClaims)
		assert.Equal(t, "invalid compact serialization format: invalid number of segments", err.Error())

		tokenCtx2 := &validationContext{
			rawJwtBearerToken: "123.456.787",
		}
		err = ctx.oauthService.parseAndValidateJwtBearerToken(tokenCtx2)
		assert.Nil(t, tokenCtx.jwtBearerTokenClaims)
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
		assert.Nil(t, tokenCtx.jwtBearerTokenClaims)
		assert.Equal(t, "token signing algorithm is not supported: RS256", err.Error())
	})

	t.Run("valid token", func(t *testing.T) {
		tokenCtx := validContext()
		signToken(tokenCtx)

		ctx.keyResolver.EXPECT().ResolveSigningKey(actorSigningKeyID.String(), gomock.Any()).Return(actorSigningKey.PublicKey, nil)

		err := ctx.oauthService.parseAndValidateJwtBearerToken(tokenCtx)
		assert.NoError(t, err)
		assert.Equal(t, actorDID.String(), tokenCtx.jwtBearerToken.Issuer())
		assert.Equal(t, actorSigningKeyID.String(), tokenCtx.jwtBearerTokenClaims.KeyID)
	})
}

func TestOAuthService_buildAccessToken(t *testing.T) {
	t.Run("missing subject", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		tokenCtx := &validationContext{
			contractVerificationResult: &contract.VPVerificationResult{Validity: contract.Valid},
			jwtBearerTokenClaims:       &services.NutsJwtBearerToken{},
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
			jwtBearerTokenClaims:       &services.NutsJwtBearerToken{},
			jwtBearerToken:             jwt.New(),
		}
		tokenCtx.jwtBearerToken.Set(jwt.SubjectKey, custodianDID.String())

		token, err := ctx.oauthService.buildAccessToken(tokenCtx)

		assert.Nil(t, err)
		assert.Equal(t, "expectedAT", token)
	})

	// todo some extra tests needed for claims generation
}

func TestOAuthService_CreateJwtBearerToken(t *testing.T) {
	sid := "789"
	usi := "irma identity token"

	request := services.CreateJwtBearerTokenRequest{
		Custodian:     custodianDID.String(),
		Actor:         actorDID.String(),
		Subject:       &sid,
		IdentityToken: &usi,
		Service:       "service",
	}

	t.Run("create a JwtBearerToken", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		ctx.didResolver.EXPECT().Resolve(custodianDID, gomock.Any()).Return(custodianDIDDocument, nil, nil).AnyTimes()
		ctx.keyResolver.EXPECT().ResolveSigningKeyID(actorDID, gomock.Any()).MinTimes(1).Return(actorSigningKeyID.String(), nil)
		ctx.privateKeyStore.EXPECT().SignJWT(gomock.Any(), actorSigningKeyID.String()).Return("token", nil)

		token, err := ctx.oauthService.CreateJwtBearerToken(request)

		if !assert.Nil(t, err) || !assert.NotEmpty(t, token.BearerToken) {
			t.FailNow()
		}
		assert.Equal(t, "token", token.BearerToken)
	})

	t.Run("custodian without endpoint", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		ctx.didResolver.EXPECT().Resolve(custodianDID, gomock.Any()).Return(&did.Document{}, nil, nil)

		token, err := ctx.oauthService.CreateJwtBearerToken(request)

		assert.Empty(t, token)
		assert.Contains(t, err.Error(), "service not found")
	})

	t.Run("request without custodian", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		request := services.CreateJwtBearerTokenRequest{
			Actor:         actorDID.String(),
			Subject:       &sid,
			IdentityToken: &usi,
		}

		token, err := ctx.oauthService.CreateJwtBearerToken(request)

		assert.Empty(t, token)
		assert.NotNil(t, err)
	})

	t.Run("signing error", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		ctx.didResolver.EXPECT().Resolve(custodianDID, gomock.Any()).Return(custodianDIDDocument, nil, nil).AnyTimes()
		ctx.keyResolver.EXPECT().ResolveSigningKeyID(actorDID, gomock.Any()).MinTimes(1).Return(actorSigningKeyID.String(), nil)
		ctx.privateKeyStore.EXPECT().SignJWT(gomock.Any(), actorSigningKeyID.String()).Return("", errors.New("boom!"))

		token, err := ctx.oauthService.CreateJwtBearerToken(request)

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
		request := services.CreateJwtBearerTokenRequest{
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
		assert.Equal(t, request.Service, claims[services.JWTService])
	})
}

func TestOAuthService_IntrospectAccessToken(t *testing.T) {

	t.Run("validate access token", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		ctx.keyResolver.EXPECT().ResolveSigningKey(actorSigningKeyID.String(), gomock.Any()).MinTimes(1).Return(actorSigningKey.Public(), nil)
		ctx.privateKeyStore.EXPECT().PrivateKeyExists(actorSigningKeyID.String()).Return(true)

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

		ctx.privateKeyStore.EXPECT().PrivateKeyExists(actorSigningKeyID.String()).Return(false)

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

		ctx.privateKeyStore.EXPECT().PrivateKeyExists(actorSigningKeyID.String()).Return(true)
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

func validContext() *validationContext {
	serviceID, _ := ssi.ParseURI(custodianDID.String() + "#service-id")
	sid := "subject"
	usi := base64.StdEncoding.EncodeToString([]byte("irma identity token"))
	claims := services.NutsJwtBearerToken{
		UserIdentity: &usi,
		SubjectID:    &sid,
		KeyID:        actorSigningKeyID.String(),
		Service:      "service",
	}
	hdrs := map[string]interface{}{
		jwt.AudienceKey:   serviceID.String(),
		jwt.ExpirationKey: time.Now().Add(5 * time.Second).Unix(),
		jwt.JwtIDKey:      "a005e81c-6749-4967-b01c-495228fcafb4",
		jwt.IssuedAtKey:   time.Now().UTC(),
		jwt.IssuerKey:     actorDID.String(),
		jwt.NotBeforeKey:  0,
		jwt.SubjectKey:    custodianDID.String(),
	}
	token := jwt.New()
	for k, v := range hdrs {
		if err := token.Set(k, v); err != nil {
			panic(err)
		}
	}
	return &validationContext{
		jwtBearerTokenClaims: &claims,
		jwtBearerToken:       token,
	}
}

func signToken(context *validationContext) {
	claimsAsMap, _ := context.jwtBearerTokenClaims.AsMap()
	for k, v := range claimsAsMap {
		if err := context.jwtBearerToken.Set(k, v); err != nil {
			panic(err)
		}
	}
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
	didResolver        *types.MockStore
	keyResolver        *types.MockKeyResolver
	oauthService       *service
}

var createContext = func(t *testing.T) *testContext {
	ctrl := gomock.NewController(t)

	contractClientMock := services.NewMockContractClient(ctrl)
	privateKeyStore := crypto.NewMockKeyStore(ctrl)
	nameResolver := vcr.NewMockConceptFinder(ctrl)
	keyResolver := types.NewMockKeyResolver(ctrl)
	didResolver := types.NewMockStore(ctrl)
	return &testContext{
		ctrl:               ctrl,
		contractClientMock: contractClientMock,
		privateKeyStore:    privateKeyStore,
		keyResolver:        keyResolver,
		nameResolver:       nameResolver,
		didResolver:        didResolver,
		oauthService: &service{
			docResolver:     doc.Resolver{didResolver},
			keyResolver:     keyResolver,
			contractClient:  contractClientMock,
			privateKeyStore: privateKeyStore,
			conceptFinder:   nameResolver,
		},
	}
}
