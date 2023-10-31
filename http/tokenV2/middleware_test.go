/*
 * Copyright (C) 2023 Nuts community
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

package tokenV2

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/core"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/audit"

	"golang.org/x/crypto/ssh"

	"github.com/labstack/echo/v4"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/google/uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const validHostname = "test.local"
const invalidHostname = "bad.local"
const validUser = "test@test.local"
const invalidUser = "nottest@test.local"

const unauthorized = "Unauthorized"
const ok = "OK"

// generateEd25519TestKey generates a new private key for use in testing also returning a jwt serializer and the ssh authorized_keys representation
func generateEd25519TestKey(t *testing.T) (jwk.Key, *jwt.Serializer, []byte) {
	// Generate a new ed25519 key
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	// Convert the public key to an ssh key, generating an authorized key representation
	sshPub, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	sshAuthKey := fmt.Sprintf("%v %v %v", sshPub.Type(), b64.StdEncoding.EncodeToString(sshPub.Marshal()), validUser)

	// Convert the base key type to a jwk type
	jwkKey, err := jwk.FromRaw(priv)
	require.NoError(t, err)

	// Set the key ID for the jwk to be the public key fingerprint
	err = jwkKey.Set(jwk.KeyIDKey, ssh.FingerprintSHA256(sshPub))
	require.NoError(t, err)

	// Create a serializer configured to use the generated key
	serializer := jwt.NewSerializer().Sign(jwt.WithKey(jwa.EdDSA, jwkKey))

	t.Logf("authorized_key = %v", sshAuthKey)

	// Return the jwk and authorized_key representation
	return jwkKey, serializer, []byte(sshAuthKey)
}

// generateECDSATestKey generates a new private key for use in testing also returning a jwt serializer and the ssh authorized_keys representation
func generateECDSATestKey(t *testing.T, curve elliptic.Curve, signingAlgorithm jwa.SignatureAlgorithm) (jwk.Key, *jwt.Serializer, []byte) {
	// Generate a new ECDSA key
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)

	// Convert the public key to an ssh key, generating an authorized key representation
	sshPub, err := ssh.NewPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	sshAuthKey := fmt.Sprintf("%v %v %v", sshPub.Type(), b64.StdEncoding.EncodeToString(sshPub.Marshal()), validUser)

	// Convert the base key type to a jwk type
	jwkKey, err := jwk.FromRaw(priv)
	require.NoError(t, err)

	// Set the key ID for the jwk to be the public key fingerprint
	err = jwkKey.Set(jwk.KeyIDKey, ssh.FingerprintSHA256(sshPub))
	require.NoError(t, err)

	// Create a serializer configured to use the generated key
	serializer := jwt.NewSerializer().Sign(jwt.WithKey(signingAlgorithm, jwkKey))

	t.Logf("authorized_key = %v", sshAuthKey)

	// Return the jwk and authorized_key representation
	return jwkKey, serializer, []byte(sshAuthKey)
}

// generateRSATestKey generates a new RSA private key for use in testing also returning a jwt serializer and the ssh authorized_keys representation
func generateRSATestKey(t *testing.T, bits int, signingAlgorithm jwa.SignatureAlgorithm) (jwk.Key, *jwt.Serializer, []byte) {
	// Generate a new ed25519 key
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)

	// Convert the public key to an ssh key, generating an authorized key representation
	sshPub, err := ssh.NewPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	sshAuthKey := fmt.Sprintf("%v %v %s", sshPub.Type(), b64.StdEncoding.EncodeToString(sshPub.Marshal()), validUser)

	// Convert the base key type to a jwk type
	jwkKey, err := jwk.FromRaw(priv)
	require.NoError(t, err)

	// Set the key ID for the jwk to be the public key fingerprint
	err = jwkKey.Set(jwk.KeyIDKey, ssh.FingerprintSHA256(sshPub))
	require.NoError(t, err)

	// Create a serializer configured to use the generated key
	serializer := jwt.NewSerializer().Sign(jwt.WithKey(signingAlgorithm, jwkKey))

	t.Logf("authorized_key = %v", sshAuthKey)

	// Return the jwk and authorized_key representation
	return jwkKey, serializer, []byte(sshAuthKey)
}

// validJWT returns a valid JWT for the specified host
func validJWT(t *testing.T) jwt.Token {
	issuedAt := time.Now()
	notBefore := issuedAt
	expires := notBefore.Add(time.Second * time.Duration(5))
	token, err := jwt.NewBuilder().
		Issuer("test@test.local").
		Subject("test@test.local").
		Audience([]string{validHostname}).
		IssuedAt(issuedAt).
		NotBefore(notBefore).
		Expiration(expires).
		JwtID(uuid.NewString()).
		Build()
	require.NoError(t, err)
	return token
}

// statusOKHandler sets a simple 200 OK response on an echo context
func statusOKHandler(context echo.Context) error {
	context.String(http.StatusOK, ok)
	return nil
}

// TestAuditLogAccessKeyRegistered ensures that key authorization events are audit logged
func TestAuditLogAccessKeyRegistered(t *testing.T) {
	// Generate a new test key and jwt serializer
	_, _, authorizedKeys := generateEd25519TestKey(t)

	// Setup audit log capturing
	capturedAuditLog := audit.CaptureLogs(t)

	// Create the middleware
	_, err := New(nil, validHostname, []byte(authorizedKeys))
	require.NoError(t, err)

	// Ensure the audit logging is working
	capturedAuditLog.AssertContains(t, "http", audit.AccessKeyRegisteredEvent, validHostname, fmt.Sprintf("Registered key: %s", authorizedKeys))
}

// TestAuditLogAccessDenied ensures that access denied events are audit logged
func TestAuditLogAccessDenied(t *testing.T) {
	// Generate a new test key and jwt serializer
	_, serializer, _ := generateEd25519TestKey(t)

	// Create a new JWT
	token := validJWT(t)

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(""))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Bearer %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Setup audit log capturing
	capturedAuditLog := audit.CaptureLogs(t)

	// Call the handler, ensuring the appropriate error is returned
	httpErr := handler(testCtx).(*echo.HTTPError)
	assert.Error(t, httpErr)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
	assert.Equal(t, unauthorized, httpErr.Message)

	// Ensure the audit logging is working
	capturedAuditLog.AssertContains(t, "http", audit.AccessDeniedEvent, "unknown", "Access denied: credential not signed by an authorized key")
}

// TestAuditLogAccessGranted ensures that access granted events are audit logged
func TestAuditLogAccessGranted(t *testing.T) {
	// Generate a new test key and jwt serializer
	_, serializer, authorizedKey := generateEd25519TestKey(t)

	// Create a new JWT
	token := validJWT(t)

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(authorizedKey))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Bearer %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Setup audit log capturing
	capturedAuditLog := audit.CaptureLogs(t)

	// Call the handler, ensuring no error is returned
	err = handler(testCtx)
	assert.NoError(t, err)

	// Ensure the 200 OK response is present
	require.NotNil(t, testCtx.Response())
	assert.Equal(t, http.StatusOK, recorder.Result().StatusCode)
	assert.Equal(t, ok, recorder.Body.String())

	// Ensure the audit logging is working
	jwtID, _ := token.Get(jwt.JwtIDKey)
	subject, _ := token.Get(jwt.SubjectKey)
	issuer, _ := token.Get(jwt.IssuerKey)
	capturedAuditLog.AssertContains(t, "http", audit.AccessGrantedEvent, validUser, fmt.Sprintf("Access granted to user '%v' with JWT %s issued to %s by %s", validUser, jwtID, subject, issuer))
}

// TestValidJWTEd25519 ensures a valid JWT signed by an Ed25519 key authorizes a request
func TestValidJWTEd25519(t *testing.T) {
	// Generate a new test key and jwt serializer
	_, serializer, authorizedKey := generateEd25519TestKey(t)

	// Create a new JWT
	token := validJWT(t)

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(authorizedKey))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Bearer %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring no error is returned
	err = handler(testCtx)
	assert.NoError(t, err)

	// Ensure the 200 OK response is present
	require.NotNil(t, testCtx.Response())
	assert.Equal(t, http.StatusOK, recorder.Result().StatusCode)
	assert.Equal(t, ok, recorder.Body.String())
}

// TestValidJWTEd25519JWKFingerprint ensures a valid JWT signed by an Ed25519 key identified by its JWK fingerprint rather than SSH fingerprint authorizes a request
func TestValidJWTEd25519JWKFingerprint(t *testing.T) {
	// Generate a new test key and jwt serializer
	key, serializer, authorizedKey := generateEd25519TestKey(t)

	// Modify the key to use the JWK type fingerprint instead of SSH fingerprint
	require.NoError(t, key.Remove(jwk.KeyIDKey))
	require.NoError(t, jwk.AssignKeyID(key))

	// Create a new JWT
	token := validJWT(t)

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(authorizedKey))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Bearer %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring no error is returned
	err = handler(testCtx)
	assert.NoError(t, err)

	// Ensure the 200 OK response is present
	require.NotNil(t, testCtx.Response())
	assert.Equal(t, http.StatusOK, recorder.Result().StatusCode)
	assert.Equal(t, ok, recorder.Body.String())
}

// TestValidJWTSingleAudience ensures a valid JWT containing a single audience as a string value results in a 200 OK
func TestValidJWTSingleAudience(t *testing.T) {
	// Generate a new test key and jwt serializer
	_, serializer, authorizedKey := generateEd25519TestKey(t)

	// Create a new JWT
	token := validJWT(t)
	token.Set(jwt.AudienceKey, validHostname)

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(authorizedKey))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Bearer %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring no error is returned
	err = handler(testCtx)
	assert.NoError(t, err)

	// Ensure the 200 OK response is present
	require.NotNil(t, testCtx.Response())
	assert.Equal(t, http.StatusOK, recorder.Result().StatusCode)
	assert.Equal(t, ok, recorder.Body.String())
}

// TestInvalidSingleAudience ensures a valid JWT containing a single audience as a string value results in a 401 Unauthorized
func TestInvalidSingleAudience(t *testing.T) {
	// Generate a new test key and jwt serializer
	_, serializer, authorizedKey := generateEd25519TestKey(t)

	// Create a new JWT
	token := validJWT(t)
	token.Set(jwt.AudienceKey, invalidHostname)

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware
	middleware, err := New(nil, validHostname, authorizedKey)
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Bearer %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring the appropriate error is returned
	err = handler(testCtx)
	require.Error(t, err)
	assert.Contains(t, err.(*echo.HTTPError).Internal.Error(), "jwt.Validate: \"aud\" not satisfied")
}

// TestValidIssProxiedSub ensures a valid JWT containing a subject mentioning a proxied username results in a 200 OK
func TestValidIssProxiedSub(t *testing.T) {
	// Generate a new test key and jwt serializer
	_, serializer, authorizedKey := generateEd25519TestKey(t)

	// Create a new JWT, setting the subject to some random value
	token := validJWT(t)
	token.Set(jwt.SubjectKey, fmt.Sprintf("%s@somecompany.com", uuid.NewString()))

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(authorizedKey))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Bearer %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring no error is returned
	err = handler(testCtx)
	assert.NoError(t, err)

	// Ensure the 200 OK response is present
	require.NotNil(t, testCtx.Response())
	assert.Equal(t, http.StatusOK, recorder.Result().StatusCode)
	assert.Equal(t, ok, recorder.Body.String())
}

// TestInvalidIss ensures a valid JWT containing the wrong issuer results in a 401 Unauthorized
func TestInvalidIss(t *testing.T) {
	// Generate a new test key and jwt serializer
	_, serializer, authorizedKey := generateEd25519TestKey(t)

	// Create a new JWT with the wrong subject
	token := validJWT(t)
	token.Set(jwt.IssuerKey, invalidUser)

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(authorizedKey))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Bearer %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring the appropriate error is returned
	err = handler(testCtx)
	require.Error(t, err)
	expectedErrorMessage := fmt.Sprintf("expected issuer (%s) does not match iss", validUser)
	assert.Contains(t, err.(*echo.HTTPError).Internal.Error(), expectedErrorMessage)
}

// TestEmptySub ensures a valid JWT containing an empty subject results in a 401 Unauthorized
func TestEmptySub(t *testing.T) {
	// Generate a new test key and jwt serializer
	_, serializer, authorizedKey := generateEd25519TestKey(t)

	// Create a new JWT with the wrong subject
	token := validJWT(t)
	token.Set(jwt.SubjectKey, "")

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(authorizedKey))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Bearer %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring the appropriate error is returned
	err = handler(testCtx)
	require.Error(t, err)
	assert.Contains(t, err.(*echo.HTTPError).Internal.Error(), "insecure credential: sub must not be empty")
}

// TestValidJWTCaseInsensitiveBearer ensures a valid JWT placed in a strangely cased authorization header authorizes a request
func TestValidJWTCaseInsensitiveBearer(t *testing.T) {
	// Generate a new test key and jwt serializer
	_, serializer, authorizedKey := generateEd25519TestKey(t)

	// Create a new JWT
	token := validJWT(t)

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(authorizedKey))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("bEaReR %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring no error is returned
	err = handler(testCtx)
	assert.NoError(t, err)
}

// TestValidJWTECDSAES256 ensures a valid JWT signed by an ECDSA 256-bit key authorizes a request
func TestValidJWTECDSAES256(t *testing.T) {
	// Generate a new test key and jwt serializer
	_, serializer, authorizedKey := generateECDSATestKey(t, elliptic.P256(), jwa.ES256)

	// Create a new JWT
	token := validJWT(t)

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(authorizedKey))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Bearer %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring no error is returned
	err = handler(testCtx)
	assert.NoError(t, err)
}

// TestValidJWTECDSAES384 ensures a valid JWT signed by an ECDSA 384-bit key authorizes a request
func TestValidJWTECDSAES384(t *testing.T) {
	// Generate a new test key and jwt serializer
	_, serializer, authorizedKey := generateECDSATestKey(t, elliptic.P384(), jwa.ES384)

	// Create a new JWT
	token := validJWT(t)

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(authorizedKey))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Bearer %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring no error is returned
	err = handler(testCtx)
	assert.NoError(t, err)
}

// TestValidJWTECDSAES384 ensures a valid JWT signed by an ECDSA 384-bit key authorizes a request
func TestValidJWTECDSAES512(t *testing.T) {
	// Generate a new test key and jwt serializer
	_, serializer, authorizedKey := generateECDSATestKey(t, elliptic.P521(), jwa.ES512)

	// Create a new JWT
	token := validJWT(t)

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(authorizedKey))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Bearer %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring no error is returned
	err = handler(testCtx)
	assert.NoError(t, err)
}

// TestWrongAudienceJWT ensures a JWT with the wrong audience from an authorized key causes 401 Unauthorized
func TestWrongAudienceJWT(t *testing.T) {
	// Generate a new test key and jwt serializer
	_, serializer, authorizedKey := generateEd25519TestKey(t)

	// Create a new JWT (with an invalid audience)
	token := validJWT(t)
	token.Set(jwt.AudienceKey, []string{invalidHostname})

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(authorizedKey))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Bearer %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring the appropriate error is returned
	err = handler(testCtx)
	require.Error(t, err)
	assert.Contains(t, err.(*echo.HTTPError).Internal.Error(), "jwt.Validate: \"aud\" not satisfied")
}

// TestWrongKeyID ensures a JWT with the wrong kid from an authorized key causes 401 Unauthorized
func TestWrongKeyID(t *testing.T) {
	// Generate a new test key and jwt serializer
	key, serializer, authorizedKey := generateEd25519TestKey(t)

	// Create a new JWT (with an invalid audience)
	token := validJWT(t)
	token.Set(jwt.AudienceKey, []string{invalidHostname})

	// Set the key id to something invalid that the middleware will not be able to locate in its in-memory database
	require.NoError(t, key.Set(jwk.KeyIDKey, "invalid-key-id"))

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(authorizedKey))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Bearer %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring the appropriate error is returned
	err = handler(testCtx)
	assert.Error(t, err)
	assert.Contains(t, err.(*echo.HTTPError).Internal.Error(), "credential not signed by an authorized key")
}

// TestCorrectKeyIDWithIncorrectSignature ensures a JWT signed by an unknown key but claiming to be signed by a known key results in 401 Unauthorized
func TestCorrectKeyIDWithIncorrectSignature(t *testing.T) {
	// Generate a new test key and jwt serializer
	trustedKey, _, authorizedKey := generateEd25519TestKey(t)

	// Generate a new test key and jwt serializer
	untrustedKey, untrustedSerializer, _ := generateEd25519TestKey(t)

	// Create a new valid JWT
	token := validJWT(t)

	// Sign and serialize the JWT with the untrusted key, setting the key id to a trusted key
	trustedKeyID, found := trustedKey.Get(jwk.KeyIDKey)
	require.True(t, found)
	require.NoError(t, untrustedKey.Set(jwk.KeyIDKey, trustedKeyID))
	serialized, err := untrustedSerializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(authorizedKey))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Bearer %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring the appropriate error is returned
	err = handler(testCtx)
	assert.Error(t, err)
	assert.Contains(t, err.(*echo.HTTPError).Internal.Error(), "credential not signed by an authorized key")
}

// TestExpiredJWT ensures an expired JWT from an authorized key causes 401 Unauthorized
func TestExpiredJWT(t *testing.T) {
	// Generate a new test key and jwt serializer
	_, serializer, authorizedKey := generateEd25519TestKey(t)

	// Create a new JWT which expired in the past
	token := validJWT(t)
	past := time.Now().Add(time.Second * time.Duration(-5))
	err := token.Set(jwt.ExpirationKey, past)
	require.NoError(t, err)

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware
	middleware, err := New(nil, validHostname, authorizedKey)
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Bearer %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring the appropriate error is returned
	err = handler(testCtx)
	assert.Error(t, err)
	assert.Contains(t, err.(*echo.HTTPError).Internal.Error(), "jwt.Validate: \"exp\" not satisfied")
}

// TestFutureIATJWT ensures a not yet valid (iat = future) JWT from an authorized key causes 401 Unauthorized
func TestFutureIATJWT(t *testing.T) {
	// Generate a new test key and jwt serializer
	_, serializer, authorizedKey := generateEd25519TestKey(t)

	// Craft the JWT such that it is not yet valid
	future := time.Now().Add(time.Second * time.Duration(60))

	// Create a new JWT with a future IssuedAt date
	token := validJWT(t)
	err := token.Set(jwt.IssuedAtKey, future)
	require.NoError(t, err)

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(authorizedKey))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Bearer %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring the appropriate error is returned
	err = handler(testCtx)
	require.Error(t, err)
	assert.Contains(t, err.(*echo.HTTPError).Internal.Error(), "jwt.Validate: \"iat\" not satisfied")
}

// TestFutureNBFJWT ensures a not yet valid (nbf = future) JWT from an authorized key causes 401 Unauthorized
func TestFutureNBFJWT(t *testing.T) {
	// Generate a new test key and jwt serializer
	_, serializer, authorizedKey := generateEd25519TestKey(t)

	// Craft the JWT such that it is not yet valid
	future := time.Now().Add(time.Second * time.Duration(60))

	// Create a new JWT with a future NotBefore date
	token := validJWT(t)
	err := token.Set(jwt.NotBeforeKey, future)
	require.NoError(t, err)

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(authorizedKey))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Bearer %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring the appropriate error is returned
	err = handler(testCtx)
	require.Error(t, err)
	assert.Contains(t, err.(*echo.HTTPError).Internal.Error(), "jwt.Validate: \"nbf\" not satisfied")
}

// TestUnauthorizedKey ensures a valid JWT signed by an unauthorized key is rejected with 401 Unauthorized
func TestUnauthorizedKey(t *testing.T) {
	// Generate a new test key and jwt serializer
	_, serializer, _ := generateEd25519TestKey(t)

	// Generate another key which will be used for authorized_keys
	_, _, authorizedKey := generateEd25519TestKey(t)

	// Create a new JWT
	token := validJWT(t)

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware, trusting a key other than the one used to sign the JWT
	middleware, err := New(nil, validHostname, []byte(authorizedKey))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Bearer %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring the appropriate error is returned
	err = handler(testCtx)
	require.Error(t, err)
	assert.Contains(t, err.(*echo.HTTPError).Internal.Error(), "credential not signed by an authorized key")
}

// TestNoAuthorizedKeys ensures middleware with an empty authorized keys rejects a signed JWT
func TestNoAuthorizedKeys(t *testing.T) {
	// Generate a new test key and jwt serializer
	_, serializer, _ := generateEd25519TestKey(t)

	// Create a new JWT
	token := validJWT(t)

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware, trusting a key other than the one used to sign the JWT
	middleware, err := New(nil, validHostname, []byte(""))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Bearer %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring the appropriate error is returned
	err = handler(testCtx)
	require.Error(t, err)
	assert.Contains(t, err.(*echo.HTTPError).Internal.Error(), "credential not signed by an authorized key")
}

// TestMissingAuthorizationHeader ensures a request with a missing authorization header gets a 401 Unauthorized response
func TestMissingAuthorizationHeader(t *testing.T) {
	// Generate a new test key and jwt serializer
	_, serializer, authorizedKey := generateEd25519TestKey(t)

	// Create a new JWT
	token := validJWT(t)

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware, trusting a key other than the one used to sign the JWT
	middleware, err := New(nil, validHostname, []byte(authorizedKey))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request with no Authorization header
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring the appropriate error is returned
	err = handler(testCtx)
	require.Error(t, err)
	assert.Contains(t, err.(*echo.HTTPError).Internal.Error(), "missing/malformed credential")
}

// TestMalformedAuthorizationHeader ensures a request with a malformed authorization header gets a 401 Unauthorized response
func TestMalformedAuthorizationHeader(t *testing.T) {
	// Generate a new test key and jwt serializer
	_, serializer, authorizedKey := generateEd25519TestKey(t)

	// Create a new JWT
	token := validJWT(t)

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware, trusting a key other than the one used to sign the JWT
	middleware, err := New(nil, validHostname, []byte(authorizedKey))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request with no Authorization header
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Bearer BAD %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring the appropriate error is returned
	err = handler(testCtx)
	require.Error(t, err)
	assert.Contains(t, err.(*echo.HTTPError).Internal.Error(), "missing/malformed credential")
}

// TestNonBearerToken ensures a request with a non-bearer authorization header gets a 401 Unauthorized response
func TestNonBearerToken(t *testing.T) {
	// Generate a new test key and jwt serializer
	_, serializer, authorizedKey := generateEd25519TestKey(t)

	// Create a new JWT
	token := validJWT(t)

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware, trusting a key other than the one used to sign the JWT
	middleware, err := New(nil, validHostname, []byte(authorizedKey))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request with no Authorization header
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Basic %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring the appropriate error is returned
	err = handler(testCtx)
	require.Error(t, err)
	assert.Contains(t, err.(*echo.HTTPError).Internal.Error(), "missing/malformed credential")
}

// TestInsecureRS256JWT ensures a JWT signed insecurely with an RS256 signing algorithm is rejected with a 401 Unauthorized response.
// The RS512 signing algorithm is a suitable alternative, or better yet do not use RSA keys at all.
func TestInsecureRS256JWT(t *testing.T) {
	// Generate a new test key and jwt serializer
	_, serializer, authorizedKey := generateRSATestKey(t, 4096, jwa.RS256)

	// Create a new JWT
	token := validJWT(t)

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(authorizedKey))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Bearer %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring no error is returned
	err = handler(testCtx)
	require.Error(t, err)
	assert.Contains(t, err.(*echo.HTTPError).Internal.Error(), "insecure credential: signing algorithm RS256 is not permitted")
}

// TestInsecureRS384JWT ensures a JWT signed insecurely with an RS384 signing algorithm is rejected with a 401 Unauthorized response.
// The RS512 signing algorithm is a suitable alternative, or better yet do not use RSA keys at all.
func TestInsecureRS384JWT(t *testing.T) {
	// Generate a new test key and jwt serializer
	_, serializer, authorizedKey := generateRSATestKey(t, 4096, jwa.RS384)

	// Create a new JWT
	token := validJWT(t)

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(authorizedKey))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Bearer %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring no error is returned
	err = handler(testCtx)
	require.Error(t, err)
	assert.Contains(t, err.(*echo.HTTPError).Internal.Error(), "insecure credential: signing algorithm RS384 is not permitted")
}

// TestInsecure1024BitRS512JWT ensures a JWT signed securely with an RS512 signing algorithm but using an insecure 1024-bit RSA key is rejected with a 401 Unauthorized response
func TestInsecure1024BitRS512JWT(t *testing.T) {
	// Generate a new test key and jwt serializer
	_, serializer, authorizedKey := generateRSATestKey(t, 1024, jwa.RS512)

	// Create a new JWT
	token := validJWT(t)

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(authorizedKey))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Bearer %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring no error is returned
	err = handler(testCtx)
	require.Error(t, err)

	// Note that this error may seem a bit strange, but the key is not authorized as 1024-bit RSA keys should never make their way
	// into the authorized keys list in memory. This technically doesn't provide the best guarantee as to the reason for failure
	// in this unit test but it is the best that can be done at the time and it is likely not desirable for the 1024-bit RSA key
	// to be loaded into the list in memory anyways. We take a small chance here but it's an extreme corner case and as long as
	// we are careful when modifying this test, this should be sufficient along with the tests in authorized_keys_test.go which
	// ensure the keys are rejected at that level.
	assert.Contains(t, err.(*echo.HTTPError).Internal.Error(), "credential not signed by an authorized key")
}

// TestSecureRS512JWT ensures a JWT signed securely with an RS512 signing algorithm and a 4096-bit RSA key is accepted with a 200 OK response
func TestSecureRS512JWT(t *testing.T) {
	// Generate a new test key and jwt serializer
	_, serializer, authorizedKey := generateRSATestKey(t, 4096, jwa.RS512)

	// Create a new JWT
	token := validJWT(t)

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(authorizedKey))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Bearer %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring no error is returned
	err = handler(testCtx)
	require.NoError(t, err)

	// Ensure the 200 OK response is present
	require.NotNil(t, testCtx.Response())
	assert.Equal(t, http.StatusOK, recorder.Result().StatusCode)
	assert.Equal(t, ok, recorder.Body.String())
}

// TestPS256JWT ensures a JWT signed with a PS256 signing algorithm results in a 401 Unauthorized response.
// The PS512 signing algorithm is a suitable alternative and is supported, or better yet do not use RSA keys
// at all.
func TestPS256JWT(t *testing.T) {
	// Generate a new test key and jwt serializer
	_, serializer, authorizedKey := generateRSATestKey(t, 4096, jwa.PS256)

	// Create a new JWT
	token := validJWT(t)

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(authorizedKey))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Bearer %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring no error is returned
	err = handler(testCtx)
	require.Error(t, err)
	assert.Contains(t, err.(*echo.HTTPError).Internal.Error(), "insecure credential: signing algorithm PS256 is not permitted")
}

// TestPS384JWT ensures a JWT signed with a PS384 signing algorithm results in a 401 Unauthorized response.
// The PS512 signing algorithm is a suitable alternative and is supported, or better yet do not use RSA keys
// at all.
func TestPS384JWT(t *testing.T) {
	// Generate a new test key and jwt serializer
	_, serializer, authorizedKey := generateRSATestKey(t, 4096, jwa.PS384)

	// Create a new JWT
	token := validJWT(t)

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(authorizedKey))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Bearer %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring no error is returned
	err = handler(testCtx)
	require.Error(t, err)
	assert.Contains(t, err.(*echo.HTTPError).Internal.Error(), "insecure credential: signing algorithm PS384 is not permitted")
}

// TestSecurePS512JWT ensures a JWT signed securely with an RS512 signing algorithm and a 4096-bit RSA key is accepted with a 200 OK response
func TestSecurePS512JWT(t *testing.T) {
	// Generate a new test key and jwt serializer
	_, serializer, authorizedKey := generateRSATestKey(t, 4096, jwa.PS512)

	// Create a new JWT
	token := validJWT(t)

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(authorizedKey))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Bearer %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring no error is returned
	err = handler(testCtx)
	require.NoError(t, err)

	// Ensure the 200 OK response is present
	require.NotNil(t, testCtx.Response())
	assert.Equal(t, http.StatusOK, recorder.Result().StatusCode)
	assert.Equal(t, ok, recorder.Body.String())
}

// TestHS256JWT ensures an HS256 signed JWT is rejected with a 401 Unauthorized response
func TestHS256JWT(t *testing.T) {
	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(""))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.M4GTX4kpyuK-nthSEEgwCjmP8xVGJsW7kQh5CMY5CmM"
	header := fmt.Sprintf("Bearer %v", token)
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring no error is returned
	err = handler(testCtx)
	require.Error(t, err)
	assert.Contains(t, err.(*echo.HTTPError).Internal.Error(), "insecure credential: signing algorithm HS256 is not permitted")
}

// TestHS384JWT ensures an HS384 signed JWT is rejected with a 401 Unauthorized response
func TestHS384JWT(t *testing.T) {
	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(""))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	token := "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KlhAYnODU2I87_7bafWOb1UAOOxoPAyTt3Qxm0NRMiB7vIj3mRTfHNzdTU8sTaYp"
	header := fmt.Sprintf("Bearer %v", token)
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring no error is returned
	err = handler(testCtx)
	require.Error(t, err)
	assert.Contains(t, err.(*echo.HTTPError).Internal.Error(), "insecure credential: signing algorithm HS384 is not permitted")
}

// TestHS512JWT ensures an HS384 signed JWT is rejected with a 401 Unauthorized response
func TestHS512JWT(t *testing.T) {
	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(""))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	token := "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.D6rYXV3Phv0vymZodiEcztZfXnhvaV14h7hrWG_MJht2NxuxKZ2_-wjg3S_oimWfz0LaF_Uazma1GPA2A_LHDg"
	header := fmt.Sprintf("Bearer %v", token)
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring no error is returned
	err = handler(testCtx)
	require.Error(t, err)
	assert.Contains(t, err.(*echo.HTTPError).Internal.Error(), "insecure credential: signing algorithm HS512 is not permitted")
}

// TestNoneAlgUnsignedJWT ensures a JWT signed with the "none" algorithm is rejected with a 401 Unauthorized response
func TestNoneAlgUnsignedJWT(t *testing.T) {
	// Use a "none" signed JWT, which is extremely dangerous and a classic JWT attack
	serialized := []byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJpZCI6MSwiaWF0IjoxNTczMzU4Mzk2fQ.")
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(""))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Bearer %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring no error is returned
	err = handler(testCtx)
	require.Error(t, err)
	assert.Contains(t, err.(*echo.HTTPError).Internal.Error(), "insecure credential: signing algorithm none is not permitted")
}

// TestMissingAud ensures a JWT with a missing audience is rejected with 401 Unauthorized
func TestMissingAud(t *testing.T) {
	// Generate a new test key and jwt serializer
	_, serializer, authorizedKey := generateEd25519TestKey(t)

	// Create a new JWT without a jti
	token := validJWT(t)
	err := token.Remove(jwt.AudienceKey)
	require.NoError(t, err)

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(authorizedKey))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Bearer %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring the appropriate error is returned
	err = handler(testCtx)
	require.Error(t, err)
	assert.Contains(t, err.(*echo.HTTPError).Internal.Error(), "jwt.Validate: claim \"aud\" not found")
}

// TestMissingIss ensures a JWT with a missing issuer is rejected with 401 Unauthorized
func TestMissingIss(t *testing.T) {
	// Generate a new test key and jwt serializer
	_, serializer, authorizedKey := generateEd25519TestKey(t)

	// Create a new JWT without a jti
	token := validJWT(t)
	err := token.Remove(jwt.IssuerKey)
	require.NoError(t, err)

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(authorizedKey))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Bearer %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring the appropriate error is returned
	err = handler(testCtx)
	require.Error(t, err)
	assert.Contains(t, err.(*echo.HTTPError).Internal.Error(), "insecure credential: missing field: iss")
}

// TestMissingSub ensures a JWT with a missing subject is rejected with 401 Unauthorized
func TestMissingSub(t *testing.T) {
	// Generate a new test key and jwt serializer
	_, serializer, authorizedKey := generateEd25519TestKey(t)

	// Create a new JWT without a jti
	token := validJWT(t)
	err := token.Remove(jwt.SubjectKey)
	require.NoError(t, err)

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(authorizedKey))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Bearer %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring the appropriate error is returned
	err = handler(testCtx)
	require.Error(t, err)
	assert.Contains(t, err.(*echo.HTTPError).Internal.Error(), "insecure credential: missing field: sub")
}

// TestMissingJTI ensures a JWT with a missing JwtID is rejected with 401 Unauthorized
func TestMissingJTI(t *testing.T) {
	// Generate a new test key and jwt serializer
	_, serializer, authorizedKey := generateEd25519TestKey(t)

	// Create a new JWT without a jti
	token := validJWT(t)
	err := token.Remove(jwt.JwtIDKey)
	require.NoError(t, err)

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(authorizedKey))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Bearer %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring the appropriate error is returned
	err = handler(testCtx)
	require.Error(t, err)
	assert.Contains(t, err.(*echo.HTTPError).Internal.Error(), "insecure credential: missing field: jti")
}

// TestNonUUIDJTI ensures a JWT with a non-UUID jti results in 401 Unauthorized
func TestNonUUIDJTI(t *testing.T) {
	// Generate a new test key and jwt serializer
	_, serializer, authorizedKey := generateEd25519TestKey(t)

	// Create a new JWT with a simple, static jti
	token := validJWT(t)
	err := token.Set(jwt.JwtIDKey, "foo")
	require.NoError(t, err)

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(authorizedKey))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Bearer %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring the appropriate error is returned
	err = handler(testCtx)
	require.Error(t, err)
	assert.Contains(t, err.(*echo.HTTPError).Internal.Error(), "insecure credential: token jti is not a valid uuid")
}

// TestMissingIAT ensures a JWT with a missing IssuedAt is rejected with 401 Unauthorized
func TestMissingIAT(t *testing.T) {
	// Generate a new test key and jwt serializer
	_, serializer, authorizedKey := generateEd25519TestKey(t)

	// Create a new JWT without an iat
	token := validJWT(t)
	err := token.Remove(jwt.IssuedAtKey)
	require.NoError(t, err)

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(authorizedKey))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Bearer %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring the appropriate error is returned
	err = handler(testCtx)
	require.Error(t, err)
	assert.Contains(t, err.(*echo.HTTPError).Internal.Error(), "insecure credential: missing field: iat")
}

// TestMissingEXP ensures a JWT with a missing Expiration is rejected with 401 Unauthorized
func TestMissingEXP(t *testing.T) {
	// Generate a new test key and jwt serializer
	_, serializer, authorizedKey := generateEd25519TestKey(t)

	// Create a new JWT with a future NotBefore date
	token := validJWT(t)
	err := token.Remove(jwt.ExpirationKey)
	require.NoError(t, err)

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(authorizedKey))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Bearer %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring the appropriate error is returned
	err = handler(testCtx)
	require.Error(t, err)
	assert.Contains(t, err.(*echo.HTTPError).Internal.Error(), "insecure credential: missing field: exp")
}

// TestMissingNBF ensures a JWT with a missing NotBefore is rejected with 401 Unauthorized
func TestMissingNBF(t *testing.T) {
	// Generate a new test key and jwt serializer
	_, serializer, authorizedKey := generateEd25519TestKey(t)

	// Create a new JWT with a future NotBefore date
	token := validJWT(t)
	err := token.Remove(jwt.NotBeforeKey)
	require.NoError(t, err)

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(authorizedKey))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Bearer %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring the appropriate error is returned
	err = handler(testCtx)
	require.Error(t, err)
	assert.Contains(t, err.(*echo.HTTPError).Internal.Error(), "insecure credential: missing field: nbf")
}

// TestExpiresLongAfterNotBeforeJWT ensures a JWT with a long duration (Expiration-NotBefore) is rejected with 401 Unauthorized
func TestExpiresLongAfterNotBeforeJWT(t *testing.T) {
	// Generate a new test key and jwt serializer
	_, serializer, authorizedKey := generateEd25519TestKey(t)

	// Create a new JWT with a NotBefore 24 hours after IssuedAt and an expiration 36 hours after IssuedAt.
	// Normally this 12 hour validity period would be accepted, but in this case the token expires too long
	// after it is issued and therefore must be rejected.
	token := validJWT(t)
	notBefore := time.Now()
	issuedAt := notBefore
	expiration := notBefore.Add(time.Hour * time.Duration(36))
	require.NoError(t, token.Set(jwt.NotBeforeKey, notBefore))
	require.NoError(t, token.Set(jwt.IssuedAtKey, issuedAt))
	require.NoError(t, token.Set(jwt.ExpirationKey, expiration))

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(authorizedKey))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Bearer %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring the appropriate error is returned
	err = handler(testCtx)
	require.Error(t, err)
	assert.Contains(t, err.(*echo.HTTPError).Internal.Error(), "insecure credential: token expires too long after nbf")
}

// TestExpiresLongAfterIssuedAtJWT ensures a JWT with a long duration (Expiration-IssuedAt) is rejected with 401 Unauthorized
func TestExpiresLongAfterIssuedAtJWT(t *testing.T) {
	// Generate a new test key and jwt serializer
	_, serializer, authorizedKey := generateEd25519TestKey(t)

	// Create a new JWT with a NotBefore 24 hours after IssuedAt and an expiration 36 hours after IssuedAt.
	// Normally this 12 hour validity period would be accepted, but in this case the token expires too long
	// after it is issued and therefore must be rejected.
	token := validJWT(t)
	notBefore := time.Now()
	issuedAt := notBefore.Add(time.Hour * time.Duration(-24))
	expiration := notBefore.Add(time.Hour * time.Duration(12))
	require.NoError(t, token.Set(jwt.NotBeforeKey, notBefore))
	require.NoError(t, token.Set(jwt.IssuedAtKey, issuedAt))
	require.NoError(t, token.Set(jwt.ExpirationKey, expiration))

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(authorizedKey))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Bearer %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring the appropriate error is returned
	err = handler(testCtx)
	require.Error(t, err)
	assert.Contains(t, err.(*echo.HTTPError).Internal.Error(), "insecure credential: token expires too long after iat")
}

// TestNotBeforePriorToIssuedAt ensures a JWT with a NotBefore date prior to the IssuedAt date is rejected with 401 Unauthorized
func TestNotBeforePriorToIssuedAt(t *testing.T) {
	// Generate a new test key and jwt serializer
	_, serializer, authorizedKey := generateEd25519TestKey(t)

	// Create a new JWT with a NotBefore 24 hours after IssuedAt and an expiration 36 hours after IssuedAt.
	// Normally this 12 hour validity period would be accepted, but in this case the token expires too long
	// after it is issued and therefore must be rejected.
	token := validJWT(t)
	issuedAt := time.Now()
	notBefore := issuedAt.Add(time.Hour * time.Duration(-1))
	expiration := notBefore.Add(time.Hour * time.Duration(12))
	require.NoError(t, token.Set(jwt.IssuedAtKey, issuedAt))
	require.NoError(t, token.Set(jwt.NotBeforeKey, notBefore))
	require.NoError(t, token.Set(jwt.ExpirationKey, expiration))

	// Sign and serialize the JWT
	serialized, err := serializer.Serialize(token)
	require.NoError(t, err)
	t.Logf("jwt=%v", string(serialized))

	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(authorizedKey))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	header := fmt.Sprintf("Bearer %v", string(serialized))
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring the appropriate error is returned
	err = handler(testCtx)
	require.Error(t, err)
	assert.Contains(t, err.(*echo.HTTPError).Internal.Error(), "insecure credential: token nbf occurs before iat")
}

// TestRepeatedACharAuthorizationHeader ensures a request with a very long Authorization header (lots of A characters) results in a 401 Unauthorized response
func TestRepeatedACharAuthorizationHeader(t *testing.T) {
	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(""))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	token := ""
	for len(token) < 99999 {
		token += "A"
	}
	header := fmt.Sprintf("Bearer %v", token)
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring the appropriate error is returned
	err = handler(testCtx)
	require.Error(t, err)
	assert.Contains(t, err.(*echo.HTTPError).Internal.Error(), "insecure credential: credential is too long")
}

// TestNOPSledAuthorizationHeader ensures a request with a very long Authorization header (repeated 0x90 bytes) results in a 401 Unauthorized response
func TestNOPSledAuthorizationHeader(t *testing.T) {
	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(""))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	token := []byte("")
	for len(token) < 99999 {
		// 0x90 is an encoded NOP instruction on x86/amd64 and thus serves as a common NOP sled
		token = append(token, 0x90)
	}
	header := fmt.Sprintf("Bearer %v", token)
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring the appropriate error is returned
	err = handler(testCtx)
	require.Error(t, err)
	assert.Contains(t, err.(*echo.HTTPError).Internal.Error(), "missing/malformed credential")
}

// TestLongB64TripletAuthorizationHeader ensures a request with a very long Authorization header (a long base64 triplet) results in a 401 Unauthorized response
func TestLongB64TripletAuthorizationHeader(t *testing.T) {
	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(""))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	encodedES512Header := "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9"
	raw := make(map[string]string)
	raw["A"] = ""
	for len(raw["A"]) < 99999 {
		raw["A"] += "A"
	}
	jsonEncoded, err := json.Marshal(raw)
	require.NoError(t, err)
	b64Encoded := b64.RawURLEncoding.EncodeToString(jsonEncoded)
	header := fmt.Sprintf("Bearer %v.%v.%v", encodedES512Header, b64Encoded, b64Encoded)
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring the appropriate error is returned
	err = handler(testCtx)
	require.Error(t, err)
	assert.Contains(t, err.(*echo.HTTPError).Internal.Error(), "insecure credential: credential is too long")
}

// TestB64JSONNOPSledAuthorizationHeader ensures a request with a Base64+JSON encoded NOP sled Authorization header results in a 401 Unauthorized response
func TestB64JSONNOPSledAuthorizationHeader(t *testing.T) {
	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(""))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	encodedES512Header := "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9"
	raw := make(map[string][]byte)
	raw["NOP"] = []byte("")
	for len(raw["NOP"]) < 8096 {
		raw["NOP"] = append(raw["NOP"], 0x90)
	}
	jsonEncoded, err := json.Marshal(raw)
	require.NoError(t, err)
	b64Encoded := b64.RawURLEncoding.EncodeToString(jsonEncoded)
	header := fmt.Sprintf("Bearer %v.%v.%v", encodedES512Header, b64Encoded, b64Encoded)
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring the appropriate error is returned
	err = handler(testCtx)
	require.Error(t, err)
	assert.Contains(t, err.(*echo.HTTPError).Internal.Error(), "insecure credential: credential is too long")
}

// TestB64NOPSledAuthorizationHeader ensures a request with a Base64 encoded NOP sled Authorization header results in a 401 Unauthorized response
func TestB64NOPSledAuthorizationHeader(t *testing.T) {
	// Create the middleware
	middleware, err := New(nil, validHostname, []byte(""))
	require.NoError(t, err)

	// Setup the handler such that if the middleware authorizes the request a 200 OK response is set
	handler := middleware.Handler(statusOKHandler)

	// Create a test GET request
	request, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)

	// Set the authorization header in the test request
	encodedES512Header := "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9"
	raw := []byte{}
	for len(raw) < 8096 {
		raw = append(raw, 0x90)
	}
	b64Encoded := b64.RawURLEncoding.EncodeToString(raw)
	header := fmt.Sprintf("Bearer %v.%v.%v", encodedES512Header, b64Encoded, b64Encoded)
	request.Header.Set("Authorization", header)

	// Setup a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the handler, ensuring the appropriate error is returned
	err = handler(testCtx)
	require.Error(t, err)
	assert.Contains(t, err.(*echo.HTTPError).Internal.Error(), "insecure credential: credential is too long")
}

func Test_unauthorizedError(t *testing.T) {
	// Create a test GET request
	request, _ := http.NewRequest("GET", "/", nil)

	// Create a test context which wraps the test request and records the response
	recorder := httptest.NewRecorder()
	testCtx := echo.New().NewContext(request, recorder)

	// Call the unauthorizedError function, ensuring the appropriate error is returned
	err := unauthorizedError(testCtx, errors.New("error"))
	require.Error(t, err)
	errorWriter := testCtx.Get(core.ErrorWriterContextKey)
	require.NotNil(t, errorWriter)
	assert.Equal(t, unauthorizedErrorWriter{}, *errorWriter.(*unauthorizedErrorWriter))
	assert.Equal(t, http.StatusUnauthorized, err.Code)
	assert.Equal(t, "Unauthorized", err.Message)
	assert.Contains(t, err.Internal.Error(), "error")
}
