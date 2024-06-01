/*
 * Copyright (C) 2024 Nuts community
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

package dpop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/crypto/jwx"
)

const (
	// ATHKey is the claim key of the ath JWT claim for a DPoP token
	ATHKey = "ath"
	// DPopType is the value of the typ JWT header for a DPoP token
	DPopType = "dpop+jwt"
	HTMKey   = "htm"
	HTUKey   = "htu"
)

// maxJtiLength is the maximum length of the jti claim in a DPoP token.
// jti's are stored to prevent replay attacks and should be unique.
// Allowing too long jti's could lead to a memory exhaustion attack.
const maxJtiLength = 256

// DPoP represents a DPoP token used for internal processing
type DPoP struct {
	raw     string
	Headers jws.Headers `json:"-"`
	Token   jwt.Token   `json:"-"`
}

// ErrInvalidDPoP is returned when a DPoP token is invalid
var ErrInvalidDPoP = errors.New("invalid DPoP token")

// New creates a new DPoP token from the given http request
func New(request http.Request) *DPoP {
	result := DPoP{}
	result.Token = jwt.New()
	// errors won't occur
	_ = result.Token.Set(HTMKey, request.Method)
	_ = result.Token.Set(HTUKey, request.URL.String())
	_ = result.Token.Set(jwt.JwtIDKey, generateID())
	_ = result.Token.Set(jwt.IssuedAtKey, time.Now())

	result.Headers = jws.NewHeaders()
	_ = result.Headers.Set(jws.TypeKey, DPopType)

	return &result
}

// generateID generates a random id for the DPoP token
// can't use the method from crypto due to circular dependencies
func generateID() string {
	buf := make([]byte, 256/8)
	_, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

// Sign the DPoP token with the given key
// It also adds the jwk and alg header
func (t *DPoP) Sign(key crypto.Signer, alg jwa.SignatureAlgorithm) (string, error) {
	if t.raw != "" {
		return "", errors.New("already signed")
	}
	publicKeyJWK, err := jwk.FromRaw(key.Public())
	if err != nil {
		return "", err
	}
	_ = publicKeyJWK.Set(jwk.AlgorithmKey, alg)
	_ = t.Headers.Set(jws.JWKKey, publicKeyJWK)

	sig, err := jwt.Sign(t.Token, jwt.WithKey(alg, key, jws.WithProtectedHeaders(t.Headers)))
	if err != nil {
		return "", err
	}
	t.raw = string(sig)

	return t.raw, nil
}

// GenerateProof generates the proof for the DPoP token
// It sets the ath claim to the base64 encoded SHA256 hash of the access token
func (t DPoP) GenerateProof(accessToken string) DPoP {
	accessTokenHash := hash.SHA256Sum([]byte(accessToken))
	base64Hash := base64.RawURLEncoding.EncodeToString(accessTokenHash.Slice())
	_ = t.Token.Set(ATHKey, base64Hash)
	return t
}

// Parse parses a DPoP token from a string.
// The token is validated for the required claims and headers.
func Parse(s string) (*DPoP, error) {
	message, err := jws.ParseString(s)
	if err != nil {
		return nil, errors.Join(ErrInvalidDPoP, err)
	}
	// we require exactly one signature
	if len(message.Signatures()) != 1 {
		return nil, fmt.Errorf("%w: invalid number of signatures", ErrInvalidDPoP)
	}
	headers := message.Signatures()[0].ProtectedHeaders()
	if !slices.Contains(jwx.SupportedAlgorithms, headers.Algorithm()) {
		return nil, fmt.Errorf("%w: invalid alg: %s", ErrInvalidDPoP, headers.Algorithm())
	}
	if headers.Type() != "dpop+jwt" {
		return nil, fmt.Errorf("%w: invalid type: %s", ErrInvalidDPoP, headers.Type())
	}
	if headers.JWK() == nil {
		return nil, fmt.Errorf("%w: missing jwk header", ErrInvalidDPoP)
	}
	if jwkIsPrivateKey(headers.JWK()) {
		return nil, fmt.Errorf("%w: invalid jwk header", ErrInvalidDPoP)
	}
	token, err := jwt.ParseString(s, jwt.WithKey(headers.Algorithm(), headers.JWK()))
	if err != nil {
		return nil, errors.Join(ErrInvalidDPoP, err)
	}
	if token.IssuedAt().IsZero() {
		return nil, fmt.Errorf("%w: missing iat claim", ErrInvalidDPoP)
	}
	if v, ok := token.Get(HTUKey); !ok || v == "" {
		return nil, fmt.Errorf("%w: missing htu claim", ErrInvalidDPoP)
	}
	if v, ok := token.Get(HTMKey); !ok || v == "" {
		return nil, fmt.Errorf("%w: missing htm claim", ErrInvalidDPoP)
	}
	if token.JwtID() == "" {
		return nil, fmt.Errorf("%w: missing jti claim", ErrInvalidDPoP)
	}
	if len(token.JwtID()) > maxJtiLength {
		return nil, fmt.Errorf("%w: jti claim too long", ErrInvalidDPoP)
	}

	return &DPoP{raw: s, Token: token, Headers: headers}, nil
}

func jwkIsPrivateKey(jwk jwk.Key) bool {
	// we try to parse it as different private keys, if there's no error, it's a private key
	var rsaPrivateKey rsa.PrivateKey
	if err := jwk.Raw(&rsaPrivateKey); err == nil {
		return true
	}
	var ecPrivateKey ecdsa.PrivateKey
	if err := jwk.Raw(&ecPrivateKey); err == nil {
		return true
	}
	var edPrivateKey ed25519.PrivateKey
	if err := jwk.Raw(&edPrivateKey); err == nil {
		return true
	}
	return false
}

// HTU returns the htu claim of the DPoP token
func (t DPoP) HTU() string {
	if v, ok := t.Token.Get(HTUKey); ok {
		return v.(string)
	}
	return ""
}

// HTM returns the htm claim of the DPoP token
func (t DPoP) HTM() string {
	if v, ok := t.Token.Get(HTMKey); ok {
		return v.(string)
	}
	return ""
}

// Match checks if the JWK, http method, domain and path of the DPoP tokens match
// for the url, the port is stripped.
// If there is a mismatch, the reason is returned in an error.
func (t DPoP) Match(jkt string, method string, url string) (bool, error) {
	tp, _ := t.Headers.JWK().Thumbprint(crypto.SHA256)
	base64tp := base64.RawURLEncoding.EncodeToString(tp)

	if base64tp != jkt {
		return false, errors.New("jkt mismatch")
	}

	// check method and url
	if method != t.HTM() {
		return false, fmt.Errorf("method mismatch, token: %s, given: %s", t.HTM(), method)
	}
	urlLeft := strip(t.HTU())
	urlRight := strip(url)
	if urlLeft != urlRight {
		return false, fmt.Errorf("url mismatch, token: %s, given: %s", urlLeft, urlRight)
	}

	return true, nil
}

func strip(raw string) string {
	url, _ := url.Parse(raw)
	url.Scheme = "https"
	url.Host = strings.Split(url.Host, ":")[0]
	url.RawQuery = ""
	url.Fragment = ""
	return url.String()
}

func (t DPoP) MarshalJSON() ([]byte, error) {
	quoted := fmt.Sprintf("%q", t.raw)
	return []byte(quoted), nil
}

func (t *DPoP) UnmarshalJSON(bytes []byte) error {
	if len(bytes) < 2 || bytes[0] != '"' || bytes[len(bytes)-1] != '"' {
		return fmt.Errorf("invalid DPoP token: %s", string(bytes))
	}
	unquoted := string(bytes[1 : len(bytes)-1])
	tmp, err := Parse(unquoted)
	if err != nil {
		return err
	}
	*t = *tmp
	return nil
}

func (t DPoP) String() string {
	return t.raw
}
