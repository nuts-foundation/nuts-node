/*
 * Copyright (C) 2021. Nuts community
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

package dag

import (
	"crypto"
	"crypto/ecdsa"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestParseDocument(t *testing.T) {
	key := generateKey()
	payload, _ := hash.ParseHex("3d2c482831de294af919a4c4604c97156cf0ba46fcf6f96e50774597470f8db8")
	payloadAsBytes := []byte(payload.String())
	t.Run("ok", func(t *testing.T) {
		headers := makeJWSHeaders(key, "123", true)
		signature, _ := jws.Sign(payloadAsBytes, headers.Algorithm(), key, jws.WithHeaders(headers))

		document, err := ParseDocument(signature)
		if !assert.NoError(t, err) {
			return
		}

		var actualKey ecdsa.PublicKey
		err = document.SigningKey().Raw(&actualKey)
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, document)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, payload, document.PayloadHash())
		assert.Equal(t, key.PublicKey, actualKey)
		assert.Equal(t, 1, int(document.Version()))
		assert.Equal(t, "foo/bar", document.PayloadType())
		assert.Equal(t, time.UTC, document.SigningTime().Location())
		assert.Equal(t, headers.PrivateParams()[previousHeader].([]string)[0], document.Previous()[0].String())
		assert.Equal(t, headers.PrivateParams()[timelineIDHeader].(string), document.TimelineID().String())
		assert.Equal(t, headers.PrivateParams()[timelineVersionHeader].(int), document.TimelineVersion())
		assert.NotNil(t, document.Data())
		assert.False(t, document.Ref().Empty())
	})
	t.Run("error - input not a JWS (compact serialization format)", func(t *testing.T) {
		document, err := ParseDocument([]byte("not a JWS"))
		assert.Nil(t, document)
		assert.EqualError(t, err, "unable to parse document: invalid compact serialization format: invalid number of segments")
	})
	t.Run("error - input not a JWS (JSON serialization format)", func(t *testing.T) {
		document, err := ParseDocument([]byte("{}"))
		assert.Nil(t, document)
		assert.EqualError(t, err, "unable to parse document: failed to unmarshal jws message: \"payload\" must be non-empty")
	})
	t.Run("error - sigt header is missing", func(t *testing.T) {
		headers := makeJWSHeaders(key, "123", false)
		delete(headers.PrivateParams(), signingTimeHeader)
		signature, _ := jws.Sign(payloadAsBytes, headers.Algorithm(), key, jws.WithHeaders(headers))

		document, err := ParseDocument(signature)

		assert.Nil(t, document)
		assert.EqualError(t, err, "document validation failed: missing sigt header")
	})
	t.Run("error - invalid sigt header", func(t *testing.T) {
		headers := makeJWSHeaders(key, "123", false)
		headers.Set(signingTimeHeader, "not a date")
		signature, _ := jws.Sign(payloadAsBytes, headers.Algorithm(), key, jws.WithHeaders(headers))

		document, err := ParseDocument(signature)

		assert.Nil(t, document)
		assert.EqualError(t, err, "document validation failed: invalid sigt header")
	})
	t.Run("error - vers header is missing", func(t *testing.T) {
		headers := makeJWSHeaders(key, "123", false)
		delete(headers.PrivateParams(), versionHeader)
		signature, _ := jws.Sign(payloadAsBytes, headers.Algorithm(), key, jws.WithHeaders(headers))

		document, err := ParseDocument(signature)

		assert.Nil(t, document)
		assert.EqualError(t, err, "document validation failed: missing ver header")
	})
	t.Run("error - both jwk and kid set", func(t *testing.T) {
		headers := makeJWSHeaders(key, "1234", true)
		headers.Set(jwk.KeyIDKey, "123")
		signature, _ := jws.Sign(payloadAsBytes, headers.Algorithm(), key, jws.WithHeaders(headers))

		document, err := ParseDocument(signature)

		assert.Nil(t, document)
		assert.EqualError(t, err, "document validation failed: either `kid` or `jwk` header must be present (but not both)")
	})
	t.Run("error - jwk/kid both not set", func(t *testing.T) {
		headers := makeJWSHeaders(nil, "", false)
		signature, _ := jws.Sign(payloadAsBytes, headers.Algorithm(), key, jws.WithHeaders(headers))

		document, err := ParseDocument(signature)

		assert.Nil(t, document)
		assert.EqualError(t, err, "document validation failed: either `kid` or `jwk` header must be present (but not both)")
	})
	t.Run("error - prevs header is missing", func(t *testing.T) {
		headers := makeJWSHeaders(key, "123", true)
		delete(headers.PrivateParams(), previousHeader)
		signature, _ := jws.Sign(payloadAsBytes, headers.Algorithm(), key, jws.WithHeaders(headers))

		document, err := ParseDocument(signature)

		assert.Nil(t, document)
		assert.EqualError(t, err, "document validation failed: missing prevs header")
	})
	t.Run("error - invalid prevs (not an array)", func(t *testing.T) {
		headers := makeJWSHeaders(key, "123", true)
		headers.Set(previousHeader, 2)
		signature, _ := jws.Sign(payloadAsBytes, headers.Algorithm(), key, jws.WithHeaders(headers))

		document, err := ParseDocument(signature)

		assert.Nil(t, document)
		assert.EqualError(t, err, "document validation failed: invalid prevs header")
	})
	t.Run("error - invalid prevs (invalid entry)", func(t *testing.T) {
		headers := makeJWSHeaders(key, "123", true)
		headers.Set(previousHeader, []string{"not a hash"})
		signature, _ := jws.Sign(payloadAsBytes, headers.Algorithm(), key, jws.WithHeaders(headers))

		document, err := ParseDocument(signature)

		assert.Nil(t, document)
		assert.EqualError(t, err, "document validation failed: invalid prevs header")
	})
	t.Run("error - invalid prevs (invalid entry, not a string)", func(t *testing.T) {
		headers := makeJWSHeaders(key, "123", true)
		headers.Set(previousHeader, []int{5})
		signature, _ := jws.Sign(payloadAsBytes, headers.Algorithm(), key, jws.WithHeaders(headers))

		document, err := ParseDocument(signature)

		assert.Nil(t, document)
		assert.EqualError(t, err, "document validation failed: invalid prevs header")
	})
	t.Run("error - cty header is invalid", func(t *testing.T) {
		headers := makeJWSHeaders(key, "", false)
		headers.Set(jws.ContentTypeKey, "")
		signature, _ := jws.Sign(payloadAsBytes, headers.Algorithm(), key, jws.WithHeaders(headers))

		document, err := ParseDocument(signature)

		assert.Nil(t, document)
		assert.EqualError(t, err, "document validation failed: payload type must be formatted as MIME type")
	})
	t.Run("error - invalid version", func(t *testing.T) {
		headers := makeJWSHeaders(key, "123", true)
		headers.Set(versionHeader, "foobar")
		signature, _ := jws.Sign(payloadAsBytes, headers.Algorithm(), key, jws.WithHeaders(headers))

		document, err := ParseDocument(signature)

		assert.Nil(t, document)
		assert.EqualError(t, err, "document validation failed: invalid ver header")
	})
	t.Run("error - unsupported version", func(t *testing.T) {
		headers := makeJWSHeaders(key, "123", true)
		headers.Set(versionHeader, 2)
		signature, _ := jws.Sign(payloadAsBytes, headers.Algorithm(), key, jws.WithHeaders(headers))

		document, err := ParseDocument(signature)

		assert.Nil(t, document)
		assert.EqualError(t, err, "document validation failed: unsupported version: 2")
	})
	t.Run("error - invalid algorithm", func(t *testing.T) {
		key := generateRSAKey()
		headers := makeJWSHeaders(key, "", false)
		headers.Set(jws.AlgorithmKey, jwa.RS256)
		signature, _ := jws.Sign(payloadAsBytes, headers.Algorithm(), key, jws.WithHeaders(headers))

		document, err := ParseDocument(signature)

		assert.Nil(t, document)
		assert.EqualError(t, err, "document validation failed: signing algorithm not allowed: RS256")
	})
	t.Run("error - invalid tid header", func(t *testing.T) {
		headers := makeJWSHeaders(key, "123", true)
		headers.Set(timelineIDHeader, "not a valid hash")
		signature, _ := jws.Sign(payloadAsBytes, headers.Algorithm(), key, jws.WithHeaders(headers))

		document, err := ParseDocument(signature)

		assert.Nil(t, document)
		assert.Contains(t, err.Error(), "document validation failed: invalid tid header")
	})
	t.Run("error - invalid tid header (not a string)", func(t *testing.T) {
		headers := makeJWSHeaders(key, "123", true)
		headers.Set(timelineIDHeader, 5)
		signature, _ := jws.Sign(payloadAsBytes, headers.Algorithm(), key, jws.WithHeaders(headers))

		document, err := ParseDocument(signature)

		assert.Nil(t, document)
		assert.Contains(t, err.Error(), "document validation failed: invalid tid header")
	})
	t.Run("error - invalid tiv header (not a numeric value)", func(t *testing.T) {
		headers := makeJWSHeaders(key, "123", true)
		headers.Set(timelineVersionHeader, "not a numeric value")
		signature, _ := jws.Sign(payloadAsBytes, headers.Algorithm(), key, jws.WithHeaders(headers))

		document, err := ParseDocument(signature)

		assert.Nil(t, document)
		assert.Contains(t, err.Error(), "document validation failed: invalid tiv header")
	})
	t.Run("error - invalid tiv header (not a numeric value)", func(t *testing.T) {
		headers := makeJWSHeaders(key, "123", true)
		headers.Set(timelineVersionHeader, "not a numeric value")
		signature, _ := jws.Sign(payloadAsBytes, headers.Algorithm(), key, jws.WithHeaders(headers))

		document, err := ParseDocument(signature)

		assert.Nil(t, document)
		assert.Contains(t, err.Error(), "document validation failed: invalid tiv header")
	})
	t.Run("error - invalid tiv header (value smaller than 0)", func(t *testing.T) {
		headers := makeJWSHeaders(key, "123", true)
		headers.Set(timelineVersionHeader, -1)
		signature, _ := jws.Sign(payloadAsBytes, headers.Algorithm(), key, jws.WithHeaders(headers))

		document, err := ParseDocument(signature)

		assert.Nil(t, document)
		assert.Contains(t, err.Error(), "document validation failed: invalid tiv header")
	})
	t.Run("error - invalid tiv header (value non-integer)", func(t *testing.T) {
		headers := makeJWSHeaders(key, "123", true)
		headers.Set(timelineVersionHeader, 1.5)
		signature, _ := jws.Sign(payloadAsBytes, headers.Algorithm(), key, jws.WithHeaders(headers))

		document, err := ParseDocument(signature)

		assert.Nil(t, document)
		assert.Contains(t, err.Error(), "document validation failed: invalid tiv header")
	})

	t.Run("error - tiv header without tid", func(t *testing.T) {
		headers := makeJWSHeaders(key, "123", true)
		delete(headers.PrivateParams(), timelineIDHeader)
		signature, _ := jws.Sign(payloadAsBytes, headers.Algorithm(), key, jws.WithHeaders(headers))

		document, err := ParseDocument(signature)

		assert.Nil(t, document)
		assert.Contains(t, err.Error(), "document validation failed: tiv specified without tid header")
	})
	t.Run("error - invalid payload", func(t *testing.T) {
		headers := makeJWSHeaders(key, "123", true)
		signature, _ := jws.Sign([]byte("not a valid hash"), headers.Algorithm(), key, jws.WithHeaders(headers))

		document, err := ParseDocument(signature)

		assert.Nil(t, document)
		assert.Contains(t, err.Error(), "document validation failed: invalid payload")
	})
}

func makeJWSHeaders(key crypto.Signer, kid string, embedKey bool) jws.Headers {
	prev, _ := hash.ParseHex("bedcd5bfb50af622be56c4aec7ac5da64745686b362afc7e615ea89b0705b8f8")
	timelineID, _ := hash.ParseHex("a7da489976d0047490617adb4f7a1f27f7af8b52a5176fd002ffe471863520ab")
	headerMap := map[string]interface{}{
		jws.AlgorithmKey:      jwa.ES256,
		jws.ContentTypeKey:    "foo/bar",
		jws.CriticalKey:       []string{signingTimeHeader, versionHeader, previousHeader},
		signingTimeHeader:     time.Now().UTC().Unix(),
		versionHeader:         1,
		previousHeader:        []string{prev.String()},
		timelineIDHeader:      timelineID.String(),
		timelineVersionHeader: 1,
	}
	if embedKey {
		keyAsJWS, _ := jwk.New(key.Public())
		keyAsJWS.Set(jwk.KeyIDKey, kid)
		headerMap[jws.JWKKey] = keyAsJWS
	} else {
		headerMap[jws.KeyIDKey] = kid
	}
	headers := jws.NewHeaders()
	for key, value := range headerMap {
		if err := headers.Set(key, value); err != nil {
			logrus.Fatalf("Unable to set header %s: %v", key, err)
		}
	}
	return headers
}
