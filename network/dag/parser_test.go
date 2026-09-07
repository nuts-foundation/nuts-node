/*
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
 *
 */

package dag

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestParseTransaction(t *testing.T) {
	key := generateKey()
	payload, _ := hash.ParseHex("3d2c482831de294af919a4c4604c97156cf0ba46fcf6f96e50774597470f8db8")
	payloadAsBytes := []byte(payload.String())
	t.Run("v1", func(t *testing.T) {
		headers := makeJWSHeaders(key, "123", true)
		_ = headers.Set("pal", []string{base64.StdEncoding.EncodeToString([]byte{5, 6, 7})})
		signature, _ := jws.Sign(payloadAsBytes, jws.WithKey(algOf(headers), key, jws.WithProtectedHeaders(headers)))

		transaction, err := ParseTransaction(signature)
		require.NoError(t, err)

		var actualKey ecdsa.PublicKey
		err = jwk.Export(transaction.SigningKey(), &actualKey)
		require.NoError(t, err)

		assert.NotNil(t, transaction)
		require.NoError(t, err)

		assert.Equal(t, payload, transaction.PayloadHash())
		assert.Equal(t, key.PublicKey, actualKey)
		assert.Equal(t, 1, int(transaction.Version()))
		assert.Equal(t, "foo/bar", transaction.PayloadType())
		assert.Equal(t, time.UTC, transaction.SigningTime().Location())
		var previousHeaderValue []string
		_ = headers.Get(previousHeader, &previousHeaderValue)
		assert.Equal(t, previousHeaderValue[0], transaction.Previous()[0].String())
		assert.Equal(t, transaction.PAL(), [][]byte{{5, 6, 7}})
		assert.NotNil(t, transaction.Data())
		assert.False(t, transaction.Ref().Empty())
	})
	t.Run("ok v2", func(t *testing.T) {
		headers := makeJWSHeaders(key, "123", true)
		_ = headers.Set("pal", []string{base64.StdEncoding.EncodeToString([]byte{5, 6, 7})})
		_ = headers.Set(versionHeader, 2)
		_ = headers.Set(jws.CriticalKey, []string{signingTimeHeader, versionHeader, previousHeader, lamportClockHeader})
		signature, _ := jws.Sign(payloadAsBytes, jws.WithKey(algOf(headers), key, jws.WithProtectedHeaders(headers)))

		transaction, err := ParseTransaction(signature)
		require.NoError(t, err)

		var actualKey ecdsa.PublicKey
		err = jwk.Export(transaction.SigningKey(), &actualKey)
		require.NoError(t, err)

		assert.NotNil(t, transaction)
		require.NoError(t, err)

		assert.Equal(t, payload, transaction.PayloadHash())
		assert.Equal(t, key.PublicKey, actualKey)
		assert.Equal(t, 2, int(transaction.Version()))
		assert.Equal(t, "foo/bar", transaction.PayloadType())
		assert.Equal(t, time.UTC, transaction.SigningTime().Location())
		var previousHeaderValue []string
		_ = headers.Get(previousHeader, &previousHeaderValue)
		assert.Equal(t, previousHeaderValue[0], transaction.Previous()[0].String())
		assert.Equal(t, transaction.PAL(), [][]byte{{5, 6, 7}})
		assert.NotNil(t, transaction.Data())
		assert.False(t, transaction.Ref().Empty())
	})
	t.Run("error - input not a JWS (compact serialization format)", func(t *testing.T) {
		tx, err := ParseTransaction([]byte("not a JWS"))
		assert.Nil(t, tx)
		assert.EqualError(t, err, "unable to parse transaction: jws.Parse: failed to parse compact format: jws.Parse: invalid compact serialization format: jwsbb: invalid number of segments")
	})
	t.Run("error - input not a JWS (JSON serialization format)", func(t *testing.T) {
		tx, err := ParseTransaction([]byte("{}"))
		assert.Nil(t, tx)
		assert.EqualError(t, err, "unable to parse transaction: jws.Parse: failed to parse compact format: jws.Parse: invalid compact serialization format: jwsbb: invalid number of segments")
	})
	t.Run("error - input not a JWS (flattened JSON serialization, same signing input as a valid compact JWS)", func(t *testing.T) {
		headers := makeJWSHeaders(key, "123", false)
		compact, _ := jws.Sign(payloadAsBytes, jws.WithKey(algOf(headers), key, jws.WithProtectedHeaders(headers)))
		parts := strings.SplitN(string(compact), ".", 3)
		flattened := fmt.Sprintf(`{"protected":%q,"payload":%q,"signature":%q}`, parts[0], parts[1], parts[2])

		tx, err := ParseTransaction([]byte(flattened))

		assert.Nil(t, tx)
		assert.ErrorContains(t, err, "unable to parse transaction")
	})
	t.Run("error - non-canonical compact serialization (trailing newline)", func(t *testing.T) {
		headers := makeJWSHeaders(key, "123", false)
		compact, _ := jws.Sign(payloadAsBytes, jws.WithKey(algOf(headers), key, jws.WithProtectedHeaders(headers)))

		tx, err := ParseTransaction(append(compact, '\n'))

		assert.Nil(t, tx)
		assert.EqualError(t, err, "unable to parse transaction: JWS is not canonically encoded compact serialization")
	})
	t.Run("ok - canonical compact serialization is accepted", func(t *testing.T) {
		headers := makeJWSHeaders(key, "123", false)
		compact, _ := jws.Sign(payloadAsBytes, jws.WithKey(algOf(headers), key, jws.WithProtectedHeaders(headers)))

		tx, err := ParseTransaction(compact)

		assert.NoError(t, err)
		assert.NotNil(t, tx)
	})
	t.Run("error - pal header has invalid type", func(t *testing.T) {
		headers := makeJWSHeaders(key, "123", false)
		_ = headers.Set("pal", 100)

		signature, _ := jws.Sign(payloadAsBytes, jws.WithKey(algOf(headers), key, jws.WithProtectedHeaders(headers)))

		transaction, err := ParseTransaction(signature)

		assert.Nil(t, transaction)
		assert.EqualError(t, err, "transaction validation failed: invalid pal header")
	})
	t.Run("error - sigt header is missing", func(t *testing.T) {
		headers := makeJWSHeaders(key, "123", false)
		_ = headers.Remove(signingTimeHeader)
		signature, _ := jws.Sign(payloadAsBytes, jws.WithKey(algOf(headers), key, jws.WithProtectedHeaders(headers)))

		transaction, err := ParseTransaction(signature)

		assert.Nil(t, transaction)
		assert.EqualError(t, err, "transaction validation failed: missing sigt header")
	})
	t.Run("error - invalid sigt header", func(t *testing.T) {
		headers := makeJWSHeaders(key, "123", false)
		headers.Set(signingTimeHeader, "not a date")
		signature, _ := jws.Sign(payloadAsBytes, jws.WithKey(algOf(headers), key, jws.WithProtectedHeaders(headers)))

		transaction, err := ParseTransaction(signature)

		assert.Nil(t, transaction)
		assert.EqualError(t, err, "transaction validation failed: invalid sigt header")
	})
	t.Run("error - vers header is missing", func(t *testing.T) {
		headers := makeJWSHeaders(key, "123", false)
		_ = headers.Remove(versionHeader)
		signature, _ := jws.Sign(payloadAsBytes, jws.WithKey(algOf(headers), key, jws.WithProtectedHeaders(headers)))

		transaction, err := ParseTransaction(signature)

		assert.Nil(t, transaction)
		assert.EqualError(t, err, "transaction validation failed: missing ver header")
	})
	t.Run("error - both jwk and kid set", func(t *testing.T) {
		headers := makeJWSHeaders(key, "1234", true)
		headers.Set(jwk.KeyIDKey, "123")
		signature, _ := jws.Sign(payloadAsBytes, jws.WithKey(algOf(headers), key, jws.WithProtectedHeaders(headers)))

		transaction, err := ParseTransaction(signature)

		assert.Nil(t, transaction)
		assert.EqualError(t, err, "transaction validation failed: either `kid` or `jwk` header must be present (but not both)")
	})
	t.Run("error - jwk/kid both not set", func(t *testing.T) {
		headers := makeJWSHeaders(nil, "", false)
		signature, _ := jws.Sign(payloadAsBytes, jws.WithKey(algOf(headers), key, jws.WithProtectedHeaders(headers)))

		transaction, err := ParseTransaction(signature)

		assert.Nil(t, transaction)
		assert.EqualError(t, err, "transaction validation failed: either `kid` or `jwk` header must be present (but not both)")
	})
	t.Run("error - prevs header is missing", func(t *testing.T) {
		headers := makeJWSHeaders(key, "123", true)
		_ = headers.Remove(previousHeader)
		signature, _ := jws.Sign(payloadAsBytes, jws.WithKey(algOf(headers), key, jws.WithProtectedHeaders(headers)))

		transaction, err := ParseTransaction(signature)

		assert.Nil(t, transaction)
		assert.EqualError(t, err, "transaction validation failed: missing prevs header")
	})
	t.Run("error - invalid prevs (not an array)", func(t *testing.T) {
		headers := makeJWSHeaders(key, "123", true)
		headers.Set(previousHeader, 2)
		signature, _ := jws.Sign(payloadAsBytes, jws.WithKey(algOf(headers), key, jws.WithProtectedHeaders(headers)))

		transaction, err := ParseTransaction(signature)

		assert.Nil(t, transaction)
		assert.EqualError(t, err, "transaction validation failed: invalid prevs header")
	})
	t.Run("error - invalid prevs (invalid entry)", func(t *testing.T) {
		headers := makeJWSHeaders(key, "123", true)
		headers.Set(previousHeader, []string{"not a hash"})
		signature, _ := jws.Sign(payloadAsBytes, jws.WithKey(algOf(headers), key, jws.WithProtectedHeaders(headers)))

		transaction, err := ParseTransaction(signature)

		assert.Nil(t, transaction)
		assert.EqualError(t, err, "transaction validation failed: invalid prevs header")
	})
	t.Run("error - invalid prevs (invalid entry, not a string)", func(t *testing.T) {
		headers := makeJWSHeaders(key, "123", true)
		headers.Set(previousHeader, []int{5})
		signature, _ := jws.Sign(payloadAsBytes, jws.WithKey(algOf(headers), key, jws.WithProtectedHeaders(headers)))

		transaction, err := ParseTransaction(signature)

		assert.Nil(t, transaction)
		assert.EqualError(t, err, "transaction validation failed: invalid prevs header")
	})
	t.Run("error - cty header is invalid", func(t *testing.T) {
		headers := makeJWSHeaders(key, "", false)
		headers.Set(jws.ContentTypeKey, "")
		signature, _ := jws.Sign(payloadAsBytes, jws.WithKey(algOf(headers), key, jws.WithProtectedHeaders(headers)))

		transaction, err := ParseTransaction(signature)

		assert.Nil(t, transaction)
		assert.EqualError(t, err, "transaction validation failed: payload type must be formatted as MIME type")
	})
	t.Run("error - invalid version", func(t *testing.T) {
		headers := makeJWSHeaders(key, "123", true)
		headers.Set(versionHeader, "foobar")
		signature, _ := jws.Sign(payloadAsBytes, jws.WithKey(algOf(headers), key, jws.WithProtectedHeaders(headers)))

		transaction, err := ParseTransaction(signature)

		assert.Nil(t, transaction)
		assert.EqualError(t, err, "transaction validation failed: invalid ver header")
	})
	t.Run("error - unsupported version", func(t *testing.T) {
		headers := makeJWSHeaders(key, "123", true)
		headers.Set(versionHeader, 3)
		signature, _ := jws.Sign(payloadAsBytes, jws.WithKey(algOf(headers), key, jws.WithProtectedHeaders(headers)))

		transaction, err := ParseTransaction(signature)

		assert.Nil(t, transaction)
		assert.EqualError(t, err, "transaction validation failed: unsupported version: 3")
	})
	t.Run("error - invalid algorithm", func(t *testing.T) {
		key := generateRSAKey()
		headers := makeJWSHeaders(key, "", false)
		headers.Set(jws.AlgorithmKey, jwa.RS256())
		signature, _ := jws.Sign(payloadAsBytes, jws.WithKey(algOf(headers), key, jws.WithProtectedHeaders(headers)))

		transaction, err := ParseTransaction(signature)

		assert.Nil(t, transaction)
		assert.EqualError(t, err, "transaction validation failed: signing algorithm not allowed: RS256")
	})
	t.Run("error - invalid lamport clock", func(t *testing.T) {
		headers := makeJWSHeaders(key, "123", true)
		headers.Set(lamportClockHeader, "a")
		signature, _ := jws.Sign(payloadAsBytes, jws.WithKey(algOf(headers), key, jws.WithProtectedHeaders(headers)))

		transaction, err := ParseTransaction(signature)

		assert.Nil(t, transaction)
		assert.EqualError(t, err, "transaction validation failed: invalid lc header")
	})
	t.Run("error - invalid payload", func(t *testing.T) {
		headers := makeJWSHeaders(key, "123", true)
		signature, _ := jws.Sign([]byte("not a valid hash"), jws.WithKey(algOf(headers), key, jws.WithProtectedHeaders(headers)))

		transaction, err := ParseTransaction(signature)

		assert.Nil(t, transaction)
		assert.Contains(t, err.Error(), "transaction validation failed: invalid payload")
	})
}

func algOf(headers jws.Headers) jwa.SignatureAlgorithm {
	alg, _ := headers.Algorithm()
	return alg
}

func TestValidateCanonicalCompactSerialization(t *testing.T) {
	t.Run("ok - canonical compact JWS", func(t *testing.T) {
		assert.NoError(t, validateCanonicalCompactSerialization([]byte("AA.AA.AA")))
	})
	t.Run("error - not compact serialization (JSON)", func(t *testing.T) {
		assert.ErrorIs(t, validateCanonicalCompactSerialization([]byte(`{"protected":"AA"}`)), errNonCanonicalJWS)
	})
	t.Run("error - wrong number of segments", func(t *testing.T) {
		assert.ErrorIs(t, validateCanonicalCompactSerialization([]byte("AA.AA")), errNonCanonicalJWS)
		assert.ErrorIs(t, validateCanonicalCompactSerialization([]byte("AA.AA.AA.AA")), errNonCanonicalJWS)
	})
	t.Run("error - segment not valid base64url", func(t *testing.T) {
		assert.ErrorIs(t, validateCanonicalCompactSerialization([]byte("AA.A+.AA")), errNonCanonicalJWS)
	})
	t.Run("error - trailing whitespace", func(t *testing.T) {
		assert.ErrorIs(t, validateCanonicalCompactSerialization([]byte("AA.AA.AA\n")), errNonCanonicalJWS)
	})
	t.Run("error - leading whitespace", func(t *testing.T) {
		assert.ErrorIs(t, validateCanonicalCompactSerialization([]byte(" AA.AA.AA")), errNonCanonicalJWS)
	})
	t.Run("error - non-canonical base64 (unused trailing bits set)", func(t *testing.T) {
		// "AP" and "AA" both decode to the single byte 0x00 - the last 4 bits of "AP" are unused by
		// a 1-byte payload and a canonical encoder always zeroes them, but a lenient decoder ignores
		// whatever they're set to. "AP" is therefore a valid but non-canonical encoding of the same
		// byte "AA" represents.
		assert.ErrorIs(t, validateCanonicalCompactSerialization([]byte("AA.AP.AA")), errNonCanonicalJWS)
	})
}

func makeJWSHeaders(key crypto.Signer, kid string, embedKey bool) jws.Headers {
	prev, _ := hash.ParseHex("bedcd5bfb50af622be56c4aec7ac5da64745686b362afc7e615ea89b0705b8f8")
	headerMap := map[string]interface{}{
		jws.AlgorithmKey:   jwa.ES256(),
		jws.ContentTypeKey: "foo/bar",
		jws.CriticalKey:    []string{signingTimeHeader, versionHeader, previousHeader, lamportClockHeader},
		lamportClockHeader: 0,
		signingTimeHeader:  time.Now().UTC().Unix(),
		versionHeader:      1,
		previousHeader:     []string{prev.String()},
	}
	if embedKey {
		keyAsJWS, _ := jwk.Import(key.Public())
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
