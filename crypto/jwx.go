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

package crypto

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"maps"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/mr-tron/base58"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/crypto/jwx"
	"github.com/nuts-foundation/nuts-node/crypto/log"
	"github.com/nuts-foundation/nuts-node/crypto/storage/spi"
)

// SignJWT creates a JWT from the given claims and signs it with the given key.
func (client *Crypto) SignJWT(ctx context.Context, claims map[string]interface{}, headers map[string]interface{}, kid string) (string, error) {
	// copy headers so we don't change the input
	headersLocal := make(map[string]interface{})
	maps.Copy(headersLocal, headers)

	privateKey, kid, err := client.getPrivateKey(ctx, kid)
	if err != nil {
		return "", err
	}

	alg, err := signingAlg(privateKey.Public())
	if err != nil {
		return "", err
	}

	headersLocal["kid"] = kid
	return SignJWT(ctx, privateKey, alg, claims, headersLocal)
}

// SignJWS creates a signed JWS using the indicated key and map of headers and payload as bytes.
func (client *Crypto) SignJWS(ctx context.Context, payload []byte, headers map[string]interface{}, kid string, detached bool) (string, error) {
	privateKey, kid, err := client.getPrivateKey(ctx, kid)
	if err != nil {
		return "", err
	}

	if _, ok := headers["jwk"]; !ok {
		headers["kid"] = kid
	}
	return SignJWS(ctx, payload, headers, privateKey, detached)
}

// EncryptJWE encrypts a payload using the provided public key and key identifier.
func (client *Crypto) EncryptJWE(ctx context.Context, payload []byte, headers map[string]interface{}, publicKey interface{}) (string, error) {
	audit.Log(ctx, log.Logger(), audit.CryptoEncryptJWEEvent).Info("Encrypting a JWE")
	return EncryptJWE(payload, headers, publicKey)
}

// DecryptJWE decrypts a message using the associated private key from the kid header.
func (client *Crypto) DecryptJWE(ctx context.Context, message string) (body []byte, headers map[string]interface{}, err error) {
	msg, err := jwe.Parse([]byte(message))
	if err != nil {
		return nil, nil, err
	}

	protectedHeaders := msg.ProtectedHeaders()
	kid := protectedHeaders.KeyID()
	if len(kid) == 0 {
		return nil, nil, errors.New("kid header not found")
	}
	privateKey, kid, err := client.getPrivateKey(ctx, kid)
	if err != nil {
		return nil, nil, err
	}

	audit.Log(ctx, log.Logger(), audit.CryptoDecryptJWEEvent).Infof("Decrypting a JWE with kid: %s", kid)

	keyJWK, err := jwk.FromRaw(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("keys stored in '%s' do not support JWE decryption", client.storage.Name())
	}
	body, err = jwe.Decrypt([]byte(message), jwe.WithKey(protectedHeaders.Algorithm(), keyJWK))
	if err != nil {
		return nil, nil, err
	}
	headers, err = msg.ProtectedHeaders().AsMap(ctx)
	if err != nil {
		return nil, nil, err
	}
	return body, headers, err
}

// SignJWT signs claims with the signer and returns the compacted token. The headers param can be used to add additional headers
func SignJWT(ctx context.Context, key crypto.Signer, alg jwa.SignatureAlgorithm, claims map[string]interface{}, headers map[string]interface{}) (token string, err error) {
	audit.Log(ctx, log.Logger(), audit.CryptoSignJWTEvent).Infof("Signing a JWT with key: %s (issuer: %s, subject: %s)", headers["kid"], claims["iss"], claims["sub"])

	var sig []byte
	t := jwt.New()

	for k, v := range claims {
		if err := t.Set(k, v); err != nil {
			return "", err
		}
	}
	hdr, err := convertHeaders(headers)
	if err != nil {
		return "", fmt.Errorf("invalid JWT headers: %w", err)
	}

	sig, err = jwt.Sign(t, jwt.WithKey(jwa.SignatureAlgorithm(alg.String()), key, jws.WithProtectedHeaders(hdr)))
	token = string(sig)

	return
}

// JWTKidAlg parses a JWT, does not validate it and returns the 'kid' and 'alg' headers
func JWTKidAlg(tokenString string) (string, jwa.SignatureAlgorithm, error) {
	j, err := jws.ParseString(tokenString)
	if err != nil {
		return "", "", err
	}

	if len(j.Signatures()) != 1 {
		return "", "", errors.New("incorrect number of signatures in JWT")
	}

	sig := j.Signatures()[0]
	hdrs := sig.ProtectedHeaders()
	return hdrs.KeyID(), hdrs.Algorithm(), nil
}

// PublicKeyFunc defines a function that resolves a public key based on a kid
type PublicKeyFunc func(kid string) (crypto.PublicKey, error)

// ParseJWT parses a token, validates and verifies it.
func ParseJWT(tokenString string, f PublicKeyFunc, options ...jwt.ParseOption) (jwt.Token, error) {
	kid, alg, err := JWTKidAlg(tokenString)
	if err != nil {
		return nil, err
	}

	key, err := f(kid)
	if err != nil {
		return nil, err
	}

	if !jwx.IsAlgorithmSupported(alg) {
		return nil, fmt.Errorf("token signing algorithm is not supported: %s", alg)
	}

	options = append(options, jwt.WithKey(alg, key))
	options = append(options, jwt.WithVerify(true))

	return jwt.ParseString(tokenString, options...)
}

// ParseJWS parses a JWS byte array object, validates and verifies it.
// This method returns the value of the payload as byte array, or an error if
// the parsing fails at any level.
func ParseJWS(token []byte, f PublicKeyFunc) (payload []byte, err error) {
	message, err := jws.Parse(token)
	if err != nil {
		return nil, err
	}
	headers, body, _, err := jws.SplitCompact(token)
	if err != nil {
		return nil, err
	}
	signatures := message.Signatures()
	for i := range signatures {
		signature := signatures[i]
		// Get and check the algorithm
		alg := signature.ProtectedHeaders().Algorithm()
		if !jwx.IsAlgorithmSupported(alg) {
			return nil, fmt.Errorf("token signing algorithm is not supported: %s", alg)
		}
		// Get the verifier for the algorithm
		verifier, err := jws.NewVerifier(alg)
		if err != nil {
			return nil, err
		}
		// Get the key id, and get the associated key
		kid := signature.ProtectedHeaders().KeyID()
		key, err := f(kid)
		if err != nil {
			return nil, err
		}
		// This seems an awkward way of appending 3 arrays.
		var payload []byte
		parts := [][]byte{headers, []byte("."), body}
		for _, part := range parts {
			payload = append(payload, part...)
		}
		err = verifier.Verify(payload, signature.Signature(), key)
		if err != nil {
			return nil, err
		}
	}

	body = message.Payload()
	return body, nil
}

func SignJWS(ctx context.Context, payload []byte, protectedHeaders map[string]interface{}, privateKey crypto.Signer, detachedPayload bool) (string, error) {
	audit.Log(ctx, log.Logger(), audit.CryptoSignJWSEvent).Infof("Signing a JWS with key: %s", protectedHeaders["kid"])
	headers := jws.NewHeaders()
	for key, value := range protectedHeaders {
		if err := headers.Set(key, value); err != nil {
			return "", fmt.Errorf("unable to set header %s: %w", key, err)
		}
	}
	// The JWX library is fine with creating a JWK for a private key (including the private exponents), so
	// we want to make sure the `jwk` header (if present) does not (accidentally) contain a private key.
	// That would lead to the node leaking its private key material in the resulting JWS which would be very, very bad.
	if headers.JWK() != nil {
		var jwkAsPrivateKey crypto.Signer
		if err := headers.JWK().Raw(&jwkAsPrivateKey); err == nil {
			// `err != nil` is good in this case, because that means the key is not assignable to crypto.Signer,
			// which is the interface implemented by all private key types.
			return "", errors.New("refusing to sign JWS with private key in JWK header")
		}
	}

	var (
		data []byte
		err  error
	)
	alg, err := SignatureAlgorithm(privateKey.Public())
	if err != nil {
		return "", err
	}

	if detachedPayload {
		// Sign JWS with detached payload
		data, err = jws.Sign(nil, jws.WithKey(alg, privateKey, jws.WithProtectedHeaders(headers)), jws.WithDetachedPayload(payload))
	} else {
		// Sign normal JWS
		data, err = jws.Sign(payload, jws.WithKey(alg, privateKey, jws.WithProtectedHeaders(headers)))
	}
	if err != nil {
		return "", fmt.Errorf("unable to sign JWS %w", err)
	}
	return string(data), nil
}

func EncryptJWE(payload []byte, protectedHeaders map[string]interface{}, publicKey interface{}) (message string, err error) {
	if publicKey == nil {
		return "", errors.New("no publicKey provided")
	}
	json, err := json.Marshal(protectedHeaders)
	if err != nil {
		return "", err
	}
	headers := jwe.NewHeaders()
	err = headers.UnmarshalJSON(json)
	if err != nil {
		return "", err
	}
	// Figure out the KeyEncryptionAlgorithm, give prevalence to the headers
	var alg jwa.KeyEncryptionAlgorithm
	if len(headers.Algorithm().String()) > 0 {
		alg = headers.Algorithm()
	} else {
		alg, err = encryptionAlgorithm(publicKey)
		if err != nil {
			return "", err
		}
	}

	// Figure out the KeyEncryptionAlgorithm, give prevalence to the headers
	enc := jwx.DefaultContentEncryptionAlgorithm
	if len(headers.ContentEncryption().String()) > 0 {
		enc = headers.ContentEncryption()
	}
	options := []jwe.EncryptOption{
		jwe.WithProtectedHeaders(headers),
		jwe.WithContentEncryption(enc),
		jwe.WithKey(alg, publicKey),
		jwe.WithCompress(headers.Compression()), // "" means no compression
	}

	encoded, err := jwe.Encrypt(payload, options...)
	return string(encoded), err
}

func (client *Crypto) getPrivateKey(ctx context.Context, kid string) (crypto.Signer, string, error) {
	privateKey, err := client.storage.GetPrivateKey(ctx, kid)
	if err != nil {
		if errors.Is(err, spi.ErrNotFound) {
			return nil, "", ErrPrivateKeyNotFound
		}
		return nil, "", err
	}
	return privateKey, kid, nil
}

func convertHeaders(headers map[string]interface{}) (jws.Headers, error) {
	hdr := jws.NewHeaders()

	for k, v := range headers {
		if err := hdr.Set(k, v); err != nil {
			return nil, err
		}
	}
	return hdr, nil
}

func signingAlg(key crypto.PublicKey) (jwa.SignatureAlgorithm, error) {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return jwa.PS256, nil
	case *ecdsa.PublicKey:
		return ecAlgUsingPublicKey(*k)
	case ed25519.PublicKey:
		return jwa.EdDSA, nil
	default:
		return "", fmt.Errorf(`could not determine signature algorithm for key type '%T'`, key)
	}
}

func ecAlgUsingPublicKey(key ecdsa.PublicKey) (alg jwa.SignatureAlgorithm, err error) {
	switch key.Params().BitSize {
	case 256:
		alg = jwa.ES256
	case 384:
		alg = jwa.ES384
	case 521:
		alg = jwa.ES512
	default:
		err = jwx.ErrUnsupportedSigningKey
	}
	return
}

// SignatureAlgorithm determines the jwa.SigningAlgorithm for ec/rsa/ed25519 keys.
func SignatureAlgorithm(key crypto.PublicKey) (jwa.SignatureAlgorithm, error) {
	if key == nil {
		return "", errors.New("no key provided")
	}

	var ptr interface{}
	switch v := key.(type) {
	case rsa.PrivateKey:
		ptr = &v
	case rsa.PublicKey:
		ptr = &v
	case ecdsa.PrivateKey:
		ptr = &v
	case ecdsa.PublicKey:
		ptr = &v
	default:
		ptr = v
	}

	switch k := ptr.(type) {
	case *rsa.PrivateKey:
		return jwa.PS256, nil
	case *rsa.PublicKey:
		return jwa.PS256, nil
	case *ecdsa.PrivateKey:
		return ecAlgUsingPublicKey(k.PublicKey)
	case *ecdsa.PublicKey:
		return ecAlgUsingPublicKey(*k)
	case ed25519.PrivateKey:
		return jwa.EdDSA, nil
	case ed25519.PublicKey:
		return jwa.EdDSA, nil
	default:
		return "", fmt.Errorf(`could not determine signature algorithm for key type '%T'`, key)
	}
}

func encryptionAlgorithm(key crypto.PublicKey) (jwa.KeyEncryptionAlgorithm, error) {

	switch key.(type) {
	case *rsa.PublicKey:
		return jwx.DefaultRsaEncryptionAlgorithm, nil
	case *ecdsa.PublicKey:
		return jwx.DefaultEcEncryptionAlgorithm, nil
	default:
		return "", fmt.Errorf("could not determine encryption algorithm for key type '%T'", key)
	}
}

// Thumbprint generates a Nuts compatible thumbprint: Base58(SHA256(rfc7638-json))
func Thumbprint(key jwk.Key) (string, error) {
	if key == nil {
		panic("Thumbprint(): key is nil")
	}
	pkHash, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base58.EncodeAlphabet(pkHash[:], base58.BTCAlphabet), nil
}
