package didion

import (
	"crypto/ecdsa"
	"crypto/x509"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/go-did/did"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_Secp256k1(t *testing.T) {
	// Generated key:
	asJSON := `{
		"crv": "secp256k1",
		"d": "Rks5OexPzxLt_67LlXjvdIFwYEnWayf7sN6duZhTl80",
		"kty": "EC",
		"x": "gLxluqM0ov_d8ujWWrNtMAdeLtj3VeaOAE8rZlRBnnk",
		"y": "fN3egGXtBfy6FpSaL6AqWB8rPyCFN2445t53J9hkR4g"
	}`
	privateKeyJWK, err := jwk.ParseKey([]byte(asJSON))
	require.NoError(t, err)
	var privateKey ecdsa.PrivateKey
	err = privateKeyJWK.Raw(&privateKey)
	require.NoError(t, err)
	pemBytes, err := x509.MarshalECPrivateKey(&privateKey)
	require.NoError(t, err)
	t.Logf(string(pemBytes))

	//privateKey, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	//
	//publicKeyJWK, err := jwk.New(privateKey)
	//require.NoError(t, err)
	//publicKeyJSON, err := json.MarshalIndent(publicKeyJWK, "", "  ")
	//require.NoError(t, err)
	//println(string(publicKeyJSON))

}

func Test_Resolver_DIDION(t *testing.T) {
	document, _, err := UniversalResolver{}.Resolve(did.MustParseDID("did:ion:EiCN5kEBzpgnw_hbn4QNA1GE-PQbqLqv40Ewoq7wEvaj0w"), nil)
	require.NoError(t, err)
	require.NotNil(t, document)
	assert.Equal(t, "did:ion:EiCN5kEBzpgnw_hbn4QNA1GE-PQbqLqv40Ewoq7wEvaj0w", document.ID.String())
}

func Test_unmarshalResult(t *testing.T) {
	const input = `{"@context":"https://w3id.org/did-resolution/v1","didDocument":{"id":"did:ion:EiCN5kEBzpgnw_hbn4QNA1GE-PQbqLqv40Ewoq7wEvaj0w","@context":["https://www.w3.org/ns/did/v1",{"@base":"did:ion:EiCN5kEBzpgnw_hbn4QNA1GE-PQbqLqv40Ewoq7wEvaj0w"}],"service":[],"verificationMethod":[{"id":"#key-1","controller":"did:ion:EiCN5kEBzpgnw_hbn4QNA1GE-PQbqLqv40Ewoq7wEvaj0w","type":"EcdsaSecp256k1VerificationKey2019","publicKeyJwk":{"crv":"secp256k1","kty":"EC","x":"gLxluqM0ov_d8ujWWrNtMAdeLtj3VeaOAE8rZlRBnnk","y":"fN3egGXtBfy6FpSaL6AqWB8rPyCFN2445t53J9hkR4g"}}],"authentication":["#key-1"]},"didResolutionMetadata":{"contentType":"application/did+ld+json","pattern":"^(did:ion:(?!test).+)$","driverUrl":"http://driver-did-ion:8080/1.0/identifiers/","duration":8,"did":{"didString":"did:ion:EiCN5kEBzpgnw_hbn4QNA1GE-PQbqLqv40Ewoq7wEvaj0w","methodSpecificId":"EiCN5kEBzpgnw_hbn4QNA1GE-PQbqLqv40Ewoq7wEvaj0w","method":"ion"}},"didDocumentMetadata":{"method":{"published":true,"recoveryCommitment":"EiCItHLs3TQ1uv12FSgxiG77HT2LYMbGkvlGwvZbRtALMg","updateCommitment":"EiCItHLs3TQ1uv12FSgxiG77HT2LYMbGkvlGwvZbRtALMg"},"canonicalId":"did:ion:EiCN5kEBzpgnw_hbn4QNA1GE-PQbqLqv40Ewoq7wEvaj0w"}}`
	document, metadata, err := unmarshalResult([]byte(input))
	require.NoError(t, err)
	require.NotNil(t, document)
	require.NotNil(t, metadata)
}
