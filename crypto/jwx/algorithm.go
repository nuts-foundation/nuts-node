package jwx

import (
	"errors"
	"github.com/lestrrat-go/jwx/v2/jwa"
)

// ErrUnsupportedSigningKey is returned when an unsupported private key is used to sign. Currently only ecdsa and rsa keys are supported
var ErrUnsupportedSigningKey = errors.New("signing key algorithm not supported")

var SupportedAlgorithms = []jwa.SignatureAlgorithm{jwa.PS256, jwa.PS384, jwa.PS512, jwa.ES256, jwa.EdDSA, jwa.ES384, jwa.ES512}

const DefaultRsaEncryptionAlgorithm = jwa.RSA_OAEP_256
const DefaultEcEncryptionAlgorithm = jwa.ECDH_ES_A256KW
const DefaultContentEncryptionAlgorithm = jwa.A256GCM

func IsAlgorithmSupported(alg jwa.SignatureAlgorithm) bool {
	for _, curr := range SupportedAlgorithms {
		if curr == alg {
			return true
		}
	}
	return false
}

func AddSupportedAlgorithm(alg jwa.SignatureAlgorithm) bool {
	SupportedAlgorithms = append(SupportedAlgorithms, alg)
	return true
}

// SupportedAlgorithmsAsStrings returns the supported algorithms as a slice of strings
func SupportedAlgorithmsAsStrings() []string {
	var result []string
	for _, alg := range SupportedAlgorithms {
		result = append(result, string(alg))
	}
	return result
}
