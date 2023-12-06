package oauth

// algValuesSupported contains a list of supported cipher suites for jwt_vc_json & jwt_vp_json presentation formats
// Recommended list of options https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms
// TODO: validate list, should reflect current recommendations from https://www.ncsc.nl
var algValuesSupported = []string{"PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}

// proofTypeValuesSupported contains a list of supported cipher suites for ldp_vc & ldp_vp presentation formats
// Recommended list of options https://w3c-ccg.github.io/ld-cryptosuite-registry/
var proofTypeValuesSupported = []string{"JsonWebSignature2020"}

// DefaultOpenIDSupportedFormats returns the OpenID formats supported by the Nuts node and is used in the
//   - Authorization Server's metadata field `vp_formats_supported`
//   - Client's metadata field `vp_formats`
//
// TODO: spec is very unclear about this part.
// See https://github.com/nuts-foundation/nuts-node/issues/2447
func DefaultOpenIDSupportedFormats() map[string]map[string][]string {
	return map[string]map[string][]string{
		"jwt_vp_json": {"alg_values_supported": algValuesSupported},
		"jwt_vc_json": {"alg_values_supported": algValuesSupported},
		"ldp_vc":      {"proof_type_values_supported": proofTypeValuesSupported},
		"ldp_vp":      {"proof_type_values_supported": proofTypeValuesSupported},
	}
}
