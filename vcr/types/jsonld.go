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

package types

import (
	"encoding/json"
	"github.com/nuts-foundation/go-did/vc"
)

// CompactingVerifiableCredential is a type to use from within the API, which compacts JSON-LD arrays.
// It retains backwards compatibility for JSON-LD array compacting, which was removed in the go-did v0.10.0 upgrade.
// This essentially retains the behavior that was removed in https://github.com/nuts-foundation/go-did/pull/98
// It only applies to JSON-LD; in case of JWT, the credential is returned as-is.
type CompactingVerifiableCredential vc.VerifiableCredential

func (v *CompactingVerifiableCredential) UnmarshalJSON(bytes []byte) error {
	var result vc.VerifiableCredential
	if err := json.Unmarshal(bytes, &result); err != nil {
		return nil
	}
	*v = CompactingVerifiableCredential(result)
	return nil
}

func (v CompactingVerifiableCredential) MarshalJSON() ([]byte, error) {
	if vc.VerifiableCredential(v).Format() == vc.JWTCredentialProofFormat {
		return json.Marshal(vc.VerifiableCredential(v))
	}
	// compact JSON-LD arrays
	data, _ := json.Marshal(vc.VerifiableCredential(v))
	asMap := make(map[string]interface{})
	_ = json.Unmarshal(data, &asMap)
	asMap["@context"] = compact(asMap["@context"])
	asMap["type"] = compact(asMap["type"])
	asMap["credentialSubject"] = compact(asMap["credentialSubject"])
	asMap["proof"] = compact(asMap["proof"])
	return json.Marshal(asMap)
}

func compact(value interface{}) interface{} {
	if array, isArray := value.([]interface{}); isArray && len(array) == 1 {
		return array[0]
	}
	return value
}

// CompactingVerifiablePresentation is like CompactingVerifiableCredential, but for VerifiablePresentation.
type CompactingVerifiablePresentation vc.VerifiablePresentation

func (v *CompactingVerifiablePresentation) UnmarshalJSON(bytes []byte) error {
	var result vc.VerifiablePresentation
	if err := json.Unmarshal(bytes, &result); err != nil {
		return nil
	}
	*v = CompactingVerifiablePresentation(result)
	return nil
}

func (v CompactingVerifiablePresentation) MarshalJSON() ([]byte, error) {
	if vc.VerifiablePresentation(v).Format() == vc.JWTPresentationProofFormat {
		return json.Marshal(vc.VerifiablePresentation(v))
	}
	var vcs []CompactingVerifiableCredential
	for _, credential := range v.VerifiableCredential {
		vcs = append(vcs, CompactingVerifiableCredential(credential))
	}
	data, _ := json.Marshal(vcs)
	var vcsAsInterface interface{}
	_ = json.Unmarshal(data, &vcsAsInterface)

	data, _ = json.Marshal(vc.VerifiablePresentation(v))
	asMap := make(map[string]interface{})
	_ = json.Unmarshal(data, &asMap)
	asMap["@context"] = compact(asMap["@context"])
	asMap["type"] = compact(asMap["type"])
	asMap["verifiableCredential"] = compact(vcsAsInterface)
	asMap["proof"] = compact(asMap["proof"])
	return json.Marshal(asMap)
}
