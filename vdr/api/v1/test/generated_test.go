/*
 * Copyright (C) 2022 Nuts community
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

package v1

import (
	"encoding/json"
	"github.com/nuts-foundation/go-did/did"
	"github.com/stretchr/testify/assert"
	"testing"
)

// Test_OASCompatibleWithDIDModel tests that the OpenAPI specification is compatible with the DID model as implemented by the go-did library.
// Since (un)marshalling DID documents is quite complex due to the dynamic nature of the contents and fields that can contain either a single or multiple values,
// we alias the API type for DIDDocument to the type provided by go-did. However, this way we can't guarantee the correctness of the OAS for DIDDocument (and child types, such as Service).
// This test ensures that the model generated from the OAS specification can be (un)marshalled by the go-did library.
func Test_OASCompatibleWithDIDModel(t *testing.T) {
	var controller interface{} = "did:example:controller"
	expected := DIDDocument{
		Context: []interface{}{
			"https://www.w3.org/ns/did/v1",
			"https://www.w3.org/ns/did/v2",
		},
		AssertionMethod: &[]string{
			"did:example:123456789abcdefghi#vm",
		},
		Authentication: &[]string{
			"did:example:123456789abcdefghi#vm",
		},
		CapabilityDelegation: &[]string{
			"did:example:123456789abcdefghi#vm",
		},
		CapabilityInvocation: &[]string{
			"did:example:123456789abcdefghi#vm",
		},
		KeyAgreement: &[]string{
			"did:example:123456789abcdefghi#vm",
		},
		VerificationMethod: &[]VerificationMethod{
			{
				Id:   "did:example:123456789abcdefghi#vm",
				Type: "Secp256k1VerificationKey2018",
				Controller: "did:example:123456789abcdefghi",
			},
		},
		Controller: &controller,
		Id:         "did:example:123456789abcdefghi",
		Service: &[]Service{
			{
				Id:              "example",
				ServiceEndpoint: "foo",
				Type:            "type",
			},
		},
	}

	expectedAsBytes, err := json.Marshal(expected)
	if !assert.NoError(t, err) {
		return
	}

	// Unmarshal and then marshal as correctly implemented DIDDocument, simulating a client calling the Nuts node
	var intermediate did.Document
	println(string(expectedAsBytes))
	err = json.Unmarshal(expectedAsBytes, &intermediate)
	if !assert.NoError(t, err) {
		return
	}
	intermediateAsBytes, err := json.Marshal(intermediate)
	if !assert.NoError(t, err) {
		return
	}

	// Now unmarshal as the generated type, result should be equal to the constructed, generated DIDDocument
	var actual DIDDocument
	err = json.Unmarshal(intermediateAsBytes, &actual)
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, expected, actual)
}
