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

package pe

import (
	"encoding/json"
	"testing"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/pe/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testPresentationDefinition = `
{
  "id": "Definition requesting NutsOrganizationCredential",
  "input_descriptors": [
	{
	  "id": "some random ID",
	  "name": "Organization matcher",
	  "purpose": "Finding any organization in CareTown starting with 'Care'",
	  "constraints": {
		"fields": [
		  {
			"path": [
			  "$.credentialSubject.organization.city"
			],
			"filter": {
			  "type": "string",
			  "const": "IJbergen"
			}
		  },
		  {
			"path": [
			  "$.credentialSubject.organization.name"
			],
			"filter": {
			  "type": "string",
			  "pattern": "care"
			}
		  },
		  {
			"path": [
			  "$.type"
			],
			"filter": {
			  "type": "string",
			  "const": "NutsOrganizationCredential"
			}
		  }
		]
	  }
	}
  ],
  "format": {
    "jwt_vc": {
      "alg": ["ES256K", "ES384"]
    },
	"ldp_vc": {
      "proof_type": [
	    "JsonWebSignature2020"
	  ]
	}
  } 
}
`

var testCredentialString = `
{
  "type": "VerifiableCredential",
  "credentialSubject": {
	"field": "value"
  }
}`

func TestMatch(t *testing.T) {
	id1 := ssi.MustParseURI("1")
	id2 := ssi.MustParseURI("2")
	id3 := ssi.MustParseURI("3")
	id4 := ssi.MustParseURI("4")
	vc1 := vc.VerifiableCredential{ID: &id1}
	vc2 := vc.VerifiableCredential{ID: &id2}
	vc3 := vc.VerifiableCredential{ID: &id3}
	vc4 := vc.VerifiableCredential{ID: &id4}
	verifiableCredential := credential.ValidNutsOrganizationCredential(t)

	t.Run("Basic", func(t *testing.T) {
		presentationDefinition := PresentationDefinition{}
		_ = json.Unmarshal([]byte(testPresentationDefinition), &presentationDefinition)

		t.Run("Happy flow", func(t *testing.T) {
			vcs, mappingObjects, err := presentationDefinition.Match([]vc.VerifiableCredential{verifiableCredential})

			require.NoError(t, err)
			assert.Len(t, vcs, 1)
			require.Len(t, mappingObjects, 1)
			assert.Equal(t, "$.verifiableCredential[0]", mappingObjects[0].Path)
		})
		t.Run("Only second VC matches", func(t *testing.T) {
			vcs, mappingObjects, err := presentationDefinition.Match([]vc.VerifiableCredential{{Type: []ssi.URI{ssi.MustParseURI("VerifiableCredential")}}, verifiableCredential})

			require.NoError(t, err)
			assert.Len(t, vcs, 1)
			assert.Len(t, mappingObjects, 1)
		})
	})
	t.Run("Input Descriptor Claim Format matching", func(t *testing.T) {
		presentationDefinition := PresentationDefinition{}
		_ = json.Unmarshal([]byte(testPresentationDefinition), &presentationDefinition)
		// making sure this test doesn't break when testPresentationDefinition changes
		fullFormat := presentationDefinition.Format
		require.NotNil(t, fullFormat)
		require.NotNil(t, (*fullFormat)["jwt_vc"])
		require.NotNil(t, (*fullFormat)["ldp_vc"])
		t.Run("Input Descriptor format only", func(t *testing.T) {
			presentationDefinition.Format = nil
			presentationDefinition.InputDescriptors[0].Format = fullFormat

			vcs, mappingObjects, err := presentationDefinition.Match([]vc.VerifiableCredential{verifiableCredential})

			require.NoError(t, err)
			assert.Len(t, vcs, 1)
			require.Len(t, mappingObjects, 1)
			assert.Equal(t, "$.verifiableCredential[0]", mappingObjects[0].Path)
		})
		t.Run("Matches format of PD but not Input Descriptor", func(t *testing.T) {
			presentationDefinition.Format = fullFormat
			presentationDefinition.InputDescriptors[0].Format = &PresentationDefinitionClaimFormatDesignations{"jwt_vc": (*fullFormat)["jwt_vc"]}

			vcs, mappingObjects, err := presentationDefinition.Match([]vc.VerifiableCredential{verifiableCredential})

			require.NoError(t, err)
			assert.Len(t, vcs, 0)
			assert.Len(t, mappingObjects, 0)
		})
	})
	t.Run("Submission requirement feature", func(t *testing.T) {
		t.Run("Pick", func(t *testing.T) {
			t.Run("Pick 1", func(t *testing.T) {
				presentationDefinition := PresentationDefinition{}
				_ = json.Unmarshal([]byte(test.PickOne), &presentationDefinition)

				vcs, mappingObjects, err := presentationDefinition.Match([]vc.VerifiableCredential{vc1, vc2})

				require.NoError(t, err)
				assert.Len(t, vcs, 1)
				assert.Len(t, mappingObjects, 1)
			})
			t.Run("error", func(t *testing.T) {
				presentationDefinition := PresentationDefinition{}
				_ = json.Unmarshal([]byte(test.PickOne), &presentationDefinition)

				_, _, err := presentationDefinition.Match([]vc.VerifiableCredential{})

				require.Error(t, err)
				assert.EqualError(t, err, "submission requirement (Pick 1 matcher) has less credentials (0) than required (1)")
			})
		})
		t.Run("Pick min max", func(t *testing.T) {
			t.Run("Ok", func(t *testing.T) {
				presentationDefinition := PresentationDefinition{}
				_ = json.Unmarshal([]byte(test.PickMinMax), &presentationDefinition)

				vcs, mappingObjects, err := presentationDefinition.Match([]vc.VerifiableCredential{vc1, vc2})

				require.NoError(t, err)
				assert.Len(t, vcs, 2)
				assert.Len(t, mappingObjects, 2)
			})
			t.Run("error", func(t *testing.T) {
				presentationDefinition := PresentationDefinition{}
				_ = json.Unmarshal([]byte(test.PickMinMax), &presentationDefinition)

				_, _, err := presentationDefinition.Match([]vc.VerifiableCredential{})

				require.Error(t, err)
				assert.EqualError(t, err, "submission requirement (Pick 1 matcher) has less matches (0) than minimal required (1)")
			})
		})
		t.Run("Pick 1 per group", func(t *testing.T) {
			presentationDefinition := PresentationDefinition{}
			_ = json.Unmarshal([]byte(test.PickOnePerGroup), &presentationDefinition)

			vcs, mappingObjects, err := presentationDefinition.Match([]vc.VerifiableCredential{vc1, vc2})

			require.NoError(t, err)
			assert.Len(t, vcs, 2)
			assert.Len(t, mappingObjects, 2)
		})
		t.Run("Pick all", func(t *testing.T) {
			presentationDefinition := PresentationDefinition{}
			_ = json.Unmarshal([]byte(test.All), &presentationDefinition)

			vcs, mappingObjects, err := presentationDefinition.Match([]vc.VerifiableCredential{vc1, vc2})

			require.NoError(t, err)
			assert.Len(t, vcs, 2)
			assert.Len(t, mappingObjects, 2)
		})
		t.Run("Deduplicate", func(t *testing.T) {
			presentationDefinition := PresentationDefinition{}
			_ = json.Unmarshal([]byte(test.DeduplicationRequired), &presentationDefinition)

			vcs, mappingObjects, err := presentationDefinition.Match([]vc.VerifiableCredential{vc1})

			require.NoError(t, err)
			assert.Len(t, vcs, 1)
			assert.Len(t, mappingObjects, 1)
		})
		t.Run("Pick 1 from nested", func(t *testing.T) {
			presentationDefinition := PresentationDefinition{}
			_ = json.Unmarshal([]byte(test.PickOneFromNested), &presentationDefinition)

			t.Run("all from group A or all from group B", func(t *testing.T) {
				t.Run("all A", func(t *testing.T) {
					vcs, mappingObjects, err := presentationDefinition.Match([]vc.VerifiableCredential{vc1, vc2})

					require.NoError(t, err)
					assert.Len(t, vcs, 2)
					assert.Len(t, mappingObjects, 2)
				})
				t.Run("all B", func(t *testing.T) {
					vcs, mappingObjects, err := presentationDefinition.Match([]vc.VerifiableCredential{vc1, vc3, vc4})

					require.NoError(t, err)
					assert.Len(t, vcs, 2)
					assert.Len(t, mappingObjects, 2)
					assert.Equal(t, "3", vcs[0].ID.String())
				})
				t.Run("no match", func(t *testing.T) {
					vcs, _, err := presentationDefinition.Match([]vc.VerifiableCredential{vc1, vc3})

					require.Error(t, err)
					assert.Len(t, vcs, 0)
				})
			})
		})
		t.Run("All from nested", func(t *testing.T) {
			t.Run("Ok", func(t *testing.T) {
				presentationDefinition := PresentationDefinition{}
				_ = json.Unmarshal([]byte(test.AllFromNested), &presentationDefinition)

				vcs, mappingObjects, err := presentationDefinition.Match([]vc.VerifiableCredential{vc1, vc2})

				require.NoError(t, err)
				assert.Len(t, vcs, 2)
				assert.Len(t, mappingObjects, 2)
			})
			t.Run("error", func(t *testing.T) {
				presentationDefinition := PresentationDefinition{}
				_ = json.Unmarshal([]byte(test.AllFromNested), &presentationDefinition)

				_, _, err := presentationDefinition.Match([]vc.VerifiableCredential{})

				require.Error(t, err)
				assert.EqualError(t, err, "submission requirement (All from nested) does not have all credentials from the group")
			})
		})
		t.Run("Pick min max from nested", func(t *testing.T) {
			t.Run("Ok", func(t *testing.T) {
				presentationDefinition := PresentationDefinition{}
				_ = json.Unmarshal([]byte(test.PickMinMaxFromNested), &presentationDefinition)

				vcs, mappingObjects, err := presentationDefinition.Match([]vc.VerifiableCredential{vc1, vc2, vc3})

				require.NoError(t, err)
				assert.Len(t, vcs, 2)
				assert.Len(t, mappingObjects, 2)
			})
			t.Run("error", func(t *testing.T) {
				presentationDefinition := PresentationDefinition{}
				_ = json.Unmarshal([]byte(test.PickMinMaxFromNested), &presentationDefinition)

				_, _, err := presentationDefinition.Match([]vc.VerifiableCredential{})

				require.Error(t, err)
				assert.EqualError(t, err, "submission requirement (Pick 1 matcher) has less matches (0) than minimal required (1)")
			})
		})
	})
}

func Test_matchFormat(t *testing.T) {
	verifiableCredential := credential.ValidNutsOrganizationCredential(t)

	t.Run("no format", func(t *testing.T) {
		match := matchFormat(nil, vc.VerifiableCredential{})

		assert.True(t, match)
	})

	t.Run("countable format", func(t *testing.T) {
		match := matchFormat(&PresentationDefinitionClaimFormatDesignations{}, vc.VerifiableCredential{})

		assert.True(t, match)
	})

	t.Run("format with jwt_vc always returns false", func(t *testing.T) {
		asMap := map[string]map[string][]string{"jwt_vc": {"alg": {"ES256K", "ES384"}}}
		asFormat := PresentationDefinitionClaimFormatDesignations(asMap)
		match := matchFormat(&asFormat, vc.VerifiableCredential{})

		assert.False(t, match)
	})

	t.Run("format with matching ldp_vc", func(t *testing.T) {
		asMap := map[string]map[string][]string{"jwt_vc": {"alg": {"ES256K", "ES384"}}, "ldp_vc": {"proof_type": {"JsonWebSignature2020"}}}
		asFormat := PresentationDefinitionClaimFormatDesignations(asMap)
		match := matchFormat(&asFormat, verifiableCredential)

		assert.True(t, match)
	})

	t.Run("non-matching ldp_vc", func(t *testing.T) {
		asMap := map[string]map[string][]string{"jwt_vc": {"alg": {"ES256K", "ES384"}}, "ldp_vc": {"proof_type": {"Ed25519Signature2018"}}}
		asFormat := PresentationDefinitionClaimFormatDesignations(asMap)
		match := matchFormat(&asFormat, verifiableCredential)

		assert.False(t, match)
	})

	t.Run("missing proof_type", func(t *testing.T) {
		asMap := map[string]map[string][]string{"ldp_vc": {}}
		asFormat := PresentationDefinitionClaimFormatDesignations(asMap)
		match := matchFormat(&asFormat, verifiableCredential)

		assert.False(t, match)
	})
}

func Test_matchCredential(t *testing.T) {
	t.Run("no constraints is a match", func(t *testing.T) {
		match, err := matchCredential(InputDescriptor{}, vc.VerifiableCredential{})

		require.NoError(t, err)
		assert.True(t, match)
	})
}

func Test_matchConstraint(t *testing.T) {
	testCredential := vc.VerifiableCredential{}
	_ = json.Unmarshal([]byte(testCredentialString), &testCredential)

	typeVal := "VerifiableCredential"
	f1True := Field{Path: []string{"$.credentialSubject.field"}}
	f2True := Field{Path: []string{"$.type"}, Filter: &Filter{Type: "string", Const: &typeVal}}
	f3False := Field{Path: []string{"$.credentialSubject.field"}, Filter: &Filter{Type: "string", Const: &typeVal}}

	t.Run("single constraint match", func(t *testing.T) {
		match, err := matchConstraint(&Constraints{Fields: []Field{f1True}}, testCredential)

		require.NoError(t, err)
		assert.True(t, match)
	})
	t.Run("single constraint mismatch", func(t *testing.T) {
		match, err := matchConstraint(&Constraints{Fields: []Field{f3False}}, testCredential)

		require.NoError(t, err)
		assert.False(t, match)
	})
	t.Run("multi constraint match", func(t *testing.T) {
		match, err := matchConstraint(&Constraints{Fields: []Field{f1True, f2True}}, testCredential)

		require.NoError(t, err)
		assert.True(t, match)
	})
	t.Run("multi constraint, single mismatch", func(t *testing.T) {
		match, err := matchConstraint(&Constraints{Fields: []Field{f1True, f3False}}, testCredential)

		require.NoError(t, err)
		assert.False(t, match)
	})
	t.Run("error", func(t *testing.T) {
		match, err := matchConstraint(&Constraints{Fields: []Field{{Path: []string{"$$"}}}}, testCredential)

		require.Error(t, err)
		assert.False(t, match)
	})
}

func Test_matchField(t *testing.T) {
	testCredential := vc.VerifiableCredential{}
	_ = json.Unmarshal([]byte(testCredentialString), &testCredential)

	t.Run("single path match", func(t *testing.T) {
		match, err := matchField(Field{Path: []string{"$.credentialSubject.field"}}, testCredential)

		require.NoError(t, err)
		assert.True(t, match)
	})
	t.Run("multi path match", func(t *testing.T) {
		match, err := matchField(Field{Path: []string{"$.other", "$.credentialSubject.field"}}, testCredential)

		require.NoError(t, err)
		assert.True(t, match)
	})
	t.Run("no match", func(t *testing.T) {
		match, err := matchField(Field{Path: []string{"$.foo", "$.bar"}}, testCredential)

		require.NoError(t, err)
		assert.False(t, match)
	})
	t.Run("no match, but optional", func(t *testing.T) {
		trueVal := true
		match, err := matchField(Field{Path: []string{"$.foo", "$.bar"}, Optional: &trueVal}, testCredential)

		require.NoError(t, err)
		assert.True(t, match)
	})
	t.Run("invalid match and optional", func(t *testing.T) {
		trueVal := true
		stringVal := "bar"
		match, err := matchField(Field{Path: []string{"$.credentialSubject.field", "$.foo"}, Optional: &trueVal, Filter: &Filter{Const: &stringVal}}, testCredential)

		require.NoError(t, err)
		assert.False(t, match)
	})
	t.Run("valid match with Filter", func(t *testing.T) {
		stringVal := "value"
		match, err := matchField(Field{Path: []string{"$.credentialSubject.field"}, Filter: &Filter{Type: "string", Const: &stringVal}}, testCredential)

		require.NoError(t, err)
		assert.True(t, match)
	})
	t.Run("match on type", func(t *testing.T) {
		stringVal := "VerifiableCredential"
		match, err := matchField(Field{Path: []string{"$.type"}, Filter: &Filter{Type: "string", Const: &stringVal}}, testCredential)

		require.NoError(t, err)
		assert.True(t, match)
	})
	t.Run("match on type array", func(t *testing.T) {
		testCredentialString = `
{
  "type": ["VerifiableCredential"],
  "credentialSubject": {
	"field": "value"
  }
}`
		_ = json.Unmarshal([]byte(testCredentialString), &testCredential)
		stringVal := "VerifiableCredential"
		match, err := matchField(Field{Path: []string{"$.type"}, Filter: &Filter{Type: "string", Const: &stringVal}}, testCredential)

		require.NoError(t, err)
		assert.True(t, match)
	})

	t.Run("errors", func(t *testing.T) {
		t.Run("invalid path", func(t *testing.T) {
			match, err := matchField(Field{Path: []string{"$$"}}, testCredential)

			require.Error(t, err)
			assert.False(t, match)
		})
		t.Run("invalid pattern", func(t *testing.T) {
			pattern := "["
			match, err := matchField(Field{Path: []string{"$.credentialSubject.field"}, Filter: &Filter{Type: "string", Pattern: &pattern}}, testCredential)

			require.Error(t, err)
			assert.False(t, match)
		})
	})
}

func Test_matchFilter(t *testing.T) {
	// values for pointer fields
	stringValue := "test"
	boolValue := true
	intValue := 1
	floatValue := 1.0

	t.Run("type filter", func(t *testing.T) {
		fString := Filter{Type: "string"}
		fNumber := Filter{Type: "number"}
		fBoolean := Filter{Type: "boolean"}
		type testCaseDef struct {
			name   string
			filter Filter
			value  interface{}
			want   bool
		}
		testCases := []testCaseDef{
			{name: "string", filter: fString, value: stringValue, want: true},
			{name: "bool", filter: fBoolean, value: boolValue, want: true},
			{name: "number/float", filter: fNumber, value: floatValue, want: true},
			{name: "number/int", filter: fNumber, value: intValue, want: true},
			{name: "string array", filter: fString, value: []interface{}{stringValue}, want: true},
			{name: "bool array", filter: fBoolean, value: []interface{}{boolValue}, want: true},
			{name: "number/float array", filter: fNumber, value: []interface{}{floatValue}, want: true},
			{name: "number/int array", filter: fNumber, value: []interface{}{intValue}, want: true},
			{name: "string with bool", filter: fString, value: boolValue, want: false},
			{name: "string with int", filter: fString, value: intValue, want: false},
			{name: "bool with float", filter: fBoolean, value: floatValue, want: false},
			{name: "number with string", filter: fNumber, value: stringValue, want: false},
		}

		for _, testCase := range testCases {
			t.Run(testCase.name, func(t *testing.T) {
				got, err := matchFilter(testCase.filter, testCase.value)
				require.NoError(t, err)
				assert.Equal(t, testCase.want, got)
			})
		}
	})

	t.Run("string filter properties", func(t *testing.T) {
		f1 := Filter{Type: "string", Const: &stringValue}
		f2 := Filter{Type: "string", Enum: []string{stringValue}}
		f3 := Filter{Type: "string", Pattern: &stringValue}
		filters := []Filter{f1, f2, f3}
		t.Run("ok", func(t *testing.T) {
			for _, filter := range filters {
				match, err := matchFilter(filter, stringValue)
				require.NoError(t, err)
				assert.True(t, match)
			}
		})
		t.Run("enum value not found", func(t *testing.T) {
			match, err := matchFilter(f2, "foo")
			require.NoError(t, err)
			assert.False(t, match)
		})
	})

	t.Run("error cases", func(t *testing.T) {
		t.Run("enum with wrong type", func(t *testing.T) {
			f := Filter{Type: "object"}
			match, err := matchFilter(f, struct{}{})
			assert.False(t, match)
			assert.Equal(t, err, ErrUnsupportedFilter)
		})
		t.Run("incorrect regex", func(t *testing.T) {
			pattern := "["
			f := Filter{Type: "string", Pattern: &pattern}
			match, err := matchFilter(f, stringValue)
			assert.False(t, match)
			assert.Error(t, err, "error parsing regexp: missing closing ]: `[`")
			match, err = matchFilter(f, []interface{}{stringValue})
			assert.False(t, match)
			assert.Error(t, err, "error parsing regexp: missing closing ]: `[`")
		})
	})
}
