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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"embed"
	"encoding/json"
	"github.com/nuts-foundation/go-did/did"
	vcrTest "github.com/nuts-foundation/nuts-node/vcr/test"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/pe/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testCredentialString = `
{
  "type": "VerifiableCredential",
  "credentialSubject": {
	"field": "value"
  }
}`

//go:embed test/*.json
var testFiles embed.FS

type testDefinitions struct {
	JSONLD              PresentationDefinition
	JSONLDorJWT         PresentationDefinition
	JSONLDorJWTWithPick PresentationDefinition
	JWT                 PresentationDefinition
}

func definitions() testDefinitions {
	var result testDefinitions
	if data, err := testFiles.ReadFile("test/pd_jsonld.json"); err != nil {
		panic(err)
	} else {
		if err = json.Unmarshal(data, &result.JSONLD); err != nil {
			panic(err)
		}
	}
	if data, err := testFiles.ReadFile("test/pd_jsonld_jwt.json"); err != nil {
		panic(err)
	} else {
		if err = json.Unmarshal(data, &result.JSONLDorJWT); err != nil {
			panic(err)
		}
	}
	if data, err := testFiles.ReadFile("test/pd_jsonld_jwt_pick.json"); err != nil {
		panic(err)
	} else {
		if err = json.Unmarshal(data, &result.JSONLDorJWTWithPick); err != nil {
			panic(err)
		}
	}
	if data, err := testFiles.ReadFile("test/pd_jwt.json"); err != nil {
		panic(err)
	} else {
		if err = json.Unmarshal(data, &result.JWT); err != nil {
			panic(err)
		}
	}
	return result
}

func TestParsePresentationDefinition(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		definition, err := ParsePresentationDefinition([]byte(`{"id": "1", "input_descriptors":[]}`))
		require.NoError(t, err)
		assert.Equal(t, "1", definition.Id)
	})
	t.Run("missing id", func(t *testing.T) {
		_, err := ParsePresentationDefinition([]byte(`{"input_descriptors":[]}`))
		assert.ErrorContains(t, err, `missing properties: "id"`)
	})
}

func TestEmployeeCredential(t *testing.T) {
	pd, err := ParsePresentationDefinition([]byte(`{
      "format": {
        "ldp_vc": {
          "proof_type": [
            "JsonWebSignature2020"
          ]
        },
        "ldp_vp": {
          "proof_type": [
            "JsonWebSignature2020"
          ]
        },
        "jwt_vc": {
          "alg": [
            "ES256"
          ]
        },
        "jwt_vp": {
          "alg": [
            "ES256"
          ]
        }
      },
      "id": "pd_any_employee_credential",
      "name": "Employee",
      "purpose": "Finding an employee for authorizing access to medical metadata",
      "input_descriptors": [
        {
          "id": "id_employee_credential_cred",
          "constraints": {
            "fields": [
              {
                "path": [
                  "$.type"
                ],
                "filter": {
                  "type": "string",
                  "const": "EmployeeCredential"
                }
              },
              {
                "id": "employee_identifier",
                "path": [
                  "$.credentialSubject.identifier",
                  "$.credentialSubject[0].identifier"
                ],
                "filter": {
                  "type": "string"
                }
              },
              {
                "id": "employee_name",
                "path": [
                  "$.credentialSubject.name",
                  "$.credentialSubject[0].name"
                ],
                "filter": {
                  "type": "string"
                }
              },
              {
                "id": "employee_role",
                "path": [
                  "$.credentialSubject.roleName",
                  "$.credentialSubject[0].roleName"
                ],
                "filter": {
                  "type": "string"
                }
              }
            ]
          }
        }
      ]
    }`))
	require.NoError(t, err)
	cred, err := vc.ParseVerifiableCredential(`eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDp3ZWI6bm9kZUE6aWFtOnJlcXVlc3RlciMwIiwidHlwIjoiSldUIn0.eyJleHAiOjE3MTI1NzI2MTIsImlzcyI6ImRpZDp3ZWI6bm9kZUE6aWFtOnJlcXVlc3RlciIsImp0aSI6ImRpZDp3ZWI6bm9kZUE6aWFtOnJlcXVlc3RlciM4ZjNkMWI0OS1iODYzLTQxZjYtYmY4Ny05ZTVhODY2YWMyMzEiLCJuYmYiOjE3MTI1NjkwMTIsInN1YiI6ImRpZDpqd2s6ZXlKamNuWWlPaUpRTFRJMU5pSXNJbXQwZVNJNklrVkRJaXdpZUNJNklsOVFVVk5TVkY5UmRFWmpOMFpvU0VwUGFGVXRibEJ2TVVaNGRFZDRTRmRqUzJ0b2FqUTVhRE5hT1VVaUxDSjVJam9pTmpoek16TTFOVkJIYm5CcVVVSkVNamRKTjE4NVpFUnpkRzU2TVVwZlZtZzNZVlprUlVOVlNHOXpRU0o5IiwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL251dHMubmwvY3JlZGVudGlhbHMvdjEiXSwiY3JlZGVudGlhbFN1YmplY3QiOlt7ImlkIjoiZGlkOmp3azpleUpqY25ZaU9pSlFMVEkxTmlJc0ltdDBlU0k2SWtWRElpd2llQ0k2SWw5UVVWTlNWRjlSZEVaak4wWm9TRXBQYUZVdGJsQnZNVVo0ZEVkNFNGZGpTMnRvYWpRNWFETmFPVVVpTENKNUlqb2lOamh6TXpNMU5WQkhibkJxVVVKRU1qZEpOMTg1WkVSemRHNTZNVXBmVm1nM1lWWmtSVU5WU0c5elFTSjkiLCJpZGVudGlmaWVyIjoiamRvZUBleGFtcGxlLmNvbSIsIm5hbWUiOiJKb2huIERvZSIsInJvbGVOYW1lIjoiQWNjb3VudGFudCJ9XSwidHlwZSI6WyJFbXBsb3llZUNyZWRlbnRpYWwiLCJWZXJpZmlhYmxlQ3JlZGVudGlhbCJdfX0.6VeGDsTEy2BpQW3RKCiczIVoAAdlfl_EP4KioE9lavWIuXTASTAPkcY9oOlfG_HFLZvu82Nnt6L-ntK8XzR7Ew`)

	credentials, _, err := pd.Match([]vc.VerifiableCredential{*cred})

	require.NoError(t, err)
	require.Len(t, credentials, 1)
}

func TestMatch(t *testing.T) {
	jsonldVC := vcrTest.ValidNutsOrganizationCredential(t)
	jwtVC := vcrTest.JWTNutsOrganizationCredential(t, did.MustParseDID("did:web:example.com"))

	t.Run("Basic", func(t *testing.T) {
		t.Run("JSON-LD", func(t *testing.T) {
			t.Run("Happy flow", func(t *testing.T) {
				vcs, mappingObjects, err := definitions().JSONLD.Match([]vc.VerifiableCredential{jsonldVC})

				require.NoError(t, err)
				assert.Len(t, vcs, 1)
				require.Len(t, mappingObjects, 1)
				assert.Equal(t, "$.verifiableCredential[0]", mappingObjects[0].Path)
			})
			t.Run("Only second VC matches", func(t *testing.T) {
				vcs, mappingObjects, err := definitions().JSONLD.Match([]vc.VerifiableCredential{{Type: []ssi.URI{ssi.MustParseURI("VerifiableCredential")}}, jsonldVC})

				require.NoError(t, err)
				assert.Len(t, vcs, 1)
				assert.Len(t, mappingObjects, 1)
			})
		})
		t.Run("JWT", func(t *testing.T) {
			t.Run("Happy flow", func(t *testing.T) {
				vcs, mappingObjects, err := definitions().JWT.Match([]vc.VerifiableCredential{jwtVC})
				require.NoError(t, err)
				assert.Len(t, vcs, 1)
				require.Len(t, mappingObjects, 1)
				assert.Equal(t, "$.verifiableCredential[0]", mappingObjects[0].Path)
			})
			t.Run("unsupported JOSE alg", func(t *testing.T) {
				token := jwt.New()
				privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				signedToken, err := jwt.Sign(token, jwt.WithKey(jwa.ES256, privateKey))
				require.NoError(t, err)
				jwtCredential, err := vc.ParseVerifiableCredential(string(signedToken))
				require.NoError(t, err)

				vcs, mappingObjects, err := definitions().JWT.Match([]vc.VerifiableCredential{*jwtCredential})

				assert.NoError(t, err)
				assert.Empty(t, vcs)
				assert.Empty(t, mappingObjects)
			})
		})
	})
	t.Run("Input Descriptor Claim Format matching", func(t *testing.T) {
		// making sure this test doesn't break when testPresentationDefinition changes
		presentationDefinition := definitions().JSONLDorJWT
		fullFormat := presentationDefinition.Format
		require.NotNil(t, fullFormat)
		require.NotNil(t, (*fullFormat)["jwt_vc"])
		require.NotNil(t, (*fullFormat)["ldp_vc"])
		t.Run("Input Descriptor format only", func(t *testing.T) {
			presentationDefinition.Format = nil
			presentationDefinition.InputDescriptors[0].Format = fullFormat

			vcs, mappingObjects, err := presentationDefinition.Match([]vc.VerifiableCredential{jsonldVC})

			require.NoError(t, err)
			assert.Len(t, vcs, 1)
			require.Len(t, mappingObjects, 1)
			assert.Equal(t, "$.verifiableCredential[0]", mappingObjects[0].Path)
		})
		t.Run("Matches format of PD but not Input Descriptor", func(t *testing.T) {
			presentationDefinition.Format = fullFormat
			presentationDefinition.InputDescriptors[0].Format = &PresentationDefinitionClaimFormatDesignations{"jwt_vc": (*fullFormat)["jwt_vc"]}

			vcs, mappingObjects, err := presentationDefinition.Match([]vc.VerifiableCredential{jsonldVC})

			require.NoError(t, err)
			assert.Len(t, vcs, 0)
			assert.Len(t, mappingObjects, 0)
		})
	})
	t.Run("Submission requirement feature", func(t *testing.T) {
		id1 := ssi.MustParseURI("1")
		id2 := ssi.MustParseURI("2")
		id3 := ssi.MustParseURI("3")
		id4 := ssi.MustParseURI("4")
		vc1 := credentialToJSONLD(vc.VerifiableCredential{ID: &id1})
		vc2 := credentialToJSONLD(vc.VerifiableCredential{ID: &id2})
		vc3 := credentialToJSONLD(vc.VerifiableCredential{ID: &id3})
		vc4 := credentialToJSONLD(vc.VerifiableCredential{ID: &id4})

		t.Run("Pick", func(t *testing.T) {
			t.Run("Pick 1", func(t *testing.T) {
				presentationDefinition := PresentationDefinition{}
				_ = json.Unmarshal([]byte(test.PickOne), &presentationDefinition)

				vcs, mappingObjects, err := presentationDefinition.Match([]vc.VerifiableCredential{vc1, vc2})

				require.NoError(t, err)
				assert.Len(t, vcs, 1)
				assert.Len(t, mappingObjects, 1)
			})
			t.Run("choose JSON-LD (with multiple 'path's)", func(t *testing.T) {
				vcs, mappingObjects, err := definitions().JSONLDorJWT.Match([]vc.VerifiableCredential{jsonldVC})

				require.NoError(t, err)
				assert.Len(t, vcs, 1)
				require.Len(t, mappingObjects, 1)
			})
			t.Run("choose JWT(with multiple 'path's)", func(t *testing.T) {
				vcs, mappingObjects, err := definitions().JSONLDorJWT.Match([]vc.VerifiableCredential{jwtVC})

				require.NoError(t, err)
				assert.Len(t, vcs, 1)
				require.Len(t, mappingObjects, 1)
			})
			t.Run("choose JSON-LD (with 'pick')", func(t *testing.T) {
				vcs, mappingObjects, err := definitions().JSONLDorJWTWithPick.Match([]vc.VerifiableCredential{jsonldVC})

				require.NoError(t, err)
				assert.Len(t, vcs, 1)
				require.Len(t, mappingObjects, 1)
			})
			t.Run("choose JWT (with 'pick')", func(t *testing.T) {
				vcs, mappingObjects, err := definitions().JSONLDorJWTWithPick.Match([]vc.VerifiableCredential{jwtVC})

				require.NoError(t, err)
				assert.Len(t, vcs, 1)
				require.Len(t, mappingObjects, 1)
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

func TestPresentationDefinition_CredentialsRequired(t *testing.T) {
	t.Run("no input descriptors", func(t *testing.T) {
		pd := PresentationDefinition{}
		assert.False(t, pd.CredentialsRequired())
	})
	t.Run("input descriptors", func(t *testing.T) {
		pd := PresentationDefinition{InputDescriptors: []*InputDescriptor{{}}}
		assert.True(t, pd.CredentialsRequired())
	})
	t.Run("submission requirements", func(t *testing.T) {
		pd := PresentationDefinition{SubmissionRequirements: []*SubmissionRequirement{{Rule: "all"}}}
		assert.True(t, pd.CredentialsRequired())
	})
	t.Run("submission requirement with min=0", func(t *testing.T) {
		none := 0
		pd := PresentationDefinition{SubmissionRequirements: []*SubmissionRequirement{{Rule: "pick", Min: &none}}}
		assert.False(t, pd.CredentialsRequired())
	})
}

func Test_matchFormat(t *testing.T) {
	t.Run("no format", func(t *testing.T) {
		match := matchFormat(nil, vc.VerifiableCredential{})

		assert.True(t, match)
	})

	t.Run("countable format", func(t *testing.T) {
		match := matchFormat(&PresentationDefinitionClaimFormatDesignations{}, credentialToJSONLD(vc.VerifiableCredential{}))

		assert.True(t, match)
	})

	t.Run("JWT", func(t *testing.T) {
		// JWT example credential taken from VC data model (expired)
		const jwtCredential = `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDpleGFtcGxlOmFiZmUxM2Y3MTIxMjA0
MzFjMjc2ZTEyZWNhYiNrZXlzLTEifQ.eyJzdWIiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxY
zI3NmUxMmVjMjEiLCJqdGkiOiJodHRwOi8vZXhhbXBsZS5lZHUvY3JlZGVudGlhbHMvMzczMiIsImlzc
yI6Imh0dHBzOi8vZXhhbXBsZS5jb20va2V5cy9mb28uandrIiwibmJmIjoxNTQxNDkzNzI0LCJpYXQiO
jE1NDE0OTM3MjQsImV4cCI6MTU3MzAyOTcyMywibm9uY2UiOiI2NjAhNjM0NUZTZXIiLCJ2YyI6eyJAY
29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd
3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL2V4YW1wbGVzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZ
UNyZWRlbnRpYWwiLCJVbml2ZXJzaXR5RGVncmVlQ3JlZGVudGlhbCJdLCJjcmVkZW50aWFsU3ViamVjd
CI6eyJkZWdyZWUiOnsidHlwZSI6IkJhY2hlbG9yRGVncmVlIiwibmFtZSI6IjxzcGFuIGxhbmc9J2ZyL
UNBJz5CYWNjYWxhdXLDqWF0IGVuIG11c2lxdWVzIG51bcOpcmlxdWVzPC9zcGFuPiJ9fX19.KLJo5GAy
BND3LDTn9H7FQokEsUEi8jKwXhGvoN3JtRa51xrNDgXDb0cq1UTYB-rK4Ft9YVmR1NI_ZOF8oGc_7wAp
8PHbF2HaWodQIoOBxxT-4WNqAxft7ET6lkH-4S6Ux3rSGAmczMohEEf8eCeN-jC8WekdPl6zKZQj0YPB
1rx6X0-xlFBs7cl6Wt8rfBP_tZ9YgVWrQmUWypSioc0MUyiphmyEbLZagTyPlUyflGlEdqrZAv6eSe6R
txJy6M1-lD7a5HTzanYTWBPAUHDZGyGKXdJw-W_x0IWChBzI8t3kpG253fg6V3tPgHeKXE94fz_QpYfg
--7kLsyBAfQGbg`
		verifiableCredential, err := vc.ParseVerifiableCredential(jwtCredential)
		require.NoError(t, err)
		t.Run("alg match", func(t *testing.T) {
			asMap := map[string]map[string][]string{"jwt_vc": {"alg": {"RS256"}}}
			asFormat := PresentationDefinitionClaimFormatDesignations(asMap)
			match := matchFormat(&asFormat, *verifiableCredential)

			assert.True(t, match)
		})
		t.Run("no alg match", func(t *testing.T) {
			asMap := map[string]map[string][]string{"jwt_vc": {"alg": {"ES256K", "ES384"}}}
			asFormat := PresentationDefinitionClaimFormatDesignations(asMap)
			match := matchFormat(&asFormat, *verifiableCredential)

			assert.False(t, match)
		})
		t.Run("missing proof_type", func(t *testing.T) {
			asMap := map[string]map[string][]string{"jwt_vc": {}}
			asFormat := PresentationDefinitionClaimFormatDesignations(asMap)
			match := matchFormat(&asFormat, *verifiableCredential)

			assert.False(t, match)
		})
	})

	t.Run("JSON-LD", func(t *testing.T) {
		verifiableCredential := vcrTest.ValidNutsOrganizationCredential(t)

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

	credSubjectFieldID := "credential_subject_field"
	typeVal := "VerifiableCredential"
	f1True := Field{Id: &credSubjectFieldID, Path: []string{"$.credentialSubject.field"}}
	f1TrueWithoutID := Field{Path: []string{"$.credentialSubject.field"}}
	f2True := Field{Path: []string{"$.type"}, Filter: &Filter{Type: "string", Const: &typeVal}}
	f3False := Field{Path: []string{"$.credentialSubject.field"}, Filter: &Filter{Type: "string", Const: &typeVal}}
	fieldMap := map[string]interface{}{credSubjectFieldID: "value"}

	t.Run("single constraint match", func(t *testing.T) {
		match, value, err := matchConstraint(&Constraints{Fields: []Field{f1True}}, testCredential)

		require.NoError(t, err)
		assert.Equal(t, fieldMap, value)
		assert.True(t, match)
	})
	t.Run("field match without ID is not included in values map", func(t *testing.T) {
		match, values, err := matchConstraint(&Constraints{Fields: []Field{f1TrueWithoutID}}, testCredential)

		require.NoError(t, err)
		assert.Empty(t, values)
		assert.True(t, match)
	})
	t.Run("single constraint mismatch", func(t *testing.T) {
		match, values, err := matchConstraint(&Constraints{Fields: []Field{f3False}}, testCredential)

		require.NoError(t, err)
		assert.Nil(t, values)
		assert.False(t, match)
	})
	t.Run("multi constraint match", func(t *testing.T) {
		match, values, err := matchConstraint(&Constraints{Fields: []Field{f1True, f2True}}, testCredential)

		require.NoError(t, err)
		assert.Equal(t, fieldMap, values)
		assert.True(t, match)
	})
	t.Run("multi constraint, single mismatch", func(t *testing.T) {
		match, values, err := matchConstraint(&Constraints{Fields: []Field{f1True, f3False}}, testCredential)

		require.NoError(t, err)
		assert.Nil(t, values)
		assert.False(t, match)
	})
	t.Run("error", func(t *testing.T) {
		match, values, err := matchConstraint(&Constraints{Fields: []Field{{Path: []string{"$$"}}}}, testCredential)

		require.Error(t, err)
		assert.Nil(t, values)
		assert.False(t, match)
	})
}

func Test_matchField(t *testing.T) {
	testCredential, err := vc.ParseVerifiableCredential(testCredentialString)
	require.NoError(t, err)
	testCredentialMap, _ := remarshalToMap(testCredential)

	t.Run("single path match", func(t *testing.T) {
		match, value, err := matchField(Field{Path: []string{"$.credentialSubject.field"}}, testCredentialMap)

		require.NoError(t, err)
		assert.Equal(t, "value", value)
		assert.True(t, match)
	})
	t.Run("multi path match", func(t *testing.T) {
		match, value, err := matchField(Field{Path: []string{"$.other", "$.credentialSubject.field"}}, testCredentialMap)

		require.NoError(t, err)
		assert.Equal(t, "value", value)
		assert.True(t, match)
	})
	t.Run("no match", func(t *testing.T) {
		match, value, err := matchField(Field{Path: []string{"$.foo", "$.bar"}}, testCredentialMap)

		require.NoError(t, err)
		assert.Nil(t, value)
		assert.False(t, match)
	})
	t.Run("no match, but optional", func(t *testing.T) {
		trueVal := true
		match, value, err := matchField(Field{Path: []string{"$.foo", "$.bar"}, Optional: &trueVal}, testCredentialMap)

		require.NoError(t, err)
		assert.Nil(t, value)
		assert.True(t, match)
	})
	t.Run("invalid match and optional", func(t *testing.T) {
		trueVal := true
		stringVal := "bar"
		match, value, err := matchField(Field{Path: []string{"$.credentialSubject.field", "$.foo"}, Optional: &trueVal, Filter: &Filter{Const: &stringVal}}, testCredentialMap)

		require.NoError(t, err)
		assert.Nil(t, value)
		assert.False(t, match)
	})
	t.Run("valid match with Filter", func(t *testing.T) {
		stringVal := "value"
		match, value, err := matchField(Field{Path: []string{"$.credentialSubject.field"}, Filter: &Filter{Type: "string", Const: &stringVal}}, testCredentialMap)

		require.NoError(t, err)
		assert.Equal(t, stringVal, value)
		assert.True(t, match)
	})
	t.Run("match on type", func(t *testing.T) {
		stringVal := "VerifiableCredential"
		match, value, err := matchField(Field{Path: []string{"$.type"}, Filter: &Filter{Type: "string", Const: &stringVal}}, testCredentialMap)

		require.NoError(t, err)
		assert.Equal(t, stringVal, value)
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
		_ = json.Unmarshal([]byte(testCredentialString), &testCredentialMap)
		stringVal := "VerifiableCredential"
		match, value, err := matchField(Field{Path: []string{"$.type"}, Filter: &Filter{Type: "string", Const: &stringVal}}, testCredentialMap)

		require.NoError(t, err)
		assert.Equal(t, []interface{}{"VerifiableCredential"}, value)
		assert.True(t, match)
	})

	t.Run("errors", func(t *testing.T) {
		t.Run("invalid path", func(t *testing.T) {
			match, value, err := matchField(Field{Path: []string{"$$"}}, testCredentialMap)

			require.Error(t, err)
			assert.Nil(t, value)
			assert.False(t, match)
		})
		t.Run("invalid pattern", func(t *testing.T) {
			pattern := "["
			match, value, err := matchField(Field{Path: []string{"$.credentialSubject.field"}, Filter: &Filter{Type: "string", Pattern: &pattern}}, testCredentialMap)

			require.Error(t, err)
			assert.Nil(t, value)
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

func TestPresentationDefinition_ResolveConstraintsFields(t *testing.T) {
	subjectDID := did.MustParseDID("did:web:example.com")
	jwtCredential := vcrTest.JWTNutsOrganizationCredential(t, subjectDID)
	jsonldCredential := vcrTest.JWTNutsOrganizationCredential(t, subjectDID)
	definition := definitions().JSONLDorJWT
	t.Run("match JWT", func(t *testing.T) {
		credentialMap := map[string]vc.VerifiableCredential{
			"organization_credential": jwtCredential,
		}

		fieldValues, _ := definition.ResolveConstraintsFields(credentialMap)

		require.Len(t, fieldValues, 2)
		assert.Equal(t, "IJbergen", fieldValues["credentialsubject_organization_city"])
		assert.Equal(t, "care", fieldValues["credentialsubject_organization_name"])
	})
	t.Run("match JSON-LD", func(t *testing.T) {
		credentialMap := map[string]vc.VerifiableCredential{
			"organization_credential": jsonldCredential,
		}

		fieldValues, _ := definition.ResolveConstraintsFields(credentialMap)

		require.Len(t, fieldValues, 2)
		assert.Equal(t, "IJbergen", fieldValues["credentialsubject_organization_city"])
		assert.Equal(t, "care", fieldValues["credentialsubject_organization_name"])
	})
	t.Run("input descriptor without constraints", func(t *testing.T) {
		format := PresentationDefinitionClaimFormatDesignations(map[string]map[string][]string{"jwt_vc": {"alg": {"ES256"}}})
		definition := PresentationDefinition{
			InputDescriptors: []*InputDescriptor{
				{
					Id:     "any_credential",
					Format: &format,
				},
			},
		}
		credentialMap := map[string]vc.VerifiableCredential{
			"any_credential": jwtCredential,
		}

		fieldValues, err := definition.ResolveConstraintsFields(credentialMap)

		require.NoError(t, err)
		assert.Empty(t, fieldValues)
	})
}

func credentialToJSONLD(credential vc.VerifiableCredential) vc.VerifiableCredential {
	bytes, err := credential.MarshalJSON()
	if err != nil {
		panic(err)
	}
	var result vc.VerifiableCredential
	err = json.Unmarshal(bytes, &result)
	if err != nil {
		panic(err)
	}
	return result
}
