package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/google/uuid"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestSQLCredentialStore(t *testing.T) {
	logrus.SetLevel(logrus.TraceLevel)
	container, db, err := startDatabase()
	require.NoError(t, err)
	defer func() {
		t.Log("Shutting down database")
		container.Terminate(context.Background())
	}()
	resetDatabaseAfterTest := func(t *testing.T) {
		t.Cleanup(func() {
			_, err := db.Exec("DELETE FROM verifiable_credentials")
			if err != nil {
				panic(err)
			}
		})
	}

	jsonldInstance := jsonld.NewJSONLDInstance()
	err = jsonldInstance.(core.Configurable).Configure(*core.NewServerConfig())
	require.NoError(t, err)

	for _, role := range []Role{RoleIssuer, RoleHolderVerifier} {
		t.Run(string(role), func(t *testing.T) {
			t.Run("store, then get", func(t *testing.T) {
				resetDatabaseAfterTest(t)
				store, err := NewSQLCredentialStore(db, role, jsonldInstance.DocumentLoader())
				require.NoError(t, err)

				cred := createVC()

				// First, write
				err = store.StoreCredential(cred)
				require.NoError(t, err)

				// Then, get by ID
				actual, err := store.GetCredential(*cred.ID)
				require.NoError(t, err)
				assertCredentialEqual(t, cred, *actual)
			})
			t.Run("SearchCredentials", func(t *testing.T) {
				search := func(t *testing.T, expected vc.VerifiableCredential,
					queryFn func(query *vc.VerifiableCredential),
					asserterFn func(actual vc.VerifiableCredential),
					filterOnType bool,
				) {
					resetDatabaseAfterTest(t)
					store, err := NewSQLCredentialStore(db, role, jsonldInstance.DocumentLoader())
					require.NoError(t, err)

					err = store.StoreCredential(expected)
					require.NoError(t, err)

					query := vc.VerifiableCredential{
						Context: append([]ssi.URI(nil), expected.Context...),
						Type:    append([]ssi.URI(nil), expected.Type...),
					}
					queryFn(&query)

					actual, err := store.SearchCredentials(query, filterOnType)

					require.NoError(t, err)
					if asserterFn == nil {
						assert.Empty(t, actual, "no results expected")
					} else {
						if !assert.NotEmpty(t, actual, "no results found") {
							// No results
							return
						}
						// All results should match the asserter
						for _, curr := range actual {
							asserterFn(curr)
						}
						// At least the expected credential should be there
						resultsJSON, _ := json.Marshal(actual)
						credJSON, _ := expected.MarshalJSON()
						assert.Contains(t, string(resultsJSON), string(credJSON))
					}
				}
				t.Run("search on ID", func(t *testing.T) {
					expected := createVC()
					search(t, expected, func(query *vc.VerifiableCredential) {
						query.ID = expected.ID
					}, func(actual vc.VerifiableCredential) {
						assert.Equal(t, expected.ID.String(), actual.ID.String())
					}, false)
				})
				t.Run("search on issuer", func(t *testing.T) {
					expected := createVC()
					search(t, expected, func(query *vc.VerifiableCredential) {
						query.Issuer = expected.Issuer
					}, func(actual vc.VerifiableCredential) {
						assert.Equal(t, expected.Issuer.String(), actual.Issuer.String())
					}, false)
				})
				t.Run("search on type", func(t *testing.T) {
					expected := createVC()
					expectedType := ssi.MustParseURI("NutsOrganizationCredential")
					search(t, expected, func(query *vc.VerifiableCredential) {
						query.Type = []ssi.URI{expectedType}
					}, func(actual vc.VerifiableCredential) {
						assert.Contains(t, actual.Type, expectedType)
					}, true)
				})
				t.Run("search on multiple types", func(t *testing.T) {
					expected := createVC()
					expectedType1 := ssi.MustParseURI("VerifiableCredential")
					expectedType2 := ssi.MustParseURI("NutsOrganizationCredential")
					search(t, expected, func(query *vc.VerifiableCredential) {
						query.Type = []ssi.URI{expectedType1, expectedType2}
					}, func(actual vc.VerifiableCredential) {
						assert.Contains(t, actual.Type, expectedType1, expectedType2)
					}, true)
				})
				t.Run("search on multiple types (different order)", func(t *testing.T) {
					expected := createVC()
					expectedType1 := ssi.MustParseURI("NutsOrganizationCredential")
					expectedType2 := ssi.MustParseURI("VerifiableCredential")
					search(t, expected, func(query *vc.VerifiableCredential) {
						query.Type = []ssi.URI{expectedType1, expectedType2}
					}, func(actual vc.VerifiableCredential) {
						assert.Contains(t, actual.Type, expectedType1, expectedType2)
					}, true)
				})
				t.Run("search on issuer, type", func(t *testing.T) {
					expected := createVC()
					expectedType := ssi.MustParseURI("NutsOrganizationCredential")
					search(t, expected, func(query *vc.VerifiableCredential) {
						query.Issuer = expected.Issuer
						query.Type = []ssi.URI{expectedType}
					}, func(actual vc.VerifiableCredential) {
						assert.Equal(t, expected.Issuer.String(), actual.Issuer.String())
						assert.Contains(t, actual.Type, expectedType)
					}, true)
				})
				t.Run("with credentialSubject.ID", func(t *testing.T) {
					expected := createVC()
					expectedSubject := ssi.MustParseURI("did:nuts:" + uuid.NewString())
					expected.CredentialSubject = []interface{}{
						credential.BaseCredentialSubject{
							ID: expectedSubject.String(),
						},
					}

					search(t, expected, func(query *vc.VerifiableCredential) {
						query.CredentialSubject = expected.CredentialSubject
					}, func(actual vc.VerifiableCredential) {
						assert.Equal(t, expectedSubject.String(), actual.CredentialSubject[0].(map[string]interface{})["id"])
					}, false)
				})
				t.Run("with credentialSubject.organization.name,city", func(t *testing.T) {
					expected := createVC()
					expected.CredentialSubject = []interface{}{
						map[string]interface{}{
							"organization": map[string]string{
								"name": "Nuts",
								"city": "Amsterdam",
							},
						},
					}

					search(t, expected, func(query *vc.VerifiableCredential) {
						query.CredentialSubject = expected.CredentialSubject
					}, func(actual vc.VerifiableCredential) {
						// Do not take into account VCs with more than one credential subject,
						// with not all of them matching the query (too complicated check).
						assert.Equal(t, 1, len(actual.CredentialSubject))
					}, false)
				})
				t.Run("fulltext", func(t *testing.T) {
					t.Run("with credentialSubject.organization.name, partial match", func(t *testing.T) {
						expected := createVC()

						search(t, expected, func(query *vc.VerifiableCredential) {
							query.CredentialSubject = []interface{}{
								map[string]interface{}{
									"organization": map[string]string{
										"name": "Ziekenhuis*",
									},
								},
							}
						}, func(actual vc.VerifiableCredential) {
							// Do not take into account VCs with more than one credential subject,
							// with not all of them matching the query (too complicated check).
							assert.Equal(t, 1, len(actual.CredentialSubject))
						}, false)
					})
					t.Run("with credentialSubject.organization.name,city, partial match", func(t *testing.T) {
						expected := createVC()

						search(t, expected, func(query *vc.VerifiableCredential) {
							query.CredentialSubject = []interface{}{
								map[string]interface{}{
									"organization": map[string]string{
										"name": "Ziekenhuis*",
										"city": "Alm*",
									},
								},
							}
						}, func(actual vc.VerifiableCredential) {
							// Do not take into account VCs with more than one credential subject,
							// with not all of them matching the query (too complicated check).
							assert.Equal(t, 1, len(actual.CredentialSubject))
						}, false)
					})
					t.Run("with credentialSubject.organization.name, partial match (not matching)", func(t *testing.T) {
						expected := createVC()

						search(t, expected, func(query *vc.VerifiableCredential) {
							query.CredentialSubject = []interface{}{
								map[string]interface{}{
									"organization": map[string]string{
										"name": "Hospit*",
									},
								},
							}
						}, nil, false)
					})
					t.Run("with credentialSubject.organization.name, not null match", func(t *testing.T) {
						expected := createVC()

						search(t, expected, func(query *vc.VerifiableCredential) {
							query.CredentialSubject = []interface{}{
								map[string]interface{}{
									"organization": map[string]string{
										"name": "*",
									},
								},
							}
						}, func(actual vc.VerifiableCredential) {
							// Do not take into account VCs with more than one credential subject,
							// with not all of them matching the query (too complicated check).
							assert.Equal(t, 1, len(actual.CredentialSubject))
						}, false)
					})
				})
				t.Run("no results", func(t *testing.T) {
					resetDatabaseAfterTest(t)
					store, err := NewSQLCredentialStore(db, role, jsonldInstance.DocumentLoader())
					require.NoError(t, err)
					cred := createVC()
					err = store.StoreCredential(cred)
					require.NoError(t, err)
					cred.ID, _ = ssi.ParseURI("non-existent")

					actual, err := store.SearchCredentials(cred, false)

					require.NoError(t, err)
					assert.Empty(t, actual)
				})
			})
		})
		t.Run("store existing credential", func(t *testing.T) {
			resetDatabaseAfterTest(t)
			store, err := NewSQLCredentialStore(db, role, jsonldInstance.DocumentLoader())
			require.NoError(t, err)

			cred := createVC()

			err = store.StoreCredential(cred)
			require.NoError(t, err)
			err = store.StoreCredential(cred)
			require.NoError(t, err)
		})
		t.Run("count", func(t *testing.T) {
			store, err := NewSQLCredentialStore(db, role, jsonldInstance.DocumentLoader())
			require.NoError(t, err)

			// Empty
			count, err := store.Count()
			require.NoError(t, err)
			assert.Equal(t, 0, count)

			// 1 result
			cred := createVC()
			err = store.StoreCredential(cred)
			require.NoError(t, err)
			count, err = store.Count()
			require.NoError(t, err)
			assert.Equal(t, 1, count)

			// 2 results
			cred2 := createVC()
			err = store.StoreCredential(cred2)
			require.NoError(t, err)
			count, err = store.Count()
			require.NoError(t, err)
			assert.Equal(t, 2, count)
		})
		t.Run("credential data already exists", func(t *testing.T) {
			resetDatabaseAfterTest(t)
			var otherRole Role
			if role == RoleIssuer {
				otherRole = RoleHolderVerifier
			} else {
				otherRole = RoleIssuer
			}
			store, err := NewSQLCredentialStore(db, role, jsonldInstance.DocumentLoader())
			require.NoError(t, err)

			otherStore, err := NewSQLCredentialStore(db, otherRole, jsonldInstance.DocumentLoader())
			require.NoError(t, err)

			// credential is already stored by other store (e.g. issued VC, thus in issuer store, then added to holder or verifier store)
			// The credential is stored just once, but registered twice (as issuer and holder/verifier).
			cred := createVC()

			err = otherStore.StoreCredential(cred)
			require.NoError(t, err)
			err = store.StoreCredential(cred)
			require.NoError(t, err)
		})
	}
}

func assertCredentialEqual(t *testing.T, expected vc.VerifiableCredential, actual vc.VerifiableCredential) {
	expectedJSON, _ := json.Marshal(expected)
	actualJSON, _ := json.Marshal(actual)
	assert.JSONEq(t, string(expectedJSON), string(actualJSON))
}

func createVC() vc.VerifiableCredential {
	id, _ := ssi.ParseURI(localDID.String() + "#" + uuid.NewString())
	expirationDate := time.Now().Add(time.Hour * 24 * 365)
	issuedCredential := vc.VerifiableCredential{
		Context:        []ssi.URI{ssi.MustParseURI("https://www.w3.org/2018/credentials/v1"), ssi.MustParseURI("https://nuts.nl/credentials/v1")},
		Type:           []ssi.URI{vc.VerifiableCredentialTypeV1URI(), ssi.MustParseURI("NutsOrganizationCredential")},
		ID:             id,
		Issuer:         localDID.URI(),
		IssuanceDate:   time.Now(),
		ExpirationDate: &expirationDate,
		CredentialSubject: []interface{}{
			map[string]interface{}{
				"id": otherDID.String(),
				"organization": map[string]string{
					"name": "Ziekenhuis de Appel",
					"city": "Almere",
				},
			},
		},
	}
	return issuedCredential
}

func TestSQLCredentialStore_LoadData(t *testing.T) {
	// Test to load some data in an arbitrary database
	t.SkipNow()
	dbURI := "postgres://postgres:postgres@localhost:5432?sslmode=disable"
	db, err := sql.Open("postgres", dbURI)
	require.NoError(t, err)
	defer db.Close()

	jsonldInstance := jsonld.NewJSONLDInstance()
	err = jsonldInstance.(core.Configurable).Configure(*core.NewServerConfig())
	require.NoError(t, err)
	store, err := NewSQLCredentialStore(db, RoleIssuer, jsonldInstance.DocumentLoader())
	require.NoError(t, err)

	err = store.StoreCredential(createVC())
	require.NoError(t, err)
}
