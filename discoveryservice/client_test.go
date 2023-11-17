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

package discoveryservice

//
//import (
//	"context"
//	"crypto/ecdsa"
//	"crypto/elliptic"
//	"crypto/rand"
//	"fmt"
//	"github.com/google/uuid"
//	"github.com/lestrrat-go/jwx/v2/jwa"
//	"github.com/lestrrat-go/jwx/v2/jwk"
//	"github.com/lestrrat-go/jwx/v2/jws"
//	"github.com/lestrrat-go/jwx/v2/jwt"
//	ssi "github.com/nuts-foundation/go-did"
//	"github.com/nuts-foundation/go-did/did"
//	"github.com/nuts-foundation/go-did/vc"
//	"github.com/nuts-foundation/nuts-node/storage"
//	"github.com/stretchr/testify/require"
//	"gorm.io/gorm/schema"
//	"testing"
//	"time"
//)
//
//func Test_client_applyDelta(t *testing.T) {
//	//storageEngine := storage.New()
//	//storageEngine.(core.Injectable).Config().(*storage.Config).SQL = storage.SQLConfig{ConnectionString: "file:../../data/sqlite.db"}
//	//require.NoError(t, storageEngine.Configure(core.TestServerConfig(core.ServerConfig{Datadir: "data"})))
//	//require.NoError(t, storageEngine.Start())
//
//	storageEngine := storage.NewTestStorageEngine(t)
//	require.NoError(t, storageEngine.Start())
//	t.Cleanup(func() {
//		_ = storageEngine.Shutdown()
//	})
//
//	t.Run("fresh list, assert all persisted fields", func(t *testing.T) {
//		c := setupClient(t, storageEngine)
//		err := c.applyDelta(TestDefinition.ID, []vc.VerifiablePresentation{vpAlice, vpBob}, []string{"other", "and another"}, 0, 1000)
//		require.NoError(t, err)
//
//		var actualList list
//		require.NoError(t, c.db.Find(&actualList, "usecase_id = ?", TestDefinition.ID).Error)
//		require.Equal(t, TestDefinition.ID, actualList.UsecaseID)
//		require.Equal(t, uint64(1000), actualList.Timestamp)
//
//		var entries []entry
//		require.NoError(t, c.db.Find(&entries, "usecase_id = ?", TestDefinition.ID).Error)
//		require.Len(t, entries, 2)
//		require.Equal(t, vpAlice.ID.String(), entries[0].PresentationID)
//		require.Equal(t, vpBob.ID.String(), entries[1].PresentationID)
//	})
//}
//
//func Test_client_writePresentation(t *testing.T) {
//	storageEngine := storage.NewTestStorageEngine(t)
//	require.NoError(t, storageEngine.Start())
//	t.Cleanup(func() {
//		_ = storageEngine.Shutdown()
//	})
//
//	t.Run("1 credential", func(t *testing.T) {
//		c := setupClient(t, storageEngine)
//		err := c.writePresentation(c.db, TestDefinition.ID, vpAlice)
//		require.NoError(t, err)
//
//		var entries []entry
//		require.NoError(t, c.db.Find(&entries, "usecase_id = ?", TestDefinition.ID).Error)
//		require.Len(t, entries, 1)
//		require.Equal(t, vpAlice.ID.String(), entries[0].PresentationID)
//		require.Equal(t, vpAlice.Raw(), entries[0].PresentationRaw)
//		require.Equal(t, vpAlice.JWT().Expiration().Unix(), entries[0].PresentationExpiration)
//
//		var credentials []credential
//		require.NoError(t, c.db.Find(&credentials, "entry_id = ?", entries[0].ID).Error)
//		require.Len(t, credentials, 1)
//		cred := credentials[0]
//		require.Equal(t, vcAlice.ID.String(), cred.CredentialID)
//		require.Equal(t, vcAlice.Issuer.String(), cred.CredentialIssuer)
//		require.Equal(t, aliceDID.String(), cred.CredentialSubjectID)
//		require.Equal(t, vcAlice.Type[1].String(), *cred.CredentialType)
//
//		expectedProperties := map[string]map[string]string{
//			cred.ID: {
//				"credentialSubject.person.givenName":  "Alice",
//				"credentialSubject.person.familyName": "Jones",
//				"credentialSubject.person.city":       "InfoSecLand",
//			},
//		}
//		for recordID, properties := range expectedProperties {
//			for key, value := range properties {
//				var prop credentialProperty
//				require.NoError(t, c.db.Find(&prop, "id = ? AND key = ?", recordID, key).Error)
//				require.Equal(t, value, prop.Value)
//			}
//		}
//	})
//}
//
//func Test_client_search(t *testing.T) {
//	storageEngine := storage.NewTestStorageEngine(t)
//	require.NoError(t, storageEngine.Start())
//	t.Cleanup(func() {
//		_ = storageEngine.Shutdown()
//	})
//
//	type testCase struct {
//		name        string
//		inputVPs    []vc.VerifiablePresentation
//		query       map[string]string
//		expectedVPs []string
//	}
//	testCases := []testCase{
//		{
//			name:     "issuer",
//			inputVPs: []vc.VerifiablePresentation{vpAlice},
//			query: map[string]string{
//				"issuer": authorityDID.String(),
//			},
//			expectedVPs: []string{vpAlice.ID.String()},
//		},
//		{
//			name:     "id",
//			inputVPs: []vc.VerifiablePresentation{vpAlice},
//			query: map[string]string{
//				"id": vcAlice.ID.String(),
//			},
//			expectedVPs: []string{vpAlice.ID.String()},
//		},
//		{
//			name:     "type",
//			inputVPs: []vc.VerifiablePresentation{vpAlice},
//			query: map[string]string{
//				"type": "TestCredential",
//			},
//			expectedVPs: []string{vpAlice.ID.String()},
//		},
//		{
//			name:     "credentialSubject.id",
//			inputVPs: []vc.VerifiablePresentation{vpAlice},
//			query: map[string]string{
//				"credentialSubject.id": aliceDID.String(),
//			},
//			expectedVPs: []string{vpAlice.ID.String()},
//		},
//		{
//			name:     "1 property",
//			inputVPs: []vc.VerifiablePresentation{vpAlice},
//			query: map[string]string{
//				"credentialSubject.person.givenName": "Alice",
//			},
//			expectedVPs: []string{vpAlice.ID.String()},
//		},
//		{
//			name:     "2 properties",
//			inputVPs: []vc.VerifiablePresentation{vpAlice},
//			query: map[string]string{
//				"credentialSubject.person.givenName":  "Alice",
//				"credentialSubject.person.familyName": "Jones",
//			},
//			expectedVPs: []string{vpAlice.ID.String()},
//		},
//		{
//			name:     "properties and base properties",
//			inputVPs: []vc.VerifiablePresentation{vpAlice},
//			query: map[string]string{
//				"issuer":                             authorityDID.String(),
//				"credentialSubject.person.givenName": "Alice",
//			},
//			expectedVPs: []string{vpAlice.ID.String()},
//		},
//		{
//			name:     "wildcard postfix",
//			inputVPs: []vc.VerifiablePresentation{vpAlice, vpBob},
//			query: map[string]string{
//				"credentialSubject.person.familyName": "Jo*",
//			},
//			expectedVPs: []string{vpAlice.ID.String(), vpBob.ID.String()},
//		},
//		{
//			name:     "wildcard prefix",
//			inputVPs: []vc.VerifiablePresentation{vpAlice, vpBob},
//			query: map[string]string{
//				"credentialSubject.person.givenName": "*ce",
//			},
//			expectedVPs: []string{vpAlice.ID.String()},
//		},
//		{
//			name:     "wildcard midway (no interpreted as wildcard)",
//			inputVPs: []vc.VerifiablePresentation{vpAlice, vpBob},
//			query: map[string]string{
//				"credentialSubject.person.givenName": "A*ce",
//			},
//			expectedVPs: []string{},
//		},
//		{
//			name:     "just wildcard",
//			inputVPs: []vc.VerifiablePresentation{vpAlice, vpBob},
//			query: map[string]string{
//				"id": "*",
//			},
//			expectedVPs: []string{vpAlice.ID.String(), vpBob.ID.String()},
//		},
//		{
//			name:     "2 VPs, 1 match",
//			inputVPs: []vc.VerifiablePresentation{vpAlice, vpBob},
//			query: map[string]string{
//				"credentialSubject.person.givenName": "Alice",
//			},
//			expectedVPs: []string{vpAlice.ID.String()},
//		},
//		{
//			name:     "multiple matches",
//			inputVPs: []vc.VerifiablePresentation{vpAlice, vpBob},
//			query: map[string]string{
//				"issuer": authorityDID.String(),
//			},
//			expectedVPs: []string{vpAlice.ID.String(), vpBob.ID.String()},
//		},
//		{
//			name:     "no match",
//			inputVPs: []vc.VerifiablePresentation{vpAlice},
//			query: map[string]string{
//				"credentialSubject.person.givenName": "Bob",
//			},
//			expectedVPs: []string{},
//		},
//		{
//			name: "empty database",
//			query: map[string]string{
//				"credentialSubject.person.givenName": "Bob",
//			},
//			expectedVPs: []string{},
//		},
//	}
//
//	for _, tc := range testCases {
//		t.Run(tc.name, func(t *testing.T) {
//			c := setupClient(t, storageEngine)
//			for _, vp := range tc.inputVPs {
//				err := c.writePresentation(c.db, TestDefinition.ID, vp)
//				require.NoError(t, err)
//			}
//			actualVPs, err := c.Search(TestDefinition.ID, tc.query)
//			require.NoError(t, err)
//			require.Len(t, actualVPs, len(tc.expectedVPs))
//			for _, expectedVP := range tc.expectedVPs {
//				found := false
//				for _, actualVP := range actualVPs {
//					if actualVP.ID.String() == expectedVP {
//						found = true
//						break
//					}
//				}
//				require.True(t, found, "expected to find VP with ID %s", expectedVP)
//			}
//		})
//	}
//}
//
//func setupClient(t *testing.T, storageEngine storage.Engine) *client {
//	t.Cleanup(func() {
//		underlyingDB, err := storageEngine.GetSQLDatabase().DB()
//		require.NoError(t, err)
//		tables := []schema.Tabler{
//			&entry{},
//			&credential{},
//			&list{},
//		}
//		for _, table := range tables {
//			_, err = underlyingDB.Exec("DELETE FROM " + table.TableName())
//			require.NoError(t, err)
//		}
//	})
//	testDefinitions := map[string]Definition{
//		TestDefinition.ID: TestDefinition,
//	}
//
//	c, err := newClient(storageEngine.GetSQLDatabase(), testDefinitions)
//	require.NoError(t, err)
//	return c
//}
//
//var keyPairs map[string]*ecdsa.PrivateKey
//var authorityDID did.DID
//var aliceDID did.DID
//var vcAlice vc.VerifiableCredential
//var vpAlice vc.VerifiablePresentation
//var bobDID did.DID
//var vcBob vc.VerifiableCredential
//
//var vpBob vc.VerifiablePresentation
//
//func init() {
//	keyPairs = make(map[string]*ecdsa.PrivateKey)
//	authorityDID = did.MustParseDID("did:example:authority")
//	keyPairs[authorityDID.String()], _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
//	aliceDID = did.MustParseDID("did:example:alice")
//	keyPairs[aliceDID.String()], _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
//	bobDID = did.MustParseDID("did:example:bob")
//	keyPairs[bobDID.String()], _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
//
//	vcAlice = createCredentialWithClaims(authorityDID, aliceDID, func() []interface{} {
//		return []interface{}{
//			map[string]interface{}{
//				"id": aliceDID.String(),
//				"person": map[string]interface{}{
//					"givenName":  "Alice",
//					"familyName": "Jones",
//					"city":       "InfoSecLand",
//				},
//			},
//		}
//	}, func(m map[string]interface{}) {
//		// do nothing
//	})
//	vpAlice = createPresentation(aliceDID, vcAlice)
//	vcBob = createCredentialWithClaims(authorityDID, bobDID, func() []interface{} {
//		return []interface{}{
//			map[string]interface{}{
//				"id": aliceDID.String(),
//				"person": map[string]interface{}{
//					"givenName":  "Bob",
//					"familyName": "Johansson",
//					"city":       "InfoSecLand",
//				},
//			},
//		}
//	}, func(m map[string]interface{}) {
//		// do nothing
//	})
//	vpBob = createPresentation(bobDID, vcBob)
//}
//
//func createCredential(issuerDID did.DID, subjectDID did.DID) vc.VerifiableCredential {
//	return createCredentialWithClaims(issuerDID, subjectDID,
//		func() []interface{} {
//			return []interface{}{
//				map[string]interface{}{
//					"id": subjectDID.String(),
//				},
//			}
//		},
//		func(claims map[string]interface{}) {
//			// do nothing
//		})
//}
//
//func createCredentialWithClaims(issuerDID did.DID, subjectDID did.DID, credentialSubjectCreator func() []interface{}, claimVisitor func(map[string]interface{})) vc.VerifiableCredential {
//	vcID := did.DIDURL{DID: issuerDID}
//	vcID.Fragment = uuid.NewString()
//	vcIDURI := vcID.URI()
//	expirationDate := time.Now().Add(time.Hour * 24)
//
//	result, err := vc.CreateJWTVerifiableCredential(context.Background(), vc.VerifiableCredential{
//		ID:                &vcIDURI,
//		Issuer:            issuerDID.URI(),
//		Type:              []ssi.URI{ssi.MustParseURI("VerifiableCredential"), ssi.MustParseURI("TestCredential")},
//		IssuanceDate:      time.Now(),
//		ExpirationDate:    &expirationDate,
//		CredentialSubject: credentialSubjectCreator(),
//	}, func(ctx context.Context, claims map[string]interface{}, headers map[string]interface{}) (string, error) {
//		claimVisitor(claims)
//		return signJWT(subjectDID, claims, headers)
//	})
//	if err != nil {
//		panic(err)
//	}
//	return *result
//}
//
//func createPresentation(subjectDID did.DID, credentials ...vc.VerifiableCredential) vc.VerifiablePresentation {
//	return createPresentationCustom(subjectDID, func(claims map[string]interface{}) {
//		// do nothing
//	}, credentials...)
//}
//
//func createPresentationCustom(subjectDID did.DID, claimVisitor func(map[string]interface{}), credentials ...vc.VerifiableCredential) vc.VerifiablePresentation {
//	headers := map[string]interface{}{
//		jws.TypeKey: "JWT",
//	}
//	claims := map[string]interface{}{
//		jwt.IssuerKey:  subjectDID.String(),
//		jwt.SubjectKey: subjectDID.String(),
//		jwt.JwtIDKey:   subjectDID.String() + "#" + uuid.NewString(),
//		"vp": vc.VerifiablePresentation{
//			Type:                 append([]ssi.URI{ssi.MustParseURI("VerifiablePresentation")}),
//			VerifiableCredential: credentials,
//		},
//		jwt.NotBeforeKey:  time.Now().Unix(),
//		jwt.ExpirationKey: time.Now().Add(time.Hour * 8),
//	}
//	claimVisitor(claims)
//	token, err := signJWT(subjectDID, claims, headers)
//	if err != nil {
//		panic(err)
//	}
//	presentation, err := vc.ParseVerifiablePresentation(token)
//	if err != nil {
//		panic(err)
//	}
//	return *presentation
//}
//
//func signJWT(subjectDID did.DID, claims map[string]interface{}, headers map[string]interface{}) (string, error) {
//	// Build JWK
//	signingKey := keyPairs[subjectDID.String()]
//	if signingKey == nil {
//		return "", fmt.Errorf("key not found for DID: %s", subjectDID)
//	}
//	subjectKeyJWK, err := jwk.FromRaw(signingKey)
//	if err != nil {
//		return "", nil
//	}
//	keyID := did.DIDURL{DID: subjectDID}
//	keyID.Fragment = "0"
//	if err := subjectKeyJWK.Set(jwk.AlgorithmKey, jwa.ES256); err != nil {
//		return "", err
//	}
//	if err := subjectKeyJWK.Set(jwk.KeyIDKey, keyID.String()); err != nil {
//		return "", err
//	}
//
//	// Build token
//	token := jwt.New()
//	for k, v := range claims {
//		if err := token.Set(k, v); err != nil {
//			return "", err
//		}
//	}
//	hdr := jws.NewHeaders()
//	for k, v := range headers {
//		if err := hdr.Set(k, v); err != nil {
//			return "", err
//		}
//	}
//	bytes, err := jwt.Sign(token, jwt.WithKey(jwa.ES256, signingKey, jws.WithProtectedHeaders(hdr)))
//	return string(bytes), err
//}
