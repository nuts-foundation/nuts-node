/*
 * Copyright (C) 2024 Nuts community
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

package didnuts

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwk"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/audit"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/storage/orm"
	"github.com/nuts-foundation/nuts-node/vdr/didnuts/didstore"
	"github.com/nuts-foundation/nuts-node/vdr/didsubject"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"gorm.io/gorm"
)

type testContext struct {
	ctrl          *gomock.Controller
	manager       *Manager
	networkClient *network.MockTransactions
	didStore      *didstore.MockStore
	didResolver   *resolver.MockDIDResolver
	db            *gorm.DB
	ctx           context.Context
	keyStore      *mockKeyStore
}

func newTestContext(t *testing.T) *testContext {
	ctrl := gomock.NewController(t)
	networkClient := network.NewMockTransactions(ctrl)
	didStore := didstore.NewMockStore(ctrl)
	didResolver := resolver.NewMockDIDResolver(ctrl)
	ctx := audit.TestContext()
	db := testDB(t)
	keyStore := &mockKeyStore{}
	manager := NewManager(keyStore, networkClient, didStore, didResolver, db)

	return &testContext{
		ctrl:          ctrl,
		manager:       manager,
		networkClient: networkClient,
		didStore:      didStore,
		didResolver:   didResolver,
		db:            db,
		ctx:           ctx,
		keyStore:      keyStore,
	}
}

func testDB(t *testing.T) *gorm.DB {
	//logrus.SetLevel(logrus.TraceLevel)
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())
	db := storageEngine.GetSQLDatabase()
	return db
}

func TestManager_Create(t *testing.T) {
	ctx := newTestContext(t)
	ctx.didStore.EXPECT().Add(gomock.Any(), gomock.Any()).Return(nil)
	ctx.networkClient.EXPECT().CreateTransaction(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, template network.Template) (dag.Transaction, error) {
		assert.Equal(t, DIDDocumentType, template.Type)
		assert.True(t, template.AttachKey)
		assert.Empty(t, template.AdditionalPrevs)
		assert.Empty(t, template.Participants)
		var didDocument did.Document
		_ = json.Unmarshal(template.Payload, &didDocument)
		assert.Len(t, didDocument.VerificationMethod, 1)
		assert.Len(t, didDocument.CapabilityInvocation, 1)
		assert.Len(t, didDocument.CapabilityDelegation, 1)
		assert.Len(t, didDocument.AssertionMethod, 1)
		assert.Len(t, didDocument.Authentication, 1)
		assert.Len(t, didDocument.KeyAgreement, 1)
		assert.Nil(t, didDocument.Service)
		return testTransaction{}, nil
	})

	_, _, err := ctx.manager.Create(nil, didsubject.DefaultCreationOptions())

	assert.NoError(t, err)
}

func TestManager_RemoveVerificationMethod(t *testing.T) {
	id123, _ := did.ParseDID("did:nuts:123")
	id123Method, _ := did.ParseDIDURL("did:nuts:123#method-1")
	publicKey := nutsCrypto.NewTestKey("did:nuts:123").Public()
	vm, _ := did.NewVerificationMethod(*id123Method, ssi.JsonWebKey2020, did.DID{}, publicKey)
	doc := &did.Document{ID: *id123}
	doc.AddCapabilityInvocation(vm)
	doc.AddCapabilityDelegation(vm)
	doc.AddAssertionMethod(vm)
	doc.AddAuthenticationMethod(vm)
	doc.AddKeyAgreement(vm)
	assert.Equal(t, vm, doc.CapabilityInvocation[0].VerificationMethod)
	assert.Equal(t, vm, doc.VerificationMethod[0])

	t.Run("ok", func(t *testing.T) {
		ctx := newTestContext(t)
		doc1 := *doc
		doc2 := *doc
		ctx.didResolver.EXPECT().Resolve(*id123, &resolver.ResolveMetadata{AllowDeactivated: true}).Return(&doc1, &resolver.DocumentMetadata{}, nil)
		ctx.didResolver.EXPECT().Resolve(*id123, nil).Return(&doc2, &resolver.DocumentMetadata{}, nil)
		ctx.didStore.EXPECT().Resolve(*id123, &resolver.ResolveMetadata{AllowDeactivated: true}).Return(&doc2, &resolver.DocumentMetadata{}, nil)
		ctx.didStore.EXPECT().Add(gomock.Any(), gomock.Any()).Return(nil)
		ctx.networkClient.EXPECT().CreateTransaction(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, template network.Template) (dag.Transaction, error) {
			var didDocument did.Document
			_ = json.Unmarshal(template.Payload, &didDocument)
			assert.Empty(t, didDocument.VerificationMethod)
			return testTransaction{}, nil
		})

		err := ctx.manager.RemoveVerificationMethod(ctx.ctx, *id123, *id123Method)
		require.NoError(t, err)
	})

	t.Run("ok - verificationMethod is not part of the document", func(t *testing.T) {
		ctx := newTestContext(t)
		ctx.didResolver.EXPECT().Resolve(*id123, &resolver.ResolveMetadata{AllowDeactivated: true}).Return(&did.Document{ID: *id123}, &resolver.DocumentMetadata{}, nil)

		err := ctx.manager.RemoveVerificationMethod(ctx.ctx, *id123, *id123Method)

		assert.NoError(t, err)
	})

	t.Run("error - document is deactivated", func(t *testing.T) {
		ctx := newTestContext(t)
		doc1 := *doc
		doc2 := *doc
		ctx.didResolver.EXPECT().Resolve(*id123, &resolver.ResolveMetadata{AllowDeactivated: true}).Return(&doc1, &resolver.DocumentMetadata{Deactivated: true}, nil)
		ctx.didStore.EXPECT().Resolve(*id123, &resolver.ResolveMetadata{AllowDeactivated: true}).Return(&doc2, &resolver.DocumentMetadata{Deactivated: true}, nil)

		err := ctx.manager.RemoveVerificationMethod(ctx.ctx, *id123, *id123Method)
		assert.True(t, errors.Is(err, resolver.ErrDeactivated))
		assert.True(t, errors.Is(err, resolver.ErrDeactivated))
	})
}

func TestManager_CreateNewAuthenticationMethodForDID(t *testing.T) {
	id123, _ := did.ParseDID("did:nuts:123")

	kc := &mockKeyStore{}

	t.Run("ok", func(t *testing.T) {
		// Prepare a document with an authenticationMethod:
		document := &did.Document{ID: *id123}
		method, err := CreateNewVerificationMethodForDID(audit.TestContext(), document.ID, kc)
		require.NoError(t, err)
		document.AddCapabilityInvocation(method)

		assert.NotNil(t, method)
		assert.Len(t, document.CapabilityInvocation, 1)
		assert.Equal(t, method.ID.String(), document.CapabilityInvocation[0].ID.String())
		assert.Equal(t, kc.key.KID(), document.CapabilityInvocation[0].ID.String())
	})
}

func TestManipulator_AddKey(t *testing.T) {
	id, _ := did.ParseDID("did:nuts:123")
	keyID, _ := did.ParseDIDURL("did:nuts:123#key-1")

	t.Run("ok - add a new key", func(t *testing.T) {
		ctx := newTestContext(t)

		currentDIDDocument := did.Document{ID: *id, Controller: []did.DID{*id}}
		ctx.didResolver.EXPECT().Resolve(*id, &resolver.ResolveMetadata{AllowDeactivated: true}).Return(&currentDIDDocument, &resolver.DocumentMetadata{}, nil)
		ctx.didStore.EXPECT().Resolve(*id, &resolver.ResolveMetadata{AllowDeactivated: true}).Return(&currentDIDDocument, &resolver.DocumentMetadata{}, nil)
		ctx.didStore.EXPECT().Add(gomock.Any(), gomock.Any()).Return(nil)
		ctx.didResolver.EXPECT().Resolve(*id, nil).Return(&currentDIDDocument, &resolver.DocumentMetadata{}, nil)
		ctx.networkClient.EXPECT().CreateTransaction(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, template network.Template) (dag.Transaction, error) {
			var didDocument did.Document
			_ = json.Unmarshal(template.Payload, &didDocument)
			assert.Len(t, didDocument.VerificationMethod, 1)
			assert.Len(t, didDocument.CapabilityInvocation, 1)
			return testTransaction{}, nil
		})

		key, err := ctx.manager.AddVerificationMethod(ctx.ctx, *id, orm.CapabilityInvocationUsage)
		require.NoError(t, err)
		assert.NotNil(t, key)
		assert.Equal(t, key.Controller, *id,
			"expected method to have DID as controller")
	})

	t.Run("error - didStore throws an error", func(t *testing.T) {
		ctx := newTestContext(t)

		currentDIDDocument := did.Document{ID: *id, Controller: []did.DID{*id}}
		currentDIDDocument.AddCapabilityInvocation(&did.VerificationMethod{ID: *keyID})
		ctx.didResolver.EXPECT().Resolve(*id, &resolver.ResolveMetadata{AllowDeactivated: true}).Return(&currentDIDDocument, &resolver.DocumentMetadata{}, nil)
		ctx.didStore.EXPECT().Resolve(*id, &resolver.ResolveMetadata{AllowDeactivated: true}).Return(nil, nil, resolver.ErrNotFound)

		key, err := ctx.manager.AddVerificationMethod(ctx.ctx, *id, 0)
		assert.ErrorIs(t, err, resolver.ErrNotFound)
		assert.Nil(t, key)
	})

	t.Run("error - did is deactivated", func(t *testing.T) {
		ctx := newTestContext(t)

		currentDIDDocument := did.Document{ID: *id, Controller: []did.DID{*id}}
		ctx.didResolver.EXPECT().Resolve(*id, &resolver.ResolveMetadata{AllowDeactivated: true}).Return(&currentDIDDocument, &resolver.DocumentMetadata{Deactivated: true}, nil)

		key, err := ctx.manager.AddVerificationMethod(nil, *id, 0)

		assert.ErrorIs(t, err, resolver.ErrDeactivated)
		assert.Nil(t, key)
	})
}

func TestManager_GenerateDocument(t *testing.T) {
	keyStore := nutsCrypto.NewMemoryCryptoInstance()
	ctx := audit.TestContext()
	db := testDB(t)
	manager := NewManager(keyStore, nil, nil, nil, db)

	t.Run("ok", func(t *testing.T) {
		doc, err := manager.NewDocument(ctx, orm.AssertionKeyUsage())

		require.NoError(t, err)
		assert.NotNil(t, doc)
		assert.True(t, strings.HasPrefix(doc.DID.ID, "did:nuts:"))
		assert.Len(t, doc.VerificationMethods, 1)

		// check if ID of the verification method and DID match the key fingerprint
		// the DID is named via base58(sha256(pub key))
		// the kid is the DID appended with the SHA256 of the pub key
		var verificationMethod did.VerificationMethod
		_ = json.Unmarshal(doc.VerificationMethods[0].Data, &verificationMethod)
		asJWK, err := verificationMethod.JWK()
		require.NoError(t, err)
		nutsThumbprint, err := nutsCrypto.Thumbprint(asJWK)
		require.NoError(t, err)
		_ = jwk.AssignKeyID(asJWK, jwk.WithThumbprintHash(crypto.SHA256))
		assert.Equal(t, fmt.Sprintf("did:nuts:%s", nutsThumbprint), doc.DID.ID)
		assert.Equal(t, fmt.Sprintf("did:nuts:%s#%s", nutsThumbprint, asJWK.KeyID()), verificationMethod.ID.String())

		t.Run("additional verification method", func(t *testing.T) {
			asDID := did.MustParseDID(doc.DID.ID)

			verificationMethod, err := manager.NewVerificationMethod(ctx, asDID, orm.AssertionKeyUsage())

			require.NoError(t, err)

			asJWK, err := verificationMethod.JWK()
			require.NoError(t, err)
			_ = jwk.AssignKeyID(asJWK, jwk.WithThumbprintHash(crypto.SHA256))
			assert.Equal(t, fmt.Sprintf("%s#%s", doc.DID.ID, asJWK.KeyID()), verificationMethod.ID.String())
		})
	})
}

var jwkString = `{"crv":"P-256","kid":"did:nuts:3gU9z3j7j4VCboc3qq3Vc5mVVGDNGjfg32xokeX8c8Zn#J9O6wvqtYOVwjc8JtZ4aodRdbPv_IKAjLkEq9uHlDdE","kty":"EC","x":"Qn6xbZtOYFoLO2qMEAczcau9uGGWwa1bT+7JmAVLtg4=","y":"d20dD0qlT+d1djVpAfrfsAfKOUxKwKkn1zqFSIuJ398="},"type":"JsonWebKey2020"}`

func TestManager_Create2(t *testing.T) {
	defaultOptions := didsubject.DefaultCreationOptions()

	t.Run("ok", func(t *testing.T) {
		t.Run("defaults", func(t *testing.T) {
			ctx := newTestContext(t)
			var txTemplate network.Template
			ctx.didStore.EXPECT().Add(gomock.Any(), gomock.Any()).Return(nil)
			ctx.networkClient.EXPECT().CreateTransaction(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, tx network.Template) (dag.Transaction, error) {
				txTemplate = tx
				return testTransaction{}, nil
			})

			doc, key, err := ctx.manager.Create(nil, defaultOptions)
			assert.NoError(t, err, "create should not return an error")
			assert.NotNil(t, doc, "create should return a document")
			assert.NotNil(t, key, "create should return a Key")
			assert.Equal(t, did.MustParseDIDURL(ctx.keyStore.key.KID()).DID, doc.ID, "the DID Doc should have the expected id")
			assert.Len(t, doc.VerificationMethod, 1, "it should have one verificationMethod")
			assert.Equal(t, ctx.keyStore.key.KID(), doc.VerificationMethod[0].ID.String(),
				"verificationMethod should have the correct id")
			assert.Len(t, doc.CapabilityInvocation, 1, "it should have 1 CapabilityInvocation")
			assert.Equal(t, doc.CapabilityInvocation[0].VerificationMethod, doc.VerificationMethod[0], "the assertionMethod should be a pointer to the verificationMethod")
			assert.Len(t, doc.AssertionMethod, 1, "it should have 1 AssertionMethod")
			assert.Equal(t, DIDDocumentType, txTemplate.Type)
			payload, _ := json.Marshal(doc)
			assert.Equal(t, payload, txTemplate.Payload)
			assert.Equal(t, key, txTemplate.Key)
			assert.Empty(t, txTemplate.AdditionalPrevs)
			assert.Len(t, doc.AssertionMethod, 1)
			assert.Len(t, doc.Authentication, 1)
			assert.Len(t, doc.CapabilityDelegation, 1)
			assert.Len(t, doc.CapabilityInvocation, 1)
			assert.Len(t, doc.KeyAgreement, 1)
		})
	})

	t.Run("error - failed to create key", func(t *testing.T) {
		ctx := newTestContext(t)
		mock := nutsCrypto.NewMockKeyStore(ctx.ctrl)
		ctx.manager.keyStore = mock
		mock.EXPECT().New(gomock.Any(), gomock.Any()).Return(nil, errors.New("b00m!"))

		_, _, err := ctx.manager.Create(nil, didsubject.DefaultCreationOptions())

		assert.EqualError(t, err, "b00m!")
	})
}

func TestManager_Deactivate(t *testing.T) {
	id, _ := did.ParseDID("did:nuts:123")
	keyID, _ := did.ParseDIDURL("did:nuts:123#key-1")
	ctx := newTestContext(t)
	currentDIDDocument := did.Document{ID: *id, Controller: []did.DID{*id}}
	currentDIDDocument.AddCapabilityInvocation(&did.VerificationMethod{ID: *keyID})
	ctx.didStore.EXPECT().Resolve(*id, &resolver.ResolveMetadata{AllowDeactivated: true}).Return(&currentDIDDocument, &resolver.DocumentMetadata{}, nil)
	ctx.didStore.EXPECT().Add(gomock.Any(), gomock.Any()).Return(nil)
	ctx.didResolver.EXPECT().Resolve(*id, nil).Return(&currentDIDDocument, &resolver.DocumentMetadata{}, nil)
	expectedDocument := CreateDocument()
	expectedDocument.ID = *id
	ctx.networkClient.EXPECT().CreateTransaction(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, template network.Template) (dag.Transaction, error) {
		var didDocument did.Document
		_ = json.Unmarshal(template.Payload, &didDocument)
		assert.Len(t, didDocument.VerificationMethod, 0)
		assert.Len(t, didDocument.Controller, 0)
		return testTransaction{}, nil
	})

	err := ctx.manager.Deactivate(ctx.ctx, *id)

	require.NoError(t, err)
}

func Test_DIDKidNamingFunc(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		keyID, err := DIDKIDNamingFunc(privateKey.PublicKey)
		require.NoError(t, err)
		assert.NotEmpty(t, keyID)
		assert.Contains(t, keyID, "did:nuts")
	})

	t.Run("ok - predefined key", func(t *testing.T) {
		pub, err := jwkToPublicKey(t, jwkString)
		require.NoError(t, err)

		keyID, err := DIDKIDNamingFunc(pub)
		require.NoError(t, err)
		assert.Equal(t, keyID, "did:nuts:3gU9z3j7j4VCboc3qq3Vc5mVVGDNGjfg32xokeX8c8Zn#J9O6wvqtYOVwjc8JtZ4aodRdbPv_IKAjLkEq9uHlDdE", keyID)
	})

	t.Run("nok - wrong key type", func(t *testing.T) {
		keyID, err := DIDKIDNamingFunc(unknownPublicKey{})
		assert.EqualError(t, err, "could not generate kid: invalid key type 'didnuts.unknownPublicKey' for jwk.New")
		assert.Empty(t, keyID)
	})
}

func Test_didSubKIDNamingFunc(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		owningDID, _ := did.ParseDID("did:nuts:bladiebla")

		keyID, err := didSubKIDNamingFunc(*owningDID)(privateKey.PublicKey)
		require.NoError(t, err)
		parsedKeyID, err := did.ParseDIDURL(keyID)
		require.NoError(t, err)
		// Make sure the idString part of the key ID is taken from the owning DID document
		assert.Equal(t, parsedKeyID.ID, owningDID.ID)
		assert.NotEmpty(t, parsedKeyID.Fragment)
	})
}

type unknownPublicKey struct{}

func jwkToPublicKey(t *testing.T, jwkStr string) (crypto.PublicKey, error) {
	t.Helper()
	keySet, err := jwk.ParseString(jwkStr)
	require.NoError(t, err)
	key, _ := keySet.Key(0)
	var rawKey crypto.PublicKey
	if err = key.Raw(&rawKey); err != nil {
		return nil, err
	}
	return rawKey, nil
}

func TestManager_NewDocument(t *testing.T) {
	keyStore := nutsCrypto.NewMemoryCryptoInstance()
	ctx := audit.TestContext()
	db := testDB(t)
	manager := NewManager(keyStore, nil, nil, nil, db)

	t.Run("ok", func(t *testing.T) {
		doc, err := manager.NewDocument(ctx, orm.AssertionKeyUsage())

		require.NoError(t, err)
		assert.NotNil(t, doc)
		assert.True(t, strings.HasPrefix(doc.DID.ID, "did:nuts:"))
		assert.Len(t, doc.VerificationMethods, 1)

		// check if ID of the verification method and DID match the key fingerprint
		// the DID is named via base58(sha256(pub key))
		// the kid is the DID appended with the SHA256 of the pub key
		var verificationMethod did.VerificationMethod
		_ = json.Unmarshal(doc.VerificationMethods[0].Data, &verificationMethod)
		asJWK, err := verificationMethod.JWK()
		require.NoError(t, err)
		nutsThumbprint, err := nutsCrypto.Thumbprint(asJWK)
		require.NoError(t, err)
		_ = jwk.AssignKeyID(asJWK, jwk.WithThumbprintHash(crypto.SHA256))
		assert.Equal(t, fmt.Sprintf("did:nuts:%s", nutsThumbprint), doc.DID.ID)
		assert.Equal(t, fmt.Sprintf("did:nuts:%s#%s", nutsThumbprint, asJWK.KeyID()), verificationMethod.ID.String())

		t.Run("additional verification method", func(t *testing.T) {
			asDID := did.MustParseDID(doc.DID.ID)

			verificationMethod, err := manager.NewVerificationMethod(ctx, asDID, orm.AssertionKeyUsage())

			require.NoError(t, err)

			asJWK, err := verificationMethod.JWK()
			require.NoError(t, err)
			_ = jwk.AssignKeyID(asJWK, jwk.WithThumbprintHash(crypto.SHA256))
			assert.Equal(t, fmt.Sprintf("%s#%s", doc.DID.ID, asJWK.KeyID()), verificationMethod.ID.String())
		})
	})
}

func TestManager_Commit(t *testing.T) {
	document, _, _ := newDidDoc()
	data, _ := json.Marshal(document.VerificationMethod[0])
	eventLog := orm.DIDChangeLog{
		Type: orm.DIDChangeCreated,
		DIDDocumentVersion: orm.DIDDocument{
			ID: uuid.New().String(),
			DID: orm.DID{
				ID:      document.ID.String(),
				Subject: "subject",
			},
			VerificationMethods: []orm.VerificationMethod{
				{
					ID:       document.VerificationMethod[0].ID.String(),
					KeyTypes: orm.VerificationMethodKeyType(orm.AssertionKeyUsage()),
					Data:     data,
				},
			},
		},
	}

	t.Run("on created", func(t *testing.T) {
		ctx := newTestContext(t)
		ctx.networkClient.EXPECT().CreateTransaction(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, template network.Template) (dag.Transaction, error) {
			var didDocument did.Document
			_ = json.Unmarshal(template.Payload, &didDocument)
			assert.Equal(t, "application/did+json", template.Type)
			assert.True(t, template.AttachKey)
			assert.Equal(t, eventLog.DIDDocumentVersion.DID.ID, didDocument.ID.String())
			assert.Len(t, didDocument.VerificationMethod, 1)
			return testTransaction{}, nil
		})
		require.NoError(t, ctx.db.Save(&eventLog).Error)

		err := ctx.manager.Commit(ctx.ctx, eventLog)

		assert.NoError(t, err)
	})
	t.Run("on deactivated", func(t *testing.T) {
		t.Skip("todo re-enable after DocumentManager change")
		ctx := newTestContext(t)
		logCopy := eventLog
		logCopy.Type = orm.DIDChangeDeactivated
		didDocument, _ := eventLog.DIDDocumentVersion.ToDIDDocument()
		metadata := resolver.DocumentMetadata{
			SourceTransactions: []hash.SHA256Hash{hash.EmptyHash()},
		}
		ctx.didResolver.EXPECT().Resolve(eventLog.DID(), gomock.Any()).Return(&didDocument, &metadata, nil).AnyTimes()
		ctx.didStore.EXPECT().Resolve(eventLog.DID(), gomock.Any()).Return(&didDocument, &metadata, nil)
		ctx.didStore.EXPECT().Add(gomock.Any(), gomock.Any()).Return(nil)
		ctx.networkClient.EXPECT().CreateTransaction(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, template network.Template) (dag.Transaction, error) {
			assert.Len(t, template.AdditionalPrevs, 2) // previous and controller
			assert.False(t, template.AttachKey)
			return testTransaction{}, nil
		})
		require.NoError(t, ctx.db.Save(&logCopy).Error)

		err := ctx.manager.Commit(ctx.ctx, logCopy)

		assert.NoError(t, err)
	})
	t.Run("on update", func(t *testing.T) {
		ctx := newTestContext(t)
		logCopy := eventLog
		logCopy.Type = orm.DIDChangeUpdated
		didDocument, _ := eventLog.DIDDocumentVersion.ToDIDDocument()
		metadata := resolver.DocumentMetadata{
			SourceTransactions: []hash.SHA256Hash{hash.EmptyHash()},
		}
		ctx.didResolver.EXPECT().Resolve(eventLog.DID(), gomock.Any()).Return(&didDocument, &metadata, nil).AnyTimes()
		ctx.didStore.EXPECT().Resolve(eventLog.DID(), gomock.Any()).Return(&didDocument, &metadata, nil).AnyTimes()
		ctx.networkClient.EXPECT().CreateTransaction(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, template network.Template) (dag.Transaction, error) {
			assert.Len(t, template.AdditionalPrevs, 2) // previous and controller
			assert.False(t, template.AttachKey)
			return testTransaction{}, nil
		})
		require.NoError(t, ctx.db.Save(&logCopy).Error)

		err := ctx.manager.Commit(ctx.ctx, logCopy)

		assert.NoError(t, err)
	})
}

func TestManager_IsCommitted(t *testing.T) {
	document, _, _ := newDidDoc()
	documentData, _ := json.Marshal(document)
	vmData, _ := json.Marshal(document.VerificationMethod[0])
	eventLog := orm.DIDChangeLog{
		Type: orm.DIDChangeCreated,
		DIDDocumentVersion: orm.DIDDocument{
			ID: uuid.New().String(),
			DID: orm.DID{
				ID:      document.ID.String(),
				Subject: "subject",
			},
			VerificationMethods: []orm.VerificationMethod{
				{
					ID:       document.VerificationMethod[0].ID.String(),
					KeyTypes: orm.VerificationMethodKeyType(orm.AssertionKeyUsage()),
					Data:     vmData,
				},
			},
			Raw: string(documentData),
		},
	}
	changeHash := hash.SHA256Sum(documentData)

	t.Run("false", func(t *testing.T) {
		ctx := newTestContext(t)
		ctx.didStore.EXPECT().Resolve(eventLog.DID(), gomock.Any()).Return(&document, &resolver.DocumentMetadata{Hash: hash.RandomHash()}, nil)
		require.NoError(t, ctx.db.Save(&eventLog).Error)

		ok, err := ctx.manager.IsCommitted(ctx.ctx, eventLog)

		require.NoError(t, err)
		assert.False(t, ok)
	})
	t.Run("true", func(t *testing.T) {
		ctx := newTestContext(t)
		ctx.didStore.EXPECT().Resolve(eventLog.DID(), gomock.Any()).Return(&document, &resolver.DocumentMetadata{Hash: changeHash}, nil)
		require.NoError(t, ctx.db.Save(&eventLog).Error)

		ok, err := ctx.manager.IsCommitted(ctx.ctx, eventLog)

		require.NoError(t, err)
		assert.True(t, ok)
	})
}
