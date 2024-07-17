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
	"encoding/json"
	"fmt"
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
	"github.com/nuts-foundation/nuts-node/vdr/didnuts/didstore"
	"github.com/nuts-foundation/nuts-node/vdr/didsubject"
	"github.com/nuts-foundation/nuts-node/vdr/management"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"gorm.io/gorm"
	"strings"
	"testing"
)

type testContext struct {
	ctrl          *gomock.Controller
	manager       *Manager
	networkClient *network.MockTransactions
	didStore      *didstore.MockStore
	didResolver   *resolver.MockDIDResolver
	db            *gorm.DB
	ctx           context.Context
	keyStore      *nutsCrypto.MockKeyStore
}

func newTestContext(t *testing.T) *testContext {
	ctrl := gomock.NewController(t)
	networkClient := network.NewMockTransactions(ctrl)
	didStore := didstore.NewMockStore(ctrl)
	didResolver := resolver.NewMockDIDResolver(ctrl)
	ctx := audit.TestContext()
	db := testDB(t)
	keyStore := nutsCrypto.NewMockKeyStore(ctrl)
	manager := NewManager(db, keyStore, networkClient, didStore, didResolver, nil, nil)

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

// todo remove at the end of #3208
func TestManager_Create(t *testing.T) {
	ctrl := gomock.NewController(t)
	creator := management.NewMockDocCreator(ctrl)
	owner := management.NewMockDocumentOwner(ctrl)
	manager := NewManager(nil, nil, nil, nil, nil, creator, owner)
	creator.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil, nil, nil)

	_, _, err := manager.Create(nil, DefaultCreationOptions())

	assert.NoError(t, err)
}

// todo remove at the end of #3208
func TestManager_Resolve(t *testing.T) {
	_, _, err := Manager{}.Resolve(did.DID{}, nil)
	assert.EqualError(t, err, "Resolve() is not supported for did:nuts")
}

// todo remove at the end of #3208
func TestManager_CreateService(t *testing.T) {
	_, err := Manager{}.CreateService(nil, did.DID{}, did.Service{})
	assert.EqualError(t, err, "CreateService() is not supported for did:nuts")
}

// todo remove at the end of #3208
func TestManager_DeleteService(t *testing.T) {
	err := Manager{}.DeleteService(nil, did.DID{}, ssi.MustParseURI("https://example.com"))
	assert.EqualError(t, err, "DeleteService() is not supported for did:nuts")
}

// todo remove at the end of #3208
func TestManager_UpdateService(t *testing.T) {
	_, err := Manager{}.UpdateService(nil, did.DID{}, ssi.MustParseURI("https://example.com"), did.Service{})
	assert.EqualError(t, err, "UpdateService() is not supported for did:nuts")
}

func TestManager_GenerateDocument(t *testing.T) {
	keyStore := nutsCrypto.NewMemoryCryptoInstance()
	ctx := audit.TestContext()
	db := testDB(t)
	manager := NewManager(db, keyStore, nil, nil, nil, nil, nil)

	t.Run("ok", func(t *testing.T) {
		doc, err := manager.NewDocument(ctx, didsubject.AssertionKeyUsage())

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

			verificationMethod, err := manager.NewVerificationMethod(ctx, asDID, didsubject.AssertionKeyUsage())

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
	eventLog := didsubject.DIDChangeLog{
		Type: didsubject.DIDChangeCreated,
		DIDDocumentVersion: didsubject.DIDDocument{
			ID: uuid.New().String(),
			DID: didsubject.DID{
				ID:      document.ID.String(),
				Subject: "subject",
			},
			VerificationMethods: []didsubject.VerificationMethod{
				{
					ID:       document.VerificationMethod[0].ID.String(),
					KeyTypes: didsubject.VerificationMethodKeyType(didsubject.AssertionKeyUsage()),
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
		logCopy.Type = didsubject.DIDChangeDeactivated
		didDocument, _ := eventLog.DIDDocumentVersion.ToDIDDocument()
		metadata := resolver.DocumentMetadata{
			SourceTransactions: []hash.SHA256Hash{hash.EmptyHash()},
		}
		ctx.didResolver.EXPECT().Resolve(eventLog.DID(), gomock.Any()).Return(&didDocument, &metadata, nil).AnyTimes()
		ctx.didStore.EXPECT().Resolve(eventLog.DID(), gomock.Any()).Return(&didDocument, &metadata, nil)
		ctx.didStore.EXPECT().Add(gomock.Any(), gomock.Any()).Return(nil)
		ctx.keyStore.EXPECT().Resolve(gomock.Any(), document.VerificationMethod[0].ID.String()).Return(nutsCrypto.TestKey{}, nil)
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
		logCopy.Type = didsubject.DIDChangeUpdated
		didDocument, _ := eventLog.DIDDocumentVersion.ToDIDDocument()
		metadata := resolver.DocumentMetadata{
			SourceTransactions: []hash.SHA256Hash{hash.EmptyHash()},
		}
		ctx.didResolver.EXPECT().Resolve(eventLog.DID(), gomock.Any()).Return(&didDocument, &metadata, nil).AnyTimes()
		ctx.didStore.EXPECT().Resolve(eventLog.DID(), gomock.Any()).Return(&didDocument, &metadata, nil).AnyTimes()
		ctx.keyStore.EXPECT().Resolve(gomock.Any(), document.VerificationMethod[0].ID.String()).Return(nutsCrypto.TestKey{}, nil)
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
	eventLog := didsubject.DIDChangeLog{
		Type: didsubject.DIDChangeCreated,
		DIDDocumentVersion: didsubject.DIDDocument{
			ID: uuid.New().String(),
			DID: didsubject.DID{
				ID:      document.ID.String(),
				Subject: "subject",
			},
			VerificationMethods: []didsubject.VerificationMethod{
				{
					ID:       document.VerificationMethod[0].ID.String(),
					KeyTypes: didsubject.VerificationMethodKeyType(didsubject.AssertionKeyUsage()),
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
