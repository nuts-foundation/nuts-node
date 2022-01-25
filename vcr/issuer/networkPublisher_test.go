package issuer

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang/mock/gomock"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/doc"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func Test_networkPublisher_resolveNutsCommServiceOwner(t *testing.T) {
	serviceID, _ := ssi.ParseURI(fmt.Sprintf("%s#1", vdr.TestDIDA.String()))
	expectedURIA, _ := ssi.ParseURI(fmt.Sprintf("%s/serviceEndpoint?type=NutsComm", vdr.TestDIDA.String()))
	service := did.Service{ID: *serviceID}

	t.Run("ok - correct did from service ID", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		sut := networkPublisher{}
		mockServiceResolver := doc.NewMockServiceResolver(ctrl)
		sut.serviceResolver = mockServiceResolver

		mockServiceResolver.EXPECT().Resolve(*expectedURIA, 5).Return(service, nil)

		serviceOwner, err := sut.resolveNutsCommServiceOwner(*vdr.TestDIDA)

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, vdr.TestDIDA, serviceOwner)
	})

	t.Run("error from resolver", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		sut := networkPublisher{}
		mockServiceResolver := doc.NewMockServiceResolver(ctrl)
		sut.serviceResolver = mockServiceResolver
		mockServiceResolver.EXPECT().Resolve(*expectedURIA, 5).Return(did.Service{}, errors.New("b00m!"))

		_, err := sut.resolveNutsCommServiceOwner(*vdr.TestDIDA)

		if !assert.Error(t, err) {
			return
		}
		assert.EqualError(t, err, "could not resolve NutsComm service owner: b00m!")
	})
}

func Test_networkPublisher_PublishCredential(t *testing.T) {
	issuerID, _ := ssi.ParseURI("did:nuts:123")
	issuerDID, _ := did.ParseDID(issuerID.String())
	subjectID, _ := ssi.ParseURI("did:nuts:456")
	subjectDID, _ := did.ParseDID(subjectID.String())

	t.Run("ok - public", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockKeyResolver := NewMockkeyResolver(ctrl)
		mockDocResolver := types.NewMockDocResolver(ctrl)
		mockNetwork := network.NewMockTransactions(ctrl)

		sut := networkPublisher{keyResolver: mockKeyResolver, didDocResolver: mockDocResolver, networkTx: mockNetwork}

		credentialToPublish := vc.VerifiableCredential{
			Issuer:            *issuerID,
			CredentialSubject: []interface{}{credential.BaseCredentialSubject{ID: subjectID.String()}},
		}
		payload, _ := json.Marshal(credentialToPublish)

		testKey := crypto.NewTestKey(issuerID.String() + "#abc")

		mockKeyResolver.EXPECT().ResolveAssertionKey(*issuerDID).Return(testKey, nil)
		mockDocResolver.EXPECT().Resolve(*issuerDID, nil).Return(&did.Document{}, &types.DocumentMetadata{}, nil)
		expectedTemplate := network.Template{
			Key:             testKey,
			Payload:         payload,
			Type:            VcDocumentType,
			AttachKey:       false,
			Timestamp:       time.Time{},
			AdditionalPrevs: nil,
			Participants:    make([]did.DID, 0),
		}
		mockNetwork.EXPECT().CreateTransaction(expectedTemplate).Return(nil, nil)

		err := sut.PublishCredential(credentialToPublish, true)
		assert.NoError(t, err)
	})

	t.Run("ok - private", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockKeyResolver := NewMockkeyResolver(ctrl)
		mockDocResolver := types.NewMockDocResolver(ctrl)
		mockNetwork := network.NewMockTransactions(ctrl)
		mockServiceResolver := doc.NewMockServiceResolver(ctrl)

		sut := networkPublisher{
			keyResolver:     mockKeyResolver,
			didDocResolver:  mockDocResolver,
			networkTx:       mockNetwork,
			serviceResolver: mockServiceResolver,
		}

		credentialToPublish := vc.VerifiableCredential{
			Issuer:            *issuerID,
			CredentialSubject: []interface{}{credential.BaseCredentialSubject{ID: subjectID.String()}},
		}
		payload, _ := json.Marshal(credentialToPublish)

		testKey := crypto.NewTestKey(issuerID.String() + "#abc")

		mockKeyResolver.EXPECT().ResolveAssertionKey(*issuerDID).Return(testKey, nil)
		mockDocResolver.EXPECT().Resolve(*issuerDID, nil).Return(&did.Document{}, &types.DocumentMetadata{}, nil)
		expectedIssuerServiceURI, _ := ssi.ParseURI("did:nuts:123/serviceEndpoint?type=NutsComm")
		expectedSubjectServiceURI, _ := ssi.ParseURI("did:nuts:456/serviceEndpoint?type=NutsComm")
		mockServiceResolver.EXPECT().Resolve(*expectedIssuerServiceURI, 5).Return(did.Service{ID: *issuerID}, nil)
		mockServiceResolver.EXPECT().Resolve(*expectedSubjectServiceURI, 5).Return(did.Service{ID: *subjectID}, nil)

		expectedTemplate := network.Template{
			Key:             testKey,
			Payload:         payload,
			Type:            VcDocumentType,
			AttachKey:       false,
			Timestamp:       time.Time{},
			AdditionalPrevs: nil,
			Participants:    []did.DID{*issuerDID, *subjectDID},
		}
		mockNetwork.EXPECT().CreateTransaction(expectedTemplate).Return(nil, nil)

		err := sut.PublishCredential(credentialToPublish, false)
		assert.NoError(t, err)

	})

	t.Run("error - invalid params", func(t *testing.T) {
		t.Run("invalid issuer", func(t *testing.T) {
			invalidIssuerID, _ := ssi.ParseURI("abc")

			credentialToPublish := vc.VerifiableCredential{
				Issuer: *invalidIssuerID,
			}

			sut := networkPublisher{}
			err := sut.PublishCredential(credentialToPublish, true)
			assert.EqualError(t, err, "invalid credential issuer: invalid DID: input length is less than 7")
		})

		t.Run("missing credentialSubject", func(t *testing.T) {
			credentialToPublish := vc.VerifiableCredential{
				Issuer: *issuerID,
			}

			sut := networkPublisher{}
			err := sut.PublishCredential(credentialToPublish, false)
			assert.EqualError(t, err, "missing credentialSubject")
		})

		t.Run("invalid credentialSubject for private transaction", func(t *testing.T) {
			credentialToPublish := vc.VerifiableCredential{
				Issuer:            *issuerID,
				CredentialSubject: []interface{}{credential.BaseCredentialSubject{ID: "abc"}},
			}

			sut := networkPublisher{}
			err := sut.PublishCredential(credentialToPublish, false)
			assert.EqualError(t, err, "failed to determine credentialSubject.ID: invalid DID: input length is less than 7")
		})
	})

	t.Run("error - returned from function calls", func(t *testing.T) {
		t.Run("missing NutsCommEndpoint", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockServiceResolver := doc.NewMockServiceResolver(ctrl)

			sut := networkPublisher{
				serviceResolver: mockServiceResolver,
			}

			credentialToPublish := vc.VerifiableCredential{
				Issuer:            *issuerID,
				CredentialSubject: []interface{}{credential.BaseCredentialSubject{ID: subjectID.String()}},
			}
			expectedIssuerServiceURI, _ := ssi.ParseURI("did:nuts:123/serviceEndpoint?type=NutsComm")
			mockServiceResolver.EXPECT().Resolve(*expectedIssuerServiceURI, 5).Return(did.Service{}, types.ErrServiceNotFound)

			err := sut.PublishCredential(credentialToPublish, false)
			assert.EqualError(t, err, "failed to resolve participating node (did=did:nuts:123): could not resolve NutsComm service owner: service not found in DID Document")
		})

		t.Run("unable to resolve an assertionKey for the issuer", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockKeyResolver := NewMockkeyResolver(ctrl)
			sut := networkPublisher{keyResolver: mockKeyResolver}

			credentialToPublish := vc.VerifiableCredential{
				Issuer:            *issuerID,
				CredentialSubject: []interface{}{credential.BaseCredentialSubject{ID: subjectID.String()}},
			}

			mockKeyResolver.EXPECT().ResolveAssertionKey(*issuerDID).Return(nil, errors.New("b00m!"))

			err := sut.PublishCredential(credentialToPublish, true)
			assert.EqualError(t, err, "could not resolve an assertion key for issuer: b00m!")
		})

		t.Run("error while creating network transaction", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockKeyResolver := NewMockkeyResolver(ctrl)
			mockDocResolver := types.NewMockDocResolver(ctrl)
			mockNetwork := network.NewMockTransactions(ctrl)

			sut := networkPublisher{keyResolver: mockKeyResolver, didDocResolver: mockDocResolver, networkTx: mockNetwork}

			credentialToPublish := vc.VerifiableCredential{
				Issuer:            *issuerID,
				CredentialSubject: []interface{}{credential.BaseCredentialSubject{ID: subjectID.String()}},
			}
			payload, _ := json.Marshal(credentialToPublish)

			testKey := crypto.NewTestKey(issuerID.String() + "#abc")

			mockKeyResolver.EXPECT().ResolveAssertionKey(*issuerDID).Return(testKey, nil)
			mockDocResolver.EXPECT().Resolve(*issuerDID, nil).Return(&did.Document{}, &types.DocumentMetadata{}, nil)
			expectedTemplate := network.Template{
				Key:             testKey,
				Payload:         payload,
				Type:            VcDocumentType,
				AttachKey:       false,
				Timestamp:       time.Time{},
				AdditionalPrevs: nil,
				Participants:    make([]did.DID, 0),
			}
			mockNetwork.EXPECT().CreateTransaction(expectedTemplate).Return(nil, errors.New("b00m!"))

			err := sut.PublishCredential(credentialToPublish, true)
			assert.EqualError(t, err, "failed to publish credential, error while creating transaction: b00m!")
		})

	})

}

func TestNewNetworkPublisher(t *testing.T) {
	publisher := NewNetworkPublisher(nil, nil, nil)
	assert.IsType(t, &networkPublisher{}, publisher)
}
