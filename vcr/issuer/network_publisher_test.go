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

package issuer

import (
	"encoding/json"
	"errors"
	"fmt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/types"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"testing"
	"time"
)

func Test_networkPublisher_resolveNutsCommServiceOwner(t *testing.T) {
	serviceID := ssi.MustParseURI(fmt.Sprintf("%s#1", vdr.TestDIDA.String()))
	expectedURIA := ssi.MustParseURI(fmt.Sprintf("%s/serviceEndpoint?type=NutsComm", vdr.TestDIDA.String()))
	service := did.Service{ID: serviceID, ServiceEndpoint: "grpc://foo"}

	t.Run("ok - correct did from service ID", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		sut := networkPublisher{}
		mockServiceResolver := resolver.NewMockServiceResolver(ctrl)
		sut.serviceResolver = mockServiceResolver

		mockServiceResolver.EXPECT().Resolve(expectedURIA, 5).Return(service, nil)

		serviceOwner, err := sut.resolveNutsCommServiceOwner(vdr.TestDIDA)

		require.NoError(t, err)
		assert.Equal(t, vdr.TestDIDA, *serviceOwner)
	})

	t.Run("error - service is not a valid NutsComm service", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		sut := networkPublisher{}
		mockServiceResolver := resolver.NewMockServiceResolver(ctrl)
		sut.serviceResolver = mockServiceResolver

		service := did.Service{ID: serviceID, ServiceEndpoint: "https://foo"}
		mockServiceResolver.EXPECT().Resolve(expectedURIA, 5).Return(service, nil)

		_, err := sut.resolveNutsCommServiceOwner(vdr.TestDIDA)

		require.Error(t, err)
		assert.Equal(t, "could not resolve NutsComm service owner: scheme must be grpc", err.Error())
	})

	t.Run("error from resolver", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		sut := networkPublisher{}
		mockServiceResolver := resolver.NewMockServiceResolver(ctrl)
		sut.serviceResolver = mockServiceResolver
		mockServiceResolver.EXPECT().Resolve(expectedURIA, 5).Return(did.Service{}, errors.New("b00m!"))

		_, err := sut.resolveNutsCommServiceOwner(vdr.TestDIDA)

		assert.EqualError(t, err, "could not resolve NutsComm service owner: b00m!")
	})
}

func Test_networkPublisher_PublishCredential(t *testing.T) {
	issuerID := ssi.MustParseURI("did:nuts:123")
	issuerDID, _ := did.ParseDID(issuerID.String())
	subjectID := ssi.MustParseURI("did:nuts:456")
	subjectDID, _ := did.ParseDID(subjectID.String())
	ctx := audit.TestContext()

	t.Run("ok - public", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		mockKeyResolver := resolver.NewMockKeyResolver(ctrl)
		mockDidResolver := resolver.NewMockDIDResolver(ctrl)
		mockNetwork := network.NewMockTransactions(ctrl)

		sut := networkPublisher{keyResolver: mockKeyResolver, didResolver: mockDidResolver, networkTx: mockNetwork}

		issuanceDate := time.Now()
		credentialToPublish := vc.VerifiableCredential{
			Issuer:            issuerID,
			IssuanceDate:      issuanceDate,
			CredentialSubject: []map[string]any{{"id": subjectID.String()}},
		}
		payload, _ := json.Marshal(credentialToPublish)

		testKey := crypto.NewTestKey(issuerID.String() + "#abc")

		mockKeyResolver.EXPECT().ResolveKey(*issuerDID, nil, resolver.AssertionMethod).Return(testKey.KID, testKey.PublicKey, nil)
		mockDidResolver.EXPECT().Resolve(*issuerDID, nil).Return(&did.Document{}, &resolver.DocumentMetadata{}, nil)
		expectedTemplate := network.Template{
			KID:             testKey.KID,
			Payload:         payload,
			Type:            types.VcDocumentType,
			Timestamp:       issuanceDate,
			AdditionalPrevs: nil,
			Participants:    []did.DID{},
		}
		mockNetwork.EXPECT().CreateTransaction(ctx, expectedTemplate).Return(nil, nil)

		err := sut.PublishCredential(ctx, credentialToPublish, true)
		assert.NoError(t, err)
	})

	t.Run("ok - private", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		mockKeyResolver := resolver.NewMockKeyResolver(ctrl)
		mockDidResolver := resolver.NewMockDIDResolver(ctrl)
		mockNetwork := network.NewMockTransactions(ctrl)
		mockServiceResolver := resolver.NewMockServiceResolver(ctrl)

		sut := networkPublisher{
			keyResolver:     mockKeyResolver,
			didResolver:     mockDidResolver,
			networkTx:       mockNetwork,
			serviceResolver: mockServiceResolver,
		}

		issuanceDate := time.Now()
		credentialToPublish := vc.VerifiableCredential{
			Issuer:            issuerID,
			IssuanceDate:      issuanceDate,
			CredentialSubject: []map[string]any{{"id": subjectID.String()}},
		}
		payload, _ := json.Marshal(credentialToPublish)

		testKey := crypto.NewTestKey(issuerID.String() + "#abc")

		mockKeyResolver.EXPECT().ResolveKey(*issuerDID, nil, resolver.AssertionMethod).Return(testKey.KID, testKey.PublicKey, nil)
		mockDidResolver.EXPECT().Resolve(*issuerDID, nil).Return(&did.Document{}, &resolver.DocumentMetadata{}, nil)
		expectedIssuerServiceURI := ssi.MustParseURI("did:nuts:123/serviceEndpoint?type=NutsComm")
		expectedSubjectServiceURI := ssi.MustParseURI("did:nuts:456/serviceEndpoint?type=NutsComm")
		mockServiceResolver.EXPECT().Resolve(expectedIssuerServiceURI, 5).Return(did.Service{ID: issuerID, ServiceEndpoint: "grpc://foo"}, nil)
		mockServiceResolver.EXPECT().Resolve(expectedSubjectServiceURI, 5).Return(did.Service{ID: subjectID, ServiceEndpoint: "grpc://foo"}, nil)

		expectedTemplate := network.Template{
			KID:             testKey.KID,
			Payload:         payload,
			Type:            types.VcDocumentType,
			Timestamp:       issuanceDate,
			AdditionalPrevs: nil,
			Participants:    []did.DID{*issuerDID, *subjectDID},
		}
		mockNetwork.EXPECT().CreateTransaction(ctx, expectedTemplate).Return(nil, nil)

		err := sut.PublishCredential(ctx, credentialToPublish, false)
		assert.NoError(t, err)

	})

	t.Run("error - invalid params", func(t *testing.T) {
		t.Run("invalid issuer", func(t *testing.T) {
			invalidIssuerID := ssi.MustParseURI("abc")

			credentialToPublish := vc.VerifiableCredential{
				Issuer: invalidIssuerID,
			}

			sut := networkPublisher{}
			err := sut.PublishCredential(ctx, credentialToPublish, true)
			assert.EqualError(t, err, "invalid credential issuer: invalid DID")
		})

		t.Run("missing credentialSubject", func(t *testing.T) {
			credentialToPublish := vc.VerifiableCredential{
				Issuer: issuerID,
			}

			sut := networkPublisher{}
			err := sut.PublishCredential(ctx, credentialToPublish, false)
			assert.EqualError(t, err, "missing credentialSubject")
		})

		t.Run("invalid credentialSubject for private transaction", func(t *testing.T) {
			credentialToPublish := vc.VerifiableCredential{
				Issuer:            issuerID,
				CredentialSubject: []map[string]any{{"id": "abc"}},
			}

			sut := networkPublisher{}
			err := sut.PublishCredential(ctx, credentialToPublish, false)
			assert.EqualError(t, err, "failed to determine credentialSubject.ID: unable to get subject DID from VC: invalid DID")
		})
	})

	t.Run("error - returned from function calls", func(t *testing.T) {
		t.Run("missing NutsCommEndpoint", func(t *testing.T) {
			ctrl := gomock.NewController(t)

			mockServiceResolver := resolver.NewMockServiceResolver(ctrl)

			sut := networkPublisher{
				serviceResolver: mockServiceResolver,
			}

			credentialToPublish := vc.VerifiableCredential{
				Issuer:            issuerID,
				CredentialSubject: []map[string]any{{"id": subjectID.String()}},
			}
			expectedIssuerServiceURI := ssi.MustParseURI("did:nuts:123/serviceEndpoint?type=NutsComm")
			mockServiceResolver.EXPECT().Resolve(expectedIssuerServiceURI, 5).Return(did.Service{}, resolver.ErrServiceNotFound)

			err := sut.PublishCredential(ctx, credentialToPublish, false)
			assert.EqualError(t, err, "failed to resolve participating node (did=did:nuts:123): could not resolve NutsComm service owner: service not found in DID Document")
		})

		t.Run("unable to resolve an assertionKey for the issuer", func(t *testing.T) {
			ctrl := gomock.NewController(t)

			mockKeyResolver := resolver.NewMockKeyResolver(ctrl)
			sut := networkPublisher{keyResolver: mockKeyResolver}

			credentialToPublish := vc.VerifiableCredential{
				Issuer:            issuerID,
				CredentialSubject: []map[string]any{{"id": subjectID.String()}},
			}

			mockKeyResolver.EXPECT().ResolveKey(*issuerDID, nil, resolver.AssertionMethod).Return("", nil, errors.New("b00m!"))

			err := sut.PublishCredential(ctx, credentialToPublish, true)
			assert.EqualError(t, err, "could not resolve an assertion key for issuer: b00m!")
		})

		t.Run("error while creating network transaction", func(t *testing.T) {
			ctrl := gomock.NewController(t)

			mockKeyResolver := resolver.NewMockKeyResolver(ctrl)
			mockDidResolver := resolver.NewMockDIDResolver(ctrl)
			mockNetwork := network.NewMockTransactions(ctrl)

			sut := networkPublisher{keyResolver: mockKeyResolver, didResolver: mockDidResolver, networkTx: mockNetwork}

			issuanceDate := time.Now()
			credentialToPublish := vc.VerifiableCredential{
				Issuer:            issuerID,
				IssuanceDate:      issuanceDate,
				CredentialSubject: []map[string]any{{"id": subjectID.String()}},
			}
			payload, _ := json.Marshal(credentialToPublish)

			testKey := crypto.NewTestKey(issuerID.String() + "#abc")

			mockKeyResolver.EXPECT().ResolveKey(*issuerDID, nil, resolver.AssertionMethod).Return(testKey.KID, testKey.PublicKey, nil)
			mockDidResolver.EXPECT().Resolve(*issuerDID, nil).Return(&did.Document{}, &resolver.DocumentMetadata{}, nil)
			expectedTemplate := network.Template{
				KID:             testKey.KID,
				Payload:         payload,
				Type:            types.VcDocumentType,
				Timestamp:       issuanceDate,
				AdditionalPrevs: nil,
				Participants:    make([]did.DID, 0),
			}
			mockNetwork.EXPECT().CreateTransaction(ctx, expectedTemplate).Return(nil, errors.New("b00m!"))

			err := sut.PublishCredential(ctx, credentialToPublish, true)
			assert.EqualError(t, err, "failed to publish credential, error while creating transaction: b00m!")
		})

	})

}

func TestNewNetworkPublisher(t *testing.T) {
	publisher := NewNetworkPublisher(nil, nil, nil)
	assert.IsType(t, &networkPublisher{}, publisher)
}

func Test_networkPublisher_PublishRevocation(t *testing.T) {
	issuerID := ssi.MustParseURI("did:nuts:123")
	issuerDID, _ := did.ParseDID(issuerID.String())
	testKey := crypto.NewTestKey(issuerID.String() + "#abc")
	ctx := audit.TestContext()

	t.Run("it should publish a revocation", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		mockKeyResolver := resolver.NewMockKeyResolver(ctrl)
		mockDidResolver := resolver.NewMockDIDResolver(ctrl)
		mockNetwork := network.NewMockTransactions(ctrl)

		mockKeyResolver.EXPECT().ResolveKey(*issuerDID, nil, resolver.AssertionMethod).Return(testKey.KID, testKey.PublicKey, nil)
		mockDidResolver.EXPECT().Resolve(*issuerDID, nil).Return(&did.Document{}, &resolver.DocumentMetadata{}, nil)

		revocationToPublish := credential.Revocation{
			Issuer: issuerID,
		}
		payload, _ := json.Marshal(revocationToPublish)

		expectedTemplate := network.Template{
			KID:             testKey.KID,
			Payload:         payload,
			Type:            types.RevocationLDDocumentType,
			Timestamp:       time.Time{},
			AdditionalPrevs: nil,
			Participants:    nil,
		}
		mockNetwork.EXPECT().CreateTransaction(ctx, gomock.Eq(expectedTemplate)).Return(nil, nil)

		sut := networkPublisher{keyResolver: mockKeyResolver, didResolver: mockDidResolver, networkTx: mockNetwork}

		err := sut.PublishRevocation(ctx, revocationToPublish)
		assert.NoError(t, err, "expected publishing to succeed")
	})

	t.Run("params", func(t *testing.T) {
		t.Run("it checks the issuer", func(t *testing.T) {
			publisher := NewNetworkPublisher(nil, nil, nil)
			revocationToPublish := credential.Revocation{}
			err := publisher.PublishRevocation(ctx, revocationToPublish)
			assert.EqualError(t, err, "invalid revocation issuer: invalid DID: DID must start with 'did:'")
		})
	})

	t.Run("handling errors from other services", func(t *testing.T) {
		t.Run("assertion key could not be found", func(t *testing.T) {
			ctrl := gomock.NewController(t)

			mockKeyResolver := resolver.NewMockKeyResolver(ctrl)
			mockDidResolver := resolver.NewMockDIDResolver(ctrl)
			mockNetwork := network.NewMockTransactions(ctrl)

			mockKeyResolver.EXPECT().ResolveKey(*issuerDID, nil, resolver.AssertionMethod).Return("", nil, errors.New("not found"))

			revocationToPublish := credential.Revocation{
				Issuer: issuerID,
			}

			sut := networkPublisher{keyResolver: mockKeyResolver, didResolver: mockDidResolver, networkTx: mockNetwork}

			err := sut.PublishRevocation(ctx, revocationToPublish)
			assert.EqualError(t, err, "could not resolve an assertion key for issuer: not found")

		})

		t.Run("did document of issuer could not be found", func(t *testing.T) {
			ctrl := gomock.NewController(t)

			mockKeyResolver := resolver.NewMockKeyResolver(ctrl)
			mockDidResolver := resolver.NewMockDIDResolver(ctrl)
			mockNetwork := network.NewMockTransactions(ctrl)

			mockKeyResolver.EXPECT().ResolveKey(*issuerDID, nil, resolver.AssertionMethod).Return(testKey.KID, testKey.PublicKey, nil)
			mockDidResolver.EXPECT().Resolve(*issuerDID, nil).Return(nil, nil, errors.New("not found"))

			revocationToPublish := credential.Revocation{
				Issuer: issuerID,
			}

			sut := networkPublisher{keyResolver: mockKeyResolver, didResolver: mockDidResolver, networkTx: mockNetwork}

			err := sut.PublishRevocation(ctx, revocationToPublish)
			assert.EqualError(t, err, "could not resolve issuer DID document: not found")
		})

		t.Run("network returns error", func(t *testing.T) {
			ctrl := gomock.NewController(t)

			mockKeyResolver := resolver.NewMockKeyResolver(ctrl)
			mockDidResolver := resolver.NewMockDIDResolver(ctrl)
			mockNetwork := network.NewMockTransactions(ctrl)

			mockKeyResolver.EXPECT().ResolveKey(*issuerDID, nil, resolver.AssertionMethod).Return(testKey.KID, testKey.PublicKey, nil)
			mockDidResolver.EXPECT().Resolve(*issuerDID, nil).Return(&did.Document{}, &resolver.DocumentMetadata{}, nil)
			mockNetwork.EXPECT().CreateTransaction(ctx, gomock.Any()).Return(nil, errors.New("foo"))

			revocationToPublish := credential.Revocation{
				Issuer: issuerID,
			}

			sut := networkPublisher{keyResolver: mockKeyResolver, didResolver: mockDidResolver, networkTx: mockNetwork}

			err := sut.PublishRevocation(ctx, revocationToPublish)
			assert.EqualError(t, err, "failed to publish revocation, error while creating transaction: foo")
		})
	})
}
