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

package golden_hammer

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/didman"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/nuts-foundation/nuts-node/test/pki"
	"github.com/nuts-foundation/nuts-node/vcr/openid4vci"
	"github.com/nuts-foundation/nuts-node/vdr/didservice"
	"github.com/nuts-foundation/nuts-node/vdr/didstore"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"go.uber.org/mock/gomock"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

var vendorDID = did.MustParseDID("did:nuts:vendor")
var serviceRef, _ = url.Parse(vendorDID.String() + "/serviceEndpoint?type=node-http-services-baseurl")
var clientADID = did.MustParseDID("did:nuts:clientA")
var clientBDID = did.MustParseDID("did:nuts:clientB")
var clientCDID = did.MustParseDID("did:nuts:clientC")

func TestGoldenHammer_Fix(t *testing.T) {
	var vendorDocumentWithBaseURL = did.Document{
		ID: vendorDID,
		Service: []did.Service{
			{
				Type:            types.BaseURLServiceType,
				ServiceEndpoint: "https://example.com",
			},
			{
				Type:            transport.NutsCommServiceType,
				ServiceEndpoint: didservice.MakeServiceReference(vendorDID, transport.NutsCommServiceType),
			},
		},
	}
	var vendorDocumentWithoutBaseURL = did.Document{
		ID: vendorDID,
		Service: []did.Service{
			{
				Type:            transport.NutsCommServiceType,
				ServiceEndpoint: "grpc://example.com:5555",
			},
		},
	}
	var clientDocumentWithoutBaseURL = did.Document{
		Service: []did.Service{
			{
				Type:            transport.NutsCommServiceType,
				ServiceEndpoint: didservice.MakeServiceReference(vendorDID, transport.NutsCommServiceType),
			},
		},
	}
	var clientDocumentWithBaseURL = did.Document{
		Service: []did.Service{
			{
				Type:            types.BaseURLServiceType,
				ServiceEndpoint: didservice.MakeServiceReference(vendorDID, types.BaseURLServiceType),
			},
			{
				Type:            transport.NutsCommServiceType,
				ServiceEndpoint: didservice.MakeServiceReference(vendorDID, transport.NutsCommServiceType),
			},
		},
	}

	// vendor and care organization DIDs do not have the required service, so it should be registered
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
	}))
	serverURL, _ := url.Parse(tlsServer.URL)
	expectedBaseURL, _ := url.Parse("https://localhost:" + serverURL.Port())
	serverPort, _ := strconv.Atoi(serverURL.Port())
	openid4vci.SetTLSIdentifierResolverPort(t, serverPort)
	defer tlsServer.Close()

	t.Run("nothing to fix", func(t *testing.T) {
		// vendor and care organization DIDs already have the required service, so there's nothing to fix
		ctrl := gomock.NewController(t)
		didStore := didstore.NewMockStore(ctrl)
		didStore.EXPECT().Resolve(vendorDID, gomock.Any()).Return(&vendorDocumentWithBaseURL, nil, nil).MinTimes(1)
		didStore.EXPECT().Resolve(clientADID, gomock.Any()).Return(&clientDocumentWithBaseURL, nil, nil).MinTimes(1)
		didStore.EXPECT().Resolve(clientBDID, gomock.Any()).Return(&clientDocumentWithBaseURL, nil, nil).MinTimes(1)
		documentOwner := types.NewMockDocumentOwner(ctrl)
		documentOwner.EXPECT().ListOwned(gomock.Any()).Return([]did.DID{vendorDID, clientADID, clientBDID}, nil)
		service := New(documentOwner, nil, didStore)

		err := service.registerServiceBaseURLs()

		assert.NoError(t, err)

		t.Run("second time list of fixed DIDs is cached (no DID resolving)", func(t *testing.T) {
			documentOwner.EXPECT().ListOwned(gomock.Any()).Return([]did.DID{vendorDID, clientADID, clientBDID}, nil)

			err := service.registerServiceBaseURLs()

			assert.NoError(t, err)
		})
	})
	t.Run("to be registered on vendor DID and client DIDs", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		didStore := didstore.NewMockStore(ctrl)
		docClientA := clientDocumentWithoutBaseURL
		docClientA.ID = clientADID
		docClientB := clientDocumentWithoutBaseURL
		docClientB.ID = clientBDID

		documentOwner := types.NewMockDocumentOwner(ctrl)
		// Order DIDs such that care organization DID is first, to test ordering
		documentOwner.EXPECT().ListOwned(gomock.Any()).Return([]did.DID{clientADID, vendorDID, clientBDID}, nil)
		didmanAPI := didman.NewMockDidman(ctrl)
		gomock.InOrder(
			// DID documents are listed first to check if they should be fixed
			didStore.EXPECT().Resolve(clientADID, gomock.Any()).Return(&docClientA, nil, nil),
			didStore.EXPECT().Resolve(vendorDID, gomock.Any()).Return(&vendorDocumentWithoutBaseURL, nil, nil),
			didStore.EXPECT().Resolve(clientBDID, gomock.Any()).Return(&docClientB, nil, nil),

			// Vendor document is fixed first
			didmanAPI.EXPECT().AddEndpoint(gomock.Any(), vendorDID, types.BaseURLServiceType, *expectedBaseURL).Return(nil, nil),

			// Then client A
			didStore.EXPECT().Resolve(vendorDID, gomock.Any()).Return(&vendorDocumentWithBaseURL, nil, nil),
			didmanAPI.EXPECT().AddEndpoint(gomock.Any(), clientADID, types.BaseURLServiceType, *serviceRef).Return(nil, nil),

			// Then client B
			didStore.EXPECT().Resolve(vendorDID, gomock.Any()).Return(&vendorDocumentWithBaseURL, nil, nil),
			didmanAPI.EXPECT().AddEndpoint(gomock.Any(), clientBDID, types.BaseURLServiceType, *serviceRef).Return(nil, nil),
		)
		service := New(documentOwner, didmanAPI, didStore)
		service.tlsConfig = tlsServer.TLS
		service.tlsConfig.InsecureSkipVerify = true
		service.tlsConfig.Certificates = []tls.Certificate{pki.Certificate()}

		err := service.registerServiceBaseURLs()

		assert.NoError(t, err)
	})
	t.Run("vendor identifier can't be resolved from TLS", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		didStore := didstore.NewMockStore(ctrl)
		didStore.EXPECT().Resolve(vendorDID, gomock.Any()).Return(&vendorDocumentWithoutBaseURL, nil, nil).MinTimes(1)
		documentOwner := types.NewMockDocumentOwner(ctrl)
		documentOwner.EXPECT().ListOwned(gomock.Any()).Return([]did.DID{vendorDID}, nil)
		service := New(documentOwner, nil, didStore)
		service.tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{pki.Certificate()},
		}

		err := service.registerServiceBaseURLs()

		assert.NoError(t, err)
	})
	t.Run("to be registered on client DIDs", func(t *testing.T) {
		// vendor DID document already contains the service, but its care organization DID documents not yet,
		// so they need to be registered.
		ctrl := gomock.NewController(t)
		didStore := didstore.NewMockStore(ctrl)
		didStore.EXPECT().Resolve(vendorDID, gomock.Any()).Return(&vendorDocumentWithBaseURL, nil, nil).MinTimes(1)
		docClientA := clientDocumentWithoutBaseURL
		docClientA.ID = clientADID
		docClientB := clientDocumentWithoutBaseURL
		docClientB.ID = clientBDID
		didStore.EXPECT().Resolve(clientADID, gomock.Any()).Return(&docClientA, nil, nil).MinTimes(1)
		didStore.EXPECT().Resolve(clientBDID, gomock.Any()).Return(&docClientB, nil, nil).MinTimes(1)
		// Client C is owned, but not linked to the vendor (via NutsComm service), so do not register the service on that one
		didStore.EXPECT().Resolve(clientCDID, gomock.Any()).Return(&did.Document{ID: clientCDID}, nil, nil).MinTimes(1)
		documentOwner := types.NewMockDocumentOwner(ctrl)
		documentOwner.EXPECT().ListOwned(gomock.Any()).Return([]did.DID{vendorDID, clientADID, clientBDID, clientCDID}, nil)
		didmanAPI := didman.NewMockDidman(ctrl)
		// AddEndpoint is not called for vendor DID (URL already present), but for client DIDs.
		// Not for clientC, since it's not linked to the vendor (doesn't have a NutsComm endpoint).
		didmanAPI.EXPECT().AddEndpoint(gomock.Any(), clientADID, types.BaseURLServiceType, *serviceRef).Return(nil, nil)
		didmanAPI.EXPECT().AddEndpoint(gomock.Any(), clientBDID, types.BaseURLServiceType, *serviceRef).Return(nil, nil)
		service := New(documentOwner, didmanAPI, didStore)
		service.tlsConfig = tlsServer.TLS
		service.tlsConfig.InsecureSkipVerify = true
		service.tlsConfig.Certificates = []tls.Certificate{pki.Certificate()}

		err := service.registerServiceBaseURLs()

		assert.NoError(t, err)
	})
	t.Run("resolve error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		didStore := didstore.NewMockStore(ctrl)
		didStore.EXPECT().Resolve(vendorDID, gomock.Any()).Return(nil, nil, fmt.Errorf("resolve error"))
		documentOwner := types.NewMockDocumentOwner(ctrl)
		documentOwner.EXPECT().ListOwned(gomock.Any()).Return([]did.DID{vendorDID}, nil)
		service := New(documentOwner, nil, didStore)
		service.tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{pki.Certificate()},
		}

		err := service.registerServiceBaseURLs()

		assert.NoError(t, err)
	})
}

// TestGoldenHammer_Lifecycle tests the lifecycle of the golden hammer service (starting it, asserting it tries to fix stuff, then shutdown).
func TestGoldenHammer_Lifecycle(t *testing.T) {
	t.Run("enabled", func(t *testing.T) {
		defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

		fixCalled := &atomic.Int64{}
		ctrl := gomock.NewController(t)
		documentOwner := types.NewMockDocumentOwner(ctrl)
		documentOwner.EXPECT().ListOwned(gomock.Any()).DoAndReturn(func(_ context.Context) ([]did.DID, error) {
			fixCalled.Add(1)
			return []did.DID{}, nil
		}).MinTimes(1)
		service := New(documentOwner, nil, nil)
		service.config.Interval = time.Millisecond
		service.config.Enabled = true

		err := service.Start()
		require.NoError(t, err)
		test.WaitFor(t, func() (bool, error) {
			// Fix should be called at least twice (since it's a loop)
			return fixCalled.Load() > 1, nil
		}, time.Second, "ListOwned() not called")

		err = service.Shutdown()
		require.NoError(t, err)
	})
	t.Run("disabled", func(t *testing.T) {
		service := New(nil, nil, nil)

		err := service.Start()
		require.NoError(t, err)

		err = service.Shutdown()
		require.NoError(t, err)
	})
}

func TestGoldenHammer_Name(t *testing.T) {
	service := New(nil, nil, nil)

	assert.Equal(t, "GoldenHammer", service.Name())
}

func TestGoldenHammer_Configure(t *testing.T) {
	t.Run("TLS enabled", func(t *testing.T) {
		cfg := core.NewServerConfig()
		cfg.TLS.CertFile = pki.CertificateFile(t)
		cfg.TLS.CertKeyFile = cfg.TLS.CertFile
		cfg.TLS.TrustStoreFile = pki.TruststoreFile(t)
		err := New(nil, nil, nil).Configure(*cfg)
		assert.NoError(t, err)
	})
	t.Run("TLS disabled", func(t *testing.T) {
		err := New(nil, nil, nil).Configure(*core.NewServerConfig())
		assert.NoError(t, err)
	})
}
