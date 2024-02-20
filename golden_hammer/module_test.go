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
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
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
				Type:            resolver.BaseURLServiceType,
				ServiceEndpoint: "https://example.com",
			},
			{
				Type:            transport.NutsCommServiceType,
				ServiceEndpoint: resolver.MakeServiceReference(vendorDID, transport.NutsCommServiceType),
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
				ServiceEndpoint: resolver.MakeServiceReference(vendorDID, transport.NutsCommServiceType),
			},
		},
	}
	var clientDocumentWithBaseURL = did.Document{
		Service: []did.Service{
			{
				Type:            resolver.BaseURLServiceType,
				ServiceEndpoint: resolver.MakeServiceReference(vendorDID, resolver.BaseURLServiceType),
			},
			{
				Type:            transport.NutsCommServiceType,
				ServiceEndpoint: resolver.MakeServiceReference(vendorDID, transport.NutsCommServiceType),
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

	t.Run("DID methods other than did:nuts are ignored", func(t *testing.T) {
		ctx := newMockContext(t)
		otherDID := did.MustParseDID("did:example:123")
		ctx.vdr.EXPECT().ListOwned(gomock.Any()).Return([]did.DID{otherDID}, nil)
		service := ctx.hammer
		service.tlsConfig = tlsServer.TLS
		service.tlsConfig.InsecureSkipVerify = true
		service.tlsConfig.Certificates = []tls.Certificate{pki.Certificate()}

		err := service.registerServiceBaseURLs()

		assert.NoError(t, err)
	})
	t.Run("nothing to fix", func(t *testing.T) {
		// vendor and care organization DIDs already have the required service, so there's nothing to fix
		ctx := newMockContext(t)
		ctx.didResolver.EXPECT().Resolve(vendorDID, gomock.Any()).Return(&vendorDocumentWithBaseURL, nil, nil).MinTimes(1)
		ctx.didResolver.EXPECT().Resolve(clientADID, gomock.Any()).Return(&clientDocumentWithBaseURL, nil, nil).MinTimes(1)
		ctx.didResolver.EXPECT().Resolve(clientBDID, gomock.Any()).Return(&clientDocumentWithBaseURL, nil, nil).MinTimes(1)
		ctx.vdr.EXPECT().ListOwned(gomock.Any()).Return([]did.DID{vendorDID, clientADID, clientBDID}, nil)

		err := ctx.hammer.registerServiceBaseURLs()

		assert.NoError(t, err)

		t.Run("second time list of fixed DIDs is cached (no DID resolving)", func(t *testing.T) {
			ctx.vdr.EXPECT().ListOwned(gomock.Any()).Return([]did.DID{vendorDID, clientADID, clientBDID}, nil)

			err := ctx.hammer.registerServiceBaseURLs()

			assert.NoError(t, err)
		})
	})
	t.Run("to be registered on vendor DID and client DIDs", func(t *testing.T) {
		ctx := newMockContext(t)
		docClientA := clientDocumentWithoutBaseURL
		docClientA.ID = clientADID
		docClientB := clientDocumentWithoutBaseURL
		docClientB.ID = clientBDID

		// Order DIDs such that care organization DID is first, to test ordering
		ctx.vdr.EXPECT().ListOwned(gomock.Any()).Return([]did.DID{clientADID, vendorDID, clientBDID}, nil)
		gomock.InOrder(
			// DID documents are listed first to check if they should be fixed
			ctx.didResolver.EXPECT().Resolve(clientADID, gomock.Any()).Return(&docClientA, nil, nil),
			ctx.didResolver.EXPECT().Resolve(vendorDID, gomock.Any()).Return(&vendorDocumentWithoutBaseURL, nil, nil),
			ctx.didResolver.EXPECT().Resolve(clientBDID, gomock.Any()).Return(&docClientB, nil, nil),

			// Vendor document is fixed first
			ctx.didmanAPI.EXPECT().AddEndpoint(gomock.Any(), vendorDID, resolver.BaseURLServiceType, *expectedBaseURL).Return(nil, nil),

			// Then client A
			ctx.didResolver.EXPECT().Resolve(vendorDID, gomock.Any()).Return(&vendorDocumentWithBaseURL, nil, nil),
			ctx.didmanAPI.EXPECT().AddEndpoint(gomock.Any(), clientADID, resolver.BaseURLServiceType, *serviceRef).Return(nil, nil),

			// Then client B
			ctx.didResolver.EXPECT().Resolve(vendorDID, gomock.Any()).Return(&vendorDocumentWithBaseURL, nil, nil),
			ctx.didmanAPI.EXPECT().AddEndpoint(gomock.Any(), clientBDID, resolver.BaseURLServiceType, *serviceRef).Return(nil, nil),
		)
		service := ctx.hammer
		service.tlsConfig = tlsServer.TLS
		service.tlsConfig.InsecureSkipVerify = true
		service.tlsConfig.Certificates = []tls.Certificate{pki.Certificate()}

		err := service.registerServiceBaseURLs()

		assert.NoError(t, err)
	})
	t.Run("vendor identifier can't be resolved from TLS", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.didResolver.EXPECT().Resolve(vendorDID, gomock.Any()).Return(&vendorDocumentWithoutBaseURL, nil, nil).MinTimes(1)
		ctx.vdr.EXPECT().ListOwned(gomock.Any()).Return([]did.DID{vendorDID}, nil)
		service := ctx.hammer
		service.tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{pki.Certificate()},
		}

		err := service.registerServiceBaseURLs()

		assert.NoError(t, err)
	})
	t.Run("to be registered on client DIDs", func(t *testing.T) {
		// vendor DID document already contains the service, but its care organization DID documents not yet,
		// so they need to be registered.
		ctx := newMockContext(t)
		ctx.didResolver.EXPECT().Resolve(vendorDID, gomock.Any()).Return(&vendorDocumentWithBaseURL, nil, nil).MinTimes(1)
		docClientA := clientDocumentWithoutBaseURL
		docClientA.ID = clientADID
		docClientB := clientDocumentWithoutBaseURL
		docClientB.ID = clientBDID
		ctx.didResolver.EXPECT().Resolve(clientADID, gomock.Any()).Return(&docClientA, nil, nil).MinTimes(1)
		ctx.didResolver.EXPECT().Resolve(clientBDID, gomock.Any()).Return(&docClientB, nil, nil).MinTimes(1)
		// Client C is owned, but not linked to the vendor (via NutsComm service), so do not register the service on that one
		ctx.didResolver.EXPECT().Resolve(clientCDID, gomock.Any()).Return(&did.Document{ID: clientCDID}, nil, nil).MinTimes(1)
		ctx.vdr.EXPECT().ListOwned(gomock.Any()).Return([]did.DID{vendorDID, clientADID, clientBDID, clientCDID}, nil)
		// AddEndpoint is not called for vendor DID (URL already present), but for client DIDs.
		// Not for clientC, since it's not linked to the vendor (doesn't have a NutsComm endpoint).
		ctx.didmanAPI.EXPECT().AddEndpoint(gomock.Any(), clientADID, resolver.BaseURLServiceType, *serviceRef).Return(nil, nil)
		ctx.didmanAPI.EXPECT().AddEndpoint(gomock.Any(), clientBDID, resolver.BaseURLServiceType, *serviceRef).Return(nil, nil)
		service := ctx.hammer
		service.tlsConfig = tlsServer.TLS
		service.tlsConfig.InsecureSkipVerify = true
		service.tlsConfig.Certificates = []tls.Certificate{pki.Certificate()}

		err := service.registerServiceBaseURLs()

		assert.NoError(t, err)
	})
	t.Run("resolve error", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.didResolver.EXPECT().Resolve(vendorDID, gomock.Any()).Return(nil, nil, fmt.Errorf("resolve error"))
		ctx.vdr.EXPECT().ListOwned(gomock.Any()).Return([]did.DID{vendorDID}, nil)
		service := ctx.hammer
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
		ctx := newMockContext(t)
		ctx.vdr.EXPECT().ListOwned(gomock.Any()).DoAndReturn(func(_ context.Context) ([]did.DID, error) {
			fixCalled.Add(1)
			return []did.DID{}, nil
		}).MinTimes(1)
		service := ctx.hammer
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
		service := New(nil, nil)

		err := service.Start()
		require.NoError(t, err)

		err = service.Shutdown()
		require.NoError(t, err)
	})
}

type mockContext struct {
	ctrl        *gomock.Controller
	didmanAPI   *didman.MockDidman
	didResolver *resolver.MockDIDResolver
	hammer      *GoldenHammer
	vdr         *vdr.MockVDR
}

func newMockContext(t *testing.T) mockContext {
	ctrl := gomock.NewController(t)
	mockVdr := vdr.NewMockVDR(ctrl)
	mockDidmanAPI := didman.NewMockDidman(ctrl)
	didResolver := resolver.NewMockDIDResolver(ctrl)
	mockVdr.EXPECT().Resolver().Return(didResolver).AnyTimes()

	return mockContext{
		ctrl:        ctrl,
		didmanAPI:   mockDidmanAPI,
		didResolver: didResolver,
		hammer:      New(mockVdr, mockDidmanAPI),
		vdr:         mockVdr,
	}
}
func TestGoldenHammer_Name(t *testing.T) {
	service := New(nil, nil)

	assert.Equal(t, "GoldenHammer", service.Name())
}

func TestGoldenHammer_Configure(t *testing.T) {
	t.Run("TLS enabled", func(t *testing.T) {
		cfg := core.NewServerConfig()
		cfg.TLS.CertFile = pki.CertificateFile(t)
		cfg.TLS.CertKeyFile = cfg.TLS.CertFile
		cfg.TLS.TrustStoreFile = pki.TruststoreFile(t)
		err := New(nil, nil).Configure(*cfg)
		assert.NoError(t, err)
	})
	t.Run("TLS disabled", func(t *testing.T) {
		err := New(nil, nil).Configure(*core.NewServerConfig())
		assert.NoError(t, err)
	})
}
