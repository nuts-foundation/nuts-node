/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
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

package vcr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/audit"
	types2 "github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/crypto/util"
	"github.com/nuts-foundation/nuts-node/events"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/types"
	"github.com/nuts-foundation/nuts-node/vcr/verifier"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestNewAmbassador(t *testing.T) {
	a := NewAmbassador(nil, nil, nil, nil)

	assert.NotNil(t, a)
}

func TestAmbassador_Configure(t *testing.T) {
	t.Run("calls network.subscribe", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		nMock := network.NewMockTransactions(ctrl)

		a := NewAmbassador(nMock, nil, nil, nil)
		nMock.EXPECT().WithPersistency().Times(2)
		nMock.EXPECT().Subscribe("vcr_vcs", gomock.Any(), gomock.Any())
		nMock.EXPECT().Subscribe("vcr_revocations", gomock.Any(), gomock.Any())

		a.Configure()
	})
}

func TestAmbassador_Start(t *testing.T) {
	t.Run("error on stream subscription", func(t *testing.T) {
		ctx := newMockContext(t)
		mockEvent := events.NewMockEvent(ctx.ctrl)
		ctx.vcr.ambassador.(*ambassador).eventManager = mockEvent
		mockPool := events.NewMockConnectionPool(ctx.ctrl)
		mockConnection := events.NewMockConn(ctx.ctrl)
		mockEvent.EXPECT().Pool().Return(mockPool)
		mockPool.EXPECT().Acquire(gomock.Any()).Return(mockConnection, nil, nil)
		mockConnection.EXPECT().JetStream().Return(nil, errors.New("b00m!"))

		err := ctx.vcr.ambassador.Start()

		assert.EqualError(t, err, "failed to subscribe to REPROCESS event stream: b00m!")
	})

	t.Run("error on nats connection acquire", func(t *testing.T) {
		ctx := newMockContext(t)
		mockEvent := events.NewMockEvent(ctx.ctrl)
		ctx.vcr.ambassador.(*ambassador).eventManager = mockEvent
		mockPool := events.NewMockConnectionPool(ctx.ctrl)
		mockEvent.EXPECT().Pool().Return(mockPool)
		mockPool.EXPECT().Acquire(gomock.Any()).Return(nil, nil, errors.New("b00m!"))

		err := ctx.vcr.ambassador.Start()

		assert.EqualError(t, err, "failed to subscribe to REPROCESS event stream: b00m!")
	})
}

func TestAmbassador_handleReprocessEvent(t *testing.T) {
	ctx := newMockContext(t)
	mockWriter := types.NewMockWriter(ctx.ctrl)
	ctx.vcr.ambassador.(*ambassador).writer = mockWriter

	// load VC
	vc := vc.VerifiableCredential{}
	vcJSON, _ := os.ReadFile("test/vc.json")
	json.Unmarshal(vcJSON, &vc)

	// load key
	pem, _ := os.ReadFile("test/private.pem")
	signer, _ := util.PemToPrivateKey(pem)
	key := crypto.NewTestKey(fmt.Sprintf("%s#1", vc.Issuer.String()))

	// trust otherwise Resolve won't work
	ctx.vcr.Trust(vc.Type[0], vc.Issuer)
	ctx.vcr.Trust(vc.Type[1], vc.Issuer)

	// mocks
	ctx.keyResolver.EXPECT().ResolveKeyByID(gomock.Any(), gomock.Any(), types2.NutsSigningKeyType).Return(signer.Public(), nil)

	// Publish a VC
	payload, _ := json.Marshal(vc)
	unsignedTransaction, _ := dag.NewTransaction(hash.SHA256Sum(payload), types.VcDocumentType, nil, nil, uint32(0))
	signedTransaction, err := dag.NewTransactionSigner(ctx.crypto, key, true).Sign(audit.TestContext(), unsignedTransaction, time.Now())
	require.NoError(t, err)
	twp := events.TransactionWithPayload{
		Transaction: signedTransaction,
		Payload:     payload,
	}
	twpBytes, _ := json.Marshal(twp)

	_, js, _ := ctx.vcr.eventManager.Pool().Acquire(context.Background())
	_, err = js.Publish("REPROCESS.application/vc+json", twpBytes)

	require.NoError(t, err)

	test.WaitFor(t, func() (bool, error) {
		_, err := ctx.vcr.Resolve(*vc.ID, nil)
		return err == nil, nil
	}, time.Second, "timeout while waiting for event to be processed")
}

func TestAmbassador_vcCallback(t *testing.T) {
	payload := []byte(jsonld.TestCredential)
	tx, _ := dag.NewTransaction(hash.EmptyHash(), types.VcDocumentType, nil, nil, 0)
	stx := tx.(dag.Transaction)
	validAt := stx.SigningTime()

	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		wMock := types.NewMockWriter(ctrl)

		target := vc.VerifiableCredential{}
		a := NewAmbassador(nil, wMock, nil, nil).(*ambassador)
		wMock.EXPECT().StoreCredential(gomock.Any(), &validAt).DoAndReturn(func(f interface{}, g interface{}) error {
			target = f.(vc.VerifiableCredential)
			return nil
		})

		err := a.vcCallback(stx, payload)

		require.NoError(t, err)

		assert.Equal(t, "did:nuts:B8PUHs2AUHbFF1xLLK4eZjgErEcMXHxs68FteY7NDtCY#123", target.ID.String())
	})

	t.Run("error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		wMock := types.NewMockWriter(ctrl)

		a := NewAmbassador(nil, wMock, nil, nil).(*ambassador)
		wMock.EXPECT().StoreCredential(gomock.Any(), &validAt).Return(errors.New("b00m!"))

		err := a.vcCallback(stx, payload)

		assert.Error(t, err)
	})

	t.Run("error - invalid payload", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		wMock := types.NewMockWriter(ctrl)

		a := NewAmbassador(nil, wMock, nil, nil).(*ambassador)

		err := a.vcCallback(stx, []byte("{"))

		assert.Error(t, err)
	})
}

func TestAmbassador_handleNetworkVCs(t *testing.T) {
	tx, _ := dag.NewTransaction(hash.EmptyHash(), types.VcDocumentType, nil, nil, 0)
	stx := tx.(dag.Transaction)

	t.Run("non-recoverable errors", func(t *testing.T) {
		t.Run("invalid payload is dag.EventFatal", func(t *testing.T) {
			a := NewAmbassador(nil, nil, nil, nil).(*ambassador)

			value, err := a.handleNetworkVCs(dag.Event{
				Transaction: stx,
				Payload:     []byte("{"),
			})

			assert.False(t, value)
			assert.True(t, errors.As(err, new(dag.EventFatal)))
		})
		t.Run("invalid remote JSON-LD URL (disallowed URL)", func(t *testing.T) {
			// Use JSON-LD processor to get actual returned error
			proc := ld.NewJsonLdProcessor()
			var target map[string]interface{}
			err := json.Unmarshal([]byte(jsonld.TestCredential), &target)
			require.NoError(t, err)
			opts := ld.NewJsonLdOptions("")
			opts.DocumentLoader = jsonld.NewFilteredLoader(nil, nil)
			result, err := proc.Expand(target, opts)
			require.Empty(t, result)
			require.Error(t, err)

			ctrl := gomock.NewController(t)
			wMock := types.NewMockWriter(ctrl)

			a := NewAmbassador(nil, wMock, nil, nil).(*ambassador)
			wMock.EXPECT().StoreCredential(gomock.Any(), gomock.Any()).Return(err)

			value, err := a.handleNetworkVCs(dag.Event{
				Transaction: stx,
				Payload:     []byte(jsonld.TestCredential),
			})

			assert.False(t, value)
			assert.True(t, errors.As(err, new(dag.EventFatal)))
		})
	})
	t.Run("recoverable errors", func(t *testing.T) {
		t.Run("context.Canceled", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			wMock := types.NewMockWriter(ctrl)

			a := NewAmbassador(nil, wMock, nil, nil).(*ambassador)
			wMock.EXPECT().StoreCredential(gomock.Any(), gomock.Any()).Return(context.Canceled)

			value, err := a.handleNetworkVCs(dag.Event{
				Transaction: stx,
				Payload:     []byte(jsonld.TestCredential),
			})

			assert.False(t, value)
			assert.False(t, errors.As(err, new(dag.EventFatal)))
		})
		t.Run("context.DeadlineExceeded", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			wMock := types.NewMockWriter(ctrl)

			a := NewAmbassador(nil, wMock, nil, nil).(*ambassador)
			wMock.EXPECT().StoreCredential(gomock.Any(), gomock.Any()).Return(context.DeadlineExceeded)

			value, err := a.handleNetworkVCs(dag.Event{
				Transaction: stx,
				Payload:     []byte(jsonld.TestCredential),
			})

			assert.False(t, value)
			assert.False(t, errors.As(err, new(dag.EventFatal)))
		})
		t.Run("error loading remote JSON-LD URL", func(t *testing.T) {
			// Use JSON-LD processor to get actual returned error
			proc := ld.NewJsonLdProcessor()
			var target map[string]interface{}
			err := json.Unmarshal([]byte(jsonld.TestCredential), &target)
			require.NoError(t, err)
			opts := ld.NewJsonLdOptions("")
			opts.DocumentLoader = ld.NewDefaultDocumentLoader(&http.Client{Transport: &stubRoundTripper{}})
			result, err := proc.Expand(target, opts)
			require.Empty(t, result)
			require.Error(t, err)

			ctrl := gomock.NewController(t)
			wMock := types.NewMockWriter(ctrl)

			a := NewAmbassador(nil, wMock, nil, nil).(*ambassador)
			wMock.EXPECT().StoreCredential(gomock.Any(), gomock.Any()).Return(err)

			value, err := a.handleNetworkVCs(dag.Event{
				Transaction: stx,
				Payload:     []byte(jsonld.TestCredential),
			})

			assert.False(t, value)
			assert.False(t, errors.As(err, new(dag.EventFatal)), "error loading remote JSON-LD URL should not be fatal: %v", err)
		})
	})
}

func Test_ambassador_handleNetworkRevocations(t *testing.T) {
	payload, _ := os.ReadFile("test/ld-revocation.json")
	tx, _ := dag.NewTransaction(hash.EmptyHash(), types.RevocationLDDocumentType, nil, nil, 0)
	stx := tx.(dag.Transaction)

	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		revocation := credential.Revocation{}
		assert.NoError(t, json.Unmarshal(payload, &revocation))

		mockVerifier := verifier.NewMockVerifier(ctrl)
		mockVerifier.EXPECT().RegisterRevocation(revocation)
		a := NewAmbassador(nil, nil, mockVerifier, nil).(*ambassador)

		value, err := a.handleNetworkRevocations(dag.Event{
			Transaction: stx,
			Payload:     payload,
		})
		assert.True(t, value)
		assert.NoError(t, err)
	})

	t.Run("error - invalid payload", func(t *testing.T) {
		a := NewAmbassador(nil, nil, nil, nil).(*ambassador)

		//err := a.jsonLDRevocationCallback(stx, []byte("b00m"))
		value, err := a.handleNetworkRevocations(dag.Event{
			Transaction: stx,
			Payload:     []byte("b00m"),
		})
		assert.False(t, value)
		assert.EqualError(t, err, "revocation processing failed: invalid character 'b' looking for beginning of value")
		assert.True(t, errors.As(err, new(dag.EventFatal)))
	})

	t.Run("error - storing fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		mockVerifier := verifier.NewMockVerifier(ctrl)
		mockVerifier.EXPECT().RegisterRevocation(gomock.Any()).Return(errors.New("foo"))
		a := NewAmbassador(nil, nil, mockVerifier, nil).(*ambassador)

		value, err := a.handleNetworkRevocations(dag.Event{
			Transaction: stx,
			Payload:     payload,
		})
		assert.False(t, value)
		assert.EqualError(t, err, "foo")
		assert.True(t, errors.As(err, new(dag.EventFatal)))
	})

	t.Run("error - cantext error is not fatal", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		mockVerifier := verifier.NewMockVerifier(ctrl)
		mockVerifier.EXPECT().RegisterRevocation(gomock.Any()).Return(context.Canceled)
		a := NewAmbassador(nil, nil, mockVerifier, nil).(*ambassador)

		value, err := a.handleNetworkRevocations(dag.Event{
			Transaction: stx,
			Payload:     payload,
		})
		assert.False(t, value)
		assert.False(t, errors.As(err, new(dag.EventFatal)))
	})
}

type stubRoundTripper struct{}

func (s stubRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusNotFound}, nil
}
