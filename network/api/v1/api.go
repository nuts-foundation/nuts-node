/*
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

package v1

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/network/log"

	"github.com/nuts-foundation/nuts-node/core"
	hash2 "github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/network/dag"
)

var _ StrictServerInterface = (*Wrapper)(nil)

// Wrapper implements the ServerInterface for the network API.
type Wrapper struct {
	Service network.Transactions
}

func (a *Wrapper) Routes(router core.EchoRouter) {
	RegisterHandlers(router, NewStrictHandler(a, []StrictMiddlewareFunc{
		func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
			return func(ctx echo.Context, request interface{}) (response interface{}, err error) {
				ctx.Set(core.OperationIDContextKey, operationID)
				ctx.Set(core.ModuleNameContextKey, network.ModuleName)
				return f(ctx, request)
			}
		},
		func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
			return audit.StrictMiddleware(f, network.ModuleName, operationID)
		},
	}))
}

// ListTransactions lists all transactions
func (a *Wrapper) ListTransactions(_ context.Context, request ListTransactionsRequestObject) (ListTransactionsResponseObject, error) {
	// Parse the start/end params, which have default values
	start := toInt(request.Params.Start, 0)
	end := toInt(request.Params.End, dag.MaxLamportClock)
	if start < 0 || end < 1 || start >= end {
		return nil, core.InvalidInputError("invalid range")
	}

	// List the specified transaction range (if it exists)
	transactions, err := a.Service.ListTransactionsInRange(uint32(start), uint32(end))
	if err != nil {
		return nil, err
	}

	results := make(ListTransactions200JSONResponse, len(transactions))
	for i, transaction := range transactions {
		results[i] = string(transaction.Data())
	}
	return results, nil
}

// GetTransaction returns a specific transaction
func (a *Wrapper) GetTransaction(_ context.Context, request GetTransactionRequestObject) (GetTransactionResponseObject, error) {
	hash, err := parseHash(request.Ref)
	if err != nil {
		return nil, err
	}
	transaction, err := a.Service.GetTransaction(hash)
	if err != nil {
		if errors.Is(err, dag.ErrTransactionNotFound) {
			return nil, core.NotFoundError("transaction not found")
		}
		return nil, err
	}
	return GetTransaction200ApplicationjoseResponse{
		Body:          bytes.NewReader(transaction.Data()),
		ContentLength: int64(len(transaction.Data())),
	}, nil
}

// GetTransactionPayload returns the payload of a specific transaction
func (a *Wrapper) GetTransactionPayload(_ context.Context, request GetTransactionPayloadRequestObject) (GetTransactionPayloadResponseObject, error) {
	hash, err := parseHash(request.Ref)
	if err != nil {
		return nil, err
	}
	data, err := a.Service.GetTransactionPayload(hash)
	if err != nil {
		if errors.Is(err, dag.ErrPayloadNotFound) {
			return nil, core.NotFoundError("transaction or contents not found")
		}
		return nil, err
	}
	return GetTransactionPayload200ApplicationoctetStreamResponse{
		Body:          bytes.NewReader(data),
		ContentLength: int64(len(data)),
	}, nil
}

// GetPeerDiagnostics returns the diagnostics of the node's peers
func (a *Wrapper) GetPeerDiagnostics(_ context.Context, _ GetPeerDiagnosticsRequestObject) (GetPeerDiagnosticsResponseObject, error) {
	diagnostics := a.Service.PeerDiagnostics()
	result := make(GetPeerDiagnostics200JSONResponse, len(diagnostics))
	for k, v := range diagnostics {
		result[k.String()] = PeerDiagnostics(v)
	}
	return result, nil
}

// RenderGraph visualizes the DAG as Graphviz/dot graph
func (a Wrapper) RenderGraph(_ context.Context, request RenderGraphRequestObject) (RenderGraphResponseObject, error) {
	start := toInt(request.Params.Start, 0)
	end := toInt(request.Params.End, dag.MaxLamportClock)
	if start < 0 || end < 1 || start >= end {
		return nil, core.InvalidInputError("invalid range")
	}
	txs, err := a.Service.ListTransactionsInRange(uint32(start), uint32(end))
	if err != nil {
		return nil, err
	}
	visitor := dag.NewDotGraphVisitor(dag.ShowShortRefLabelStyle)
	for _, tx := range txs {
		visitor.Accept(tx)
	}
	data := visitor.Render()
	return RenderGraph200TextvndGraphvizResponse{
		Body:          bytes.NewReader([]byte(data)),
		ContentLength: int64(len(data)),
	}, nil
}

func (a Wrapper) ListEvents(_ context.Context, _ ListEventsRequestObject) (ListEventsResponseObject, error) {
	response := make(ListEvents200JSONResponse, 0)
	for _, notifier := range a.Service.Subscribers() {
		eventSubscriber := EventSubscriber{
			Name: notifier.Name(),
		}
		events, err := notifier.GetFailedEvents()
		if err != nil {
			return nil, err
		}
		for _, event := range events {
			eventError := event.Error
			eventType := event.Type
			eventLatest := event.Latest.Format(time.RFC3339)
			eventSubscriber.Events = append(eventSubscriber.Events, Event{
				Error:                     &eventError,
				Hash:                      event.Hash.String(),
				Retries:                   event.Retries,
				LatestNotificationAttempt: &eventLatest,
				Transaction:               event.Transaction.Ref().String(),
				Type:                      &eventType,
			})
		}
		response = append(response, eventSubscriber)
	}
	return response, nil
}

func toInt(v *int, def int64) int64 {
	if v == nil {
		return def
	}
	return int64(*v)
}

func (a Wrapper) Reprocess(_ context.Context, request ReprocessRequestObject) (ReprocessResponseObject, error) {
	if request.Params.Type == nil {
		return nil, core.InvalidInputError("missing type")
	}

	go func() {
		_, err := a.Service.Reprocess(context.Background(), *request.Params.Type)
		if err != nil {
			log.Logger().Error(err)
		}
	}()

	return Reprocess202Response{}, nil
}

func parseHash(hashAsString string) (hash2.SHA256Hash, error) {
	hash, err := hash2.ParseHex(hashAsString)
	if err != nil {
		return hash, core.InvalidInputError("invalid hash: %w", err)
	}
	return hash, err
}
