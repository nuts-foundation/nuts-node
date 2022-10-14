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
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/core"
	hash2 "github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/transport"
)

// Wrapper implements the ServerInterface for the network API.
type Wrapper struct {
	Service network.Transactions
}

// Preprocess is called just before the API operation itself is invoked.
func (a *Wrapper) Preprocess(operationID string, context echo.Context) {
	context.Set(core.OperationIDContextKey, operationID)
	context.Set(core.ModuleNameContextKey, network.ModuleName)
}

func (a *Wrapper) Routes(router core.EchoRouter) {
	RegisterHandlers(router, a)
}

// ListTransactions lists all transactions
func (a Wrapper) ListTransactions(ctx echo.Context) error {
	transactions, err := a.Service.ListTransactionsInRange(0, dag.MaxLamportClock)
	if err != nil {
		return err
	}
	results := make([]string, len(transactions))
	for i, transaction := range transactions {
		results[i] = string(transaction.Data())
	}
	return ctx.JSON(http.StatusOK, results)
}

// GetTransaction returns a specific transaction
func (a Wrapper) GetTransaction(ctx echo.Context, hashAsString string) error {
	hash, err := parseHash(hashAsString)
	if err != nil {
		return err
	}
	transaction, err := a.Service.GetTransaction(hash)
	if err != nil {
		if errors.Is(err, dag.ErrTransactionNotFound) {
			return core.NotFoundError("transaction not found")
		}
		return err
	}
	ctx.Response().Header().Set(echo.HeaderContentType, "application/jose")
	ctx.Response().WriteHeader(http.StatusOK)
	_, err = ctx.Response().Writer.Write(transaction.Data())
	return err
}

// GetTransactionPayload returns the payload of a specific transaction
func (a Wrapper) GetTransactionPayload(ctx echo.Context, hashAsString string) error {
	hash, err := parseHash(hashAsString)
	if err != nil {
		return err
	}
	data, err := a.Service.GetTransactionPayload(hash)
	if err != nil {
		if errors.Is(err, dag.ErrPayloadNotFound) {
			return core.NotFoundError("transaction or contents not found")
		}
		return err
	}
	ctx.Response().Header().Set(echo.HeaderContentType, "application/octet-stream")
	ctx.Response().WriteHeader(http.StatusOK)
	_, err = ctx.Response().Writer.Write(data)
	return err
}

// GetPeerDiagnostics returns the diagnostics of the node's peers
func (a Wrapper) GetPeerDiagnostics(ctx echo.Context) error {
	diagnostics := a.Service.PeerDiagnostics()
	result := make(map[transport.PeerID]PeerDiagnostics, len(diagnostics))
	for k, v := range diagnostics {
		result[k] = PeerDiagnostics(v)
	}
	return ctx.JSON(http.StatusOK, result)
}

// RenderGraph visualizes the DAG as Graphviz/dot graph
func (a Wrapper) RenderGraph(ctx echo.Context, params RenderGraphParams) error {
	start := toInt(params.Start, 0)
	end := toInt(params.End, dag.MaxLamportClock)
	if start < 0 || end < 1 || start >= end {
		return core.InvalidInputError("invalid range")
	}
	txs, err := a.Service.ListTransactionsInRange(uint32(start), uint32(end))
	if err != nil {
		return err
	}
	visitor := dag.NewDotGraphVisitor(dag.ShowShortRefLabelStyle)
	for _, tx := range txs {
		visitor.Accept(tx)
	}
	ctx.Response().Header().Set(echo.HeaderContentType, "text/vnd.graphviz")
	return ctx.String(http.StatusOK, visitor.Render())
}

func (a Wrapper) ListEvents(ctx echo.Context) error {
	response := make([]EventSubscriber, 0)
	for _, notifier := range a.Service.Subscribers() {
		eventSubscriber := EventSubscriber{
			Name: notifier.Name(),
		}
		events, err := notifier.GetFailedEvents()
		if err != nil {
			return err
		}
		for _, event := range events {
			eventError := event.Error
			eventType := event.Type
			eventSubscriber.Events = append(eventSubscriber.Events, Event{
				Error:       &eventError,
				Hash:        event.Hash.String(),
				Retries:     event.Retries,
				Transaction: event.Transaction.Ref().String(),
				Type:        &eventType,
			})
		}
		response = append(response, eventSubscriber)
	}
	return ctx.JSON(http.StatusOK, response)
}

func toInt(v *int, def int64) int64 {
	if v == nil {
		return def
	}
	return int64(*v)
}

func (a Wrapper) Reprocess(ctx echo.Context, params ReprocessParams) error {
	if params.Type == nil {
		return core.InvalidInputError("missing type")
	}

	a.Service.Reprocess(*params.Type)

	return ctx.NoContent(http.StatusAccepted)
}

func parseHash(hashAsString string) (hash2.SHA256Hash, error) {
	hash, err := hash2.ParseHex(hashAsString)
	if err != nil {
		return hash, core.InvalidInputError("invalid hash: %w", err)
	}
	return hash, err
}
