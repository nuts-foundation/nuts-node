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
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/nuts-foundation/nuts-node/network/transport"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
)

// HTTPClient holds the server address and other basic settings for the http client
type HTTPClient struct {
	core.ClientConfig
	TokenGenerator core.AuthorizationTokenGenerator
}

// GetTransactionPayload retrieves the transaction payload for the given transaction. If the transaction or payload is not found
// nil is returned.
func (hb HTTPClient) GetTransactionPayload(transactionRef hash.SHA256Hash) ([]byte, error) {
	ctx := context.Background()

	res, err := hb.client().GetTransactionPayload(ctx, transactionRef.String())
	if err != nil {
		return nil, err
	}
	if res.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if err := core.TestResponseCode(http.StatusOK, res); err != nil {
		return nil, err
	}
	return io.ReadAll(res.Body)
}

// GetTransaction retrieves the transaction for the given reference. If the transaction is not known, an error is returned.
func (hb HTTPClient) GetTransaction(transactionRef hash.SHA256Hash) (dag.Transaction, error) {
	ctx := context.Background()
	res, err := hb.client().GetTransaction(ctx, transactionRef.String())
	if err != nil {
		return nil, err
	}
	return testAndParseTransactionResponse(res)
}

// ListTransactions returns all transactions known to this network instance.
// TODO: This is potentially an expensive operation without pagination
func (hb HTTPClient) ListTransactions(params *ListTransactionsParams) ([]dag.Transaction, error) {
	ctx := context.Background()

	res, err := hb.client().ListTransactions(ctx, params)
	if err != nil {
		return nil, err
	}
	if err := core.TestResponseCode(http.StatusOK, res); err != nil {
		return nil, err
	}
	responseData, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	unparsedTransactions := make([]string, 0)
	if err = json.Unmarshal(responseData, &unparsedTransactions); err != nil {
		return nil, err
	}
	transactions := make([]dag.Transaction, 0)
	for _, unparsedTransaction := range unparsedTransactions {
		transaction, err := dag.ParseTransaction([]byte(unparsedTransaction))
		if err != nil {
			return nil, err
		}
		transactions = append(transactions, transaction)
	}

	return transactions, nil
}

// GetPeerDiagnostics retrieves diagnostic information on the node's peers.
func (hb HTTPClient) GetPeerDiagnostics() (map[transport.PeerID]PeerDiagnostics, error) {
	ctx := context.Background()
	response, err := hb.client().GetPeerDiagnostics(ctx)
	if err != nil {
		return nil, err
	}
	if err := core.TestResponseCode(http.StatusOK, response); err != nil {
		return nil, err
	}
	responseData, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	result := make(map[transport.PeerID]PeerDiagnostics, 0)
	err = json.Unmarshal(responseData, &result)
	return result, err
}

// Reprocess triggers reprocessing of transactions with the given content type
func (hb HTTPClient) Reprocess(contentType string) error {
	ctx := context.Background()
	response, err := hb.client().Reprocess(ctx, &ReprocessParams{Type: &contentType})
	if err != nil {
		return err
	}
	if err = core.TestResponseCode(http.StatusAccepted, response); err != nil {
		return err
	}
	return nil
}

func (hb HTTPClient) client() ClientInterface {
	response, err := NewClientWithResponses(hb.GetAddress(), WithHTTPClient(core.MustCreateHTTPClient(hb.ClientConfig, hb.TokenGenerator)))
	if err != nil {
		panic(err)
	}
	return response
}

func testAndParseTransactionResponse(response *http.Response) (dag.Transaction, error) {
	if response.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if err := core.TestResponseCode(http.StatusOK, response); err != nil {
		return nil, err
	}
	responseData, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	return dag.ParseTransaction(responseData)
}
