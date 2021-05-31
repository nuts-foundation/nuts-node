package proto

import (
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/p2p"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"testing"
	"time"
)

func createMessageSender(t *testing.T) (defaultMessageSender, *p2p.MockAdapter) {
	ctrl := gomock.NewController(t)
	t.Cleanup(func() {
		ctrl.Finish()
	})
	p2pInterface := p2p.NewMockAdapter(ctrl)
	sender := defaultMessageSender{p2p: p2pInterface}
	return sender, p2pInterface
}

func Test_defaultMessageSender_broadcastAdvertHashes(t *testing.T) {
	sender, mock := createMessageSender(t)
	now := time.Now()
	hash1 := hash.SHA256Sum([]byte{1})
	mock.EXPECT().Broadcast(&transport.NetworkMessage{Message: &transport.NetworkMessage_AdvertHashes{AdvertHashes: &transport.AdvertHashes{
		CurrentBlockDate: uint32(now.Unix()),
		Blocks:           []*transport.BlockHashes{{Hashes: [][]byte{hash1.Slice()}}},
		HistoricHash:     hash.EmptyHash().Slice(),
	}}})
	sender.broadcastAdvertHashes([]dagBlock{
		{start: time.Time{}},
		{start: now, heads: []hash.SHA256Hash{hash1}},
	},
	)
}

func Test_defaultMessageSender_broadcastDiagnostics(t *testing.T) {
	sender, mock := createMessageSender(t)
	mock.EXPECT().Broadcast(&transport.NetworkMessage{Message: &transport.NetworkMessage_DiagnosticsBroadcast{DiagnosticsBroadcast: &transport.Diagnostics{
		Uptime:               1000,
		Peers:                []string{"foobar"},
		NumberOfTransactions: 5,
		Version:              "1.0",
		Vendor:               "Test",
	}}})
	sender.broadcastDiagnostics(Diagnostics{
		Uptime:               1000 * time.Second,
		Peers:                []p2p.PeerID{"foobar"},
		NumberOfTransactions: 5,
		Version:              "1.0",
		Vendor:               "Test",
	})
}

func Test_defaultMessageSender_sendTransactionList(t *testing.T) {
	sender, mock := createMessageSender(t)
	blockDate := time.Date(2021, 4, 29, 0, 0, 0, 0, time.UTC)
	tx := testTX{data: []byte{1, 2, 3}}
	mock.EXPECT().Send(peer, &transport.NetworkMessage{Message: &transport.NetworkMessage_TransactionList{TransactionList: &transport.TransactionList{
		BlockDate: uint32(blockDate.Unix()),
		Transactions: []*transport.Transaction{{
			Hash: tx.Ref().Slice(),
			Data: tx.data,
		}},
	}}})
	sender.sendTransactionList(peer, []dag.Transaction{tx}, blockDate)
}

func Test_defaultMessageSender_sendTransactionListQuery(t *testing.T) {
	t.Run("block date is set", func(t *testing.T) {
		sender, mock := createMessageSender(t)
		moment := time.Now()
		mock.EXPECT().Send(peer, &transport.NetworkMessage{Message: &transport.NetworkMessage_TransactionListQuery{TransactionListQuery: &transport.TransactionListQuery{BlockDate: uint32(moment.Unix())}}})
		sender.sendTransactionListQuery(peer, moment)
	})
	t.Run("block date is zero", func(t *testing.T) {
		sender, mock := createMessageSender(t)
		mock.EXPECT().Send(peer, &transport.NetworkMessage{Message: &transport.NetworkMessage_TransactionListQuery{TransactionListQuery: &transport.TransactionListQuery{BlockDate: 0}}})
		sender.sendTransactionListQuery(peer, time.Time{})
	})
}

func Test_defaultMessageSender_sendTransactionPayload(t *testing.T) {
	sender, mock := createMessageSender(t)
	payload := []byte{1, 2, 3}
	payloadHash := hash.SHA256Sum(payload)
	mock.EXPECT().Send(peer, &transport.NetworkMessage{Message: &transport.NetworkMessage_TransactionPayload{TransactionPayload: &transport.TransactionPayload{
		PayloadHash: payloadHash.Slice(),
		Data:        payload,
	}}})
	sender.sendTransactionPayload(peer, payloadHash, payload)
}

func Test_defaultMessageSender_sendTransactionPayloadQuery(t *testing.T) {
	sender, mock := createMessageSender(t)
	payloadHash := hash.SHA256Sum([]byte{1, 2, 3})
	mock.EXPECT().Send(peer, &transport.NetworkMessage{Message: &transport.NetworkMessage_TransactionPayloadQuery{TransactionPayloadQuery: &transport.TransactionPayloadQuery{PayloadHash: payloadHash.Slice()}}})
	sender.sendTransactionPayloadQuery(peer, payloadHash)
}
