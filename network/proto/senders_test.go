package proto

import (
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/p2p"
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
	mock.EXPECT().Broadcast(gomock.Any())
	sender.broadcastAdvertHashes([]dagBlock{{
		start: time.Now(),
	}})
}

func Test_defaultMessageSender_sendTransactionList(t *testing.T) {
	sender, mock := createMessageSender(t)
	mock.EXPECT().Send(peer, gomock.Any())
	sender.sendTransactionList(peer, nil)
}

func Test_defaultMessageSender_sendTransactionListQuery(t *testing.T) {
	sender, mock := createMessageSender(t)
	mock.EXPECT().Send(peer, gomock.Any())
	sender.sendTransactionListQuery(peer, time.Now())
}

func Test_defaultMessageSender_sendTransactionPayload(t *testing.T) {
	sender, mock := createMessageSender(t)
	mock.EXPECT().Send(peer, gomock.Any())
	sender.sendTransactionPayload(peer, hash.SHA256Sum([]byte{1, 2, 3}), []byte{1, 2, 3})
}

func Test_defaultMessageSender_sendTransactionPayloadQuery(t *testing.T) {
	sender, mock := createMessageSender(t)
	mock.EXPECT().Send(peer, gomock.Any())
	sender.sendTransactionPayloadQuery(peer, hash.SHA256Sum([]byte{1, 2, 3}))
}
