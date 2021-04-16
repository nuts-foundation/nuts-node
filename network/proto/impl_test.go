package proto

import (
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/p2p"
	"testing"
	"time"
)

func Test_ProtocolLifecycle(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	instance := NewProtocol()

	publisher := dag.NewMockPublisher(mockCtrl)
	publisher.EXPECT().Subscribe("*", gomock.Any())

	instance.Configure(p2p.NewInterface(), dag.NewMockDAG(mockCtrl), publisher,
		dag.NewMockPayloadStore(mockCtrl), dag.NewMockTransactionSignatureVerifier(mockCtrl), time.Second * 2, "local")
	instance.Start()
	instance.Stop()
}
