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
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/network/transport/v1/logic"
	"github.com/nuts-foundation/nuts-node/network/transport/v1/p2p"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestProtocolV1_Configure(t *testing.T) {
	adapterConfig := p2p.AdapterConfig{PeerID: "peer-id"}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	adapter := p2p.NewMockAdapter(ctrl)
	adapter.EXPECT().Configure(adapterConfig)
	underlyingProto := logic.NewMockProtocol(ctrl)
	underlyingProto.EXPECT().Configure(gomock.Any(), gomock.Any(), gomock.Any(), adapterConfig.PeerID)

	v1 := New(DefaultConfig(), adapterConfig, dag.NewMockDAG(ctrl), dag.NewMockPublisher(ctrl), dag.NewMockPayloadStore(ctrl), dummyDiagnostics).(*protocolV1)
	v1.adapter = adapter
	v1.protocol = underlyingProto

	err := v1.Configure()
	assert.NoError(t, err)
}

func TestProtocolV1_Start(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	adapter := p2p.NewMockAdapter(ctrl)
	adapter.EXPECT().Start()
	underlyingProto := logic.NewMockProtocol(ctrl)
	underlyingProto.EXPECT().Start()

	v1 := New(DefaultConfig(), p2p.AdapterConfig{PeerID: "peer-id"}, dag.NewMockDAG(ctrl), dag.NewMockPublisher(ctrl), dag.NewMockPayloadStore(ctrl), dummyDiagnostics).(*protocolV1)
	v1.adapter = adapter
	v1.protocol = underlyingProto
	assert.NoError(t, v1.Start())
}

func dummyDiagnostics() transport.Diagnostics {
	return transport.Diagnostics{}
}

func TestProtocolV1_Stop(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	adapter := p2p.NewMockAdapter(ctrl)
	adapter.EXPECT().Stop()
	underlyingProto := logic.NewMockProtocol(ctrl)
	underlyingProto.EXPECT().Stop()

	v1 := New(DefaultConfig(), p2p.AdapterConfig{PeerID: "peer-id"}, dag.NewMockDAG(ctrl), dag.NewMockPublisher(ctrl), dag.NewMockPayloadStore(ctrl), dummyDiagnostics).(*protocolV1)
	v1.adapter = adapter
	v1.protocol = underlyingProto
	assert.NoError(t, v1.Stop())
}
