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
	"github.com/magiconair/properties/assert"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/network/transport/v1/logic"
	"testing"
)

func TestProtocolV1_Configure(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	underlyingProto := logic.NewMockProtocol(ctrl)
	underlyingProto.EXPECT().Configure(gomock.Any(), gomock.Any(), gomock.Any(), transport.PeerID("peer-id"))

	v1 := New(DefaultConfig(), dag.NewMockDAG(ctrl), dag.NewMockPublisher(ctrl), dag.NewMockPayloadStore(ctrl), dummyDiagnostics).(*protocolV1)
	v1.protocol = underlyingProto

	v1.Configure("peer-id")
}

func TestProtocolV1_Start(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	underlyingProto := logic.NewMockProtocol(ctrl)
	underlyingProto.EXPECT().Start()

	v1 := New(DefaultConfig(), dag.NewMockDAG(ctrl), dag.NewMockPublisher(ctrl), dag.NewMockPayloadStore(ctrl), dummyDiagnostics).(*protocolV1)
	v1.protocol = underlyingProto
	v1.Start()
}

func TestProtocolV1_MethodName(t *testing.T) {
	assert.Equal(t, protocolV1{}.MethodName(), "/transport.Network/Connect")
}

func dummyDiagnostics() transport.Diagnostics {
	return transport.Diagnostics{}
}

func TestProtocolV1_Stop(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	underlyingProto := logic.NewMockProtocol(ctrl)
	underlyingProto.EXPECT().Stop()

	v1 := New(DefaultConfig(), dag.NewMockDAG(ctrl), dag.NewMockPublisher(ctrl), dag.NewMockPayloadStore(ctrl), dummyDiagnostics).(*protocolV1)
	v1.protocol = underlyingProto
	v1.Stop()
}
