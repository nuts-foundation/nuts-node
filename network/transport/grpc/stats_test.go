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

package grpc

import (
	"errors"
	"github.com/magiconair/properties/assert"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
	"go.uber.org/mock/gomock"
	"testing"
)

func Test_NumberOfPeersStatistic(t *testing.T) {
	statistic := numberOfPeersStatistic{numberOfPeers: 10}
	assert.Equal(t, statistic.String(), "10")
	assert.Equal(t, statistic.Result(), 10)
	assert.Equal(t, statistic.Name(), "connected_peers_count")
}

func Test_PeersStatistic(t *testing.T) {
	statistic := peersStatistic{peers: []transport.Peer{
		{ID: "abc", Address: "localhost:8080"},
		{ID: "def", Address: "remote:8081"},
	}}
	assert.Equal(t, statistic.Result(), statistic.peers)
	assert.Equal(t, statistic.String(), "def@remote:8081 abc@localhost:8080")
	assert.Equal(t, statistic.Name(), "connected_peers")
}

func Test_OwnPeerIDStatistic(t *testing.T) {
	statistic := ownPeerIDStatistic{peerID: "bla"}
	assert.Equal(t, statistic.Result(), transport.PeerID("bla"))
	assert.Equal(t, statistic.String(), "bla")
	assert.Equal(t, statistic.Name(), "peer_id")
}

func Test_PrometheusStreamWrapper(t *testing.T) {
	assertCount := func(t *testing.T, counter *prometheus.CounterVec, labels []string, count float64) {
		t.Helper()
		metric := &io_prometheus_client.Metric{}
		_ = counter.WithLabelValues(labels...).Write(metric)
		assert.Equal(t, count, *metric.Counter.Value)
	}

	t.Run("Send", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		stream := NewMockStream(ctrl)
		stream.EXPECT().SendMsg(gomock.Any())
		prot := &TestProtocol{}
		counter := prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "t", Subsystem: "es", Name: "t"}, []string{"version", "type"})
		wrapper := prometheusStreamWrapper{
			stream:              stream,
			protocol:            prot,
			sentMessagesCounter: counter,
		}

		envelope := prot.CreateEnvelope().(*TestMessage)
		_ = wrapper.SendMsg(envelope)

		assertCount(t, counter, []string{"v0", "TestMessage"}, 1)
	})
	t.Run("Receive", func(t *testing.T) {
		t.Run("ok", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			stream := NewMockStream(ctrl)
			stream.EXPECT().RecvMsg(gomock.Any())
			prot := &TestProtocol{}
			counter := prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "t", Subsystem: "es", Name: "t"}, []string{"version", "type"})
			wrapper := prometheusStreamWrapper{
				stream:              stream,
				protocol:            prot,
				recvMessagesCounter: counter,
			}

			envelope := prot.CreateEnvelope().(*TestMessage)
			_ = wrapper.RecvMsg(envelope)

			assertCount(t, counter, []string{"v0", "TestMessage"}, 1)
		})
		t.Run("no count on receive error", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			stream := NewMockStream(ctrl)
			stream.EXPECT().RecvMsg(gomock.Any()).Return(errors.New("failure"))
			prot := &TestProtocol{}
			counter := prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "t", Subsystem: "es", Name: "t"}, []string{"version", "type"})
			wrapper := prometheusStreamWrapper{
				stream:              stream,
				protocol:            prot,
				recvMessagesCounter: counter,
			}

			envelope := prot.CreateEnvelope().(*TestMessage)
			_ = wrapper.RecvMsg(envelope)

			assertCount(t, counter, []string{"v0", "TestMessage"}, 0)
		})
	})

}
