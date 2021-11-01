// Code generated by MockGen. DO NOT EDIT.
// Source: network/transport/v1/p2p/interface.go

// Package p2p is a generated GoMock package.
package p2p

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	core "github.com/nuts-foundation/nuts-node/core"
	transport "github.com/nuts-foundation/nuts-node/network/transport"
	grpc "github.com/nuts-foundation/nuts-node/network/transport/grpc"
	protobuf "github.com/nuts-foundation/nuts-node/network/transport/v1/protobuf"
	grpc0 "google.golang.org/grpc"
)

// MockAdapter is a mock of Adapter interface.
type MockAdapter struct {
	ctrl     *gomock.Controller
	recorder *MockAdapterMockRecorder
}

// MockAdapterMockRecorder is the mock recorder for MockAdapter.
type MockAdapterMockRecorder struct {
	mock *MockAdapter
}

// NewMockAdapter creates a new mock instance.
func NewMockAdapter(ctrl *gomock.Controller) *MockAdapter {
	mock := &MockAdapter{ctrl: ctrl}
	mock.recorder = &MockAdapterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAdapter) EXPECT() *MockAdapterMockRecorder {
	return m.recorder
}

// Broadcast mocks base method.
func (m *MockAdapter) Broadcast(message *protobuf.NetworkMessage) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Broadcast", message)
}

// Broadcast indicates an expected call of Broadcast.
func (mr *MockAdapterMockRecorder) Broadcast(message interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Broadcast", reflect.TypeOf((*MockAdapter)(nil).Broadcast), message)
}

// Configure mocks base method.
func (m *MockAdapter) Configure(config AdapterConfig) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Configure", config)
	ret0, _ := ret[0].(error)
	return ret0
}

// Configure indicates an expected call of Configure.
func (mr *MockAdapterMockRecorder) Configure(config interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Configure", reflect.TypeOf((*MockAdapter)(nil).Configure), config)
}

// ConnectToPeer mocks base method.
func (m *MockAdapter) ConnectToPeer(address string) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ConnectToPeer", address)
	ret0, _ := ret[0].(bool)
	return ret0
}

// ConnectToPeer indicates an expected call of ConnectToPeer.
func (mr *MockAdapterMockRecorder) ConnectToPeer(address interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ConnectToPeer", reflect.TypeOf((*MockAdapter)(nil).ConnectToPeer), address)
}

// Diagnostics mocks base method.
func (m *MockAdapter) Diagnostics() []core.DiagnosticResult {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Diagnostics")
	ret0, _ := ret[0].([]core.DiagnosticResult)
	return ret0
}

// Diagnostics indicates an expected call of Diagnostics.
func (mr *MockAdapterMockRecorder) Diagnostics() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Diagnostics", reflect.TypeOf((*MockAdapter)(nil).Diagnostics))
}

// EventChannels mocks base method.
func (m *MockAdapter) EventChannels() (chan transport.Peer, chan transport.Peer) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "EventChannels")
	ret0, _ := ret[0].(chan transport.Peer)
	ret1, _ := ret[1].(chan transport.Peer)
	return ret0, ret1
}

// EventChannels indicates an expected call of EventChannels.
func (mr *MockAdapterMockRecorder) EventChannels() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "EventChannels", reflect.TypeOf((*MockAdapter)(nil).EventChannels))
}

// Peers mocks base method.
func (m *MockAdapter) Peers() []transport.Peer {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Peers")
	ret0, _ := ret[0].([]transport.Peer)
	return ret0
}

// Peers indicates an expected call of Peers.
func (mr *MockAdapterMockRecorder) Peers() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Peers", reflect.TypeOf((*MockAdapter)(nil).Peers))
}

// ReceivedMessages mocks base method.
func (m *MockAdapter) ReceivedMessages() MessageQueue {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ReceivedMessages")
	ret0, _ := ret[0].(MessageQueue)
	return ret0
}

// ReceivedMessages indicates an expected call of ReceivedMessages.
func (mr *MockAdapterMockRecorder) ReceivedMessages() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReceivedMessages", reflect.TypeOf((*MockAdapter)(nil).ReceivedMessages))
}

// RegisterService mocks base method.
func (m *MockAdapter) RegisterService(registrar grpc0.ServiceRegistrar, acceptorCallback grpc.StreamAcceptor) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "RegisterService", registrar, acceptorCallback)
}

// RegisterService indicates an expected call of RegisterService.
func (mr *MockAdapterMockRecorder) RegisterService(registrar, acceptorCallback interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RegisterService", reflect.TypeOf((*MockAdapter)(nil).RegisterService), registrar, acceptorCallback)
}

// Send mocks base method.
func (m *MockAdapter) Send(peer transport.PeerID, message *protobuf.NetworkMessage) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Send", peer, message)
	ret0, _ := ret[0].(error)
	return ret0
}

// Send indicates an expected call of Send.
func (mr *MockAdapterMockRecorder) Send(peer, message interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Send", reflect.TypeOf((*MockAdapter)(nil).Send), peer, message)
}

// Start mocks base method.
func (m *MockAdapter) Start() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Start")
	ret0, _ := ret[0].(error)
	return ret0
}

// Start indicates an expected call of Start.
func (mr *MockAdapterMockRecorder) Start() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Start", reflect.TypeOf((*MockAdapter)(nil).Start))
}

// Stop mocks base method.
func (m *MockAdapter) Stop() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Stop")
	ret0, _ := ret[0].(error)
	return ret0
}

// Stop indicates an expected call of Stop.
func (mr *MockAdapterMockRecorder) Stop() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Stop", reflect.TypeOf((*MockAdapter)(nil).Stop))
}

// MockMessageQueue is a mock of MessageQueue interface.
type MockMessageQueue struct {
	ctrl     *gomock.Controller
	recorder *MockMessageQueueMockRecorder
}

// MockMessageQueueMockRecorder is the mock recorder for MockMessageQueue.
type MockMessageQueueMockRecorder struct {
	mock *MockMessageQueue
}

// NewMockMessageQueue creates a new mock instance.
func NewMockMessageQueue(ctrl *gomock.Controller) *MockMessageQueue {
	mock := &MockMessageQueue{ctrl: ctrl}
	mock.recorder = &MockMessageQueueMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockMessageQueue) EXPECT() *MockMessageQueueMockRecorder {
	return m.recorder
}

// Get mocks base method.
func (m *MockMessageQueue) Get() PeerMessage {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get")
	ret0, _ := ret[0].(PeerMessage)
	return ret0
}

// Get indicates an expected call of Get.
func (mr *MockMessageQueueMockRecorder) Get() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockMessageQueue)(nil).Get))
}
