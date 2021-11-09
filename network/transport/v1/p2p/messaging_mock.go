// Code generated by MockGen. DO NOT EDIT.
// Source: network/transport/v1/p2p/messaging.go

// Package p2p is a generated GoMock package.
package p2p

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	protobuf "github.com/nuts-foundation/nuts-node/network/transport/v1/protobuf"
)

// MockgrpcMessenger is a mock of grpcMessenger interface.
type MockgrpcMessenger struct {
	ctrl     *gomock.Controller
	recorder *MockgrpcMessengerMockRecorder
}

// MockgrpcMessengerMockRecorder is the mock recorder for MockgrpcMessenger.
type MockgrpcMessengerMockRecorder struct {
	mock *MockgrpcMessenger
}

// NewMockgrpcMessenger creates a new mock instance.
func NewMockgrpcMessenger(ctrl *gomock.Controller) *MockgrpcMessenger {
	mock := &MockgrpcMessenger{ctrl: ctrl}
	mock.recorder = &MockgrpcMessengerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockgrpcMessenger) EXPECT() *MockgrpcMessengerMockRecorder {
	return m.recorder
}

// Recv mocks base method.
func (m *MockgrpcMessenger) Recv() (*protobuf.NetworkMessage, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Recv")
	ret0, _ := ret[0].(*protobuf.NetworkMessage)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Recv indicates an expected call of Recv.
func (mr *MockgrpcMessengerMockRecorder) Recv() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Recv", reflect.TypeOf((*MockgrpcMessenger)(nil).Recv))
}

// Send mocks base method.
func (m *MockgrpcMessenger) Send(message *protobuf.NetworkMessage) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Send", message)
	ret0, _ := ret[0].(error)
	return ret0
}

// Send indicates an expected call of Send.
func (mr *MockgrpcMessengerMockRecorder) Send(message interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Send", reflect.TypeOf((*MockgrpcMessenger)(nil).Send), message)
}
