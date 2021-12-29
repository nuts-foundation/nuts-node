// Code generated by MockGen. DO NOT EDIT.
// Source: network/transport/v2/retry.go

// Package v2 is a generated GoMock package.
package v2

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	hash "github.com/nuts-foundation/nuts-node/crypto/hash"
)

// MockRetriable is a mock of Retriable interface.
type MockRetriable struct {
	ctrl     *gomock.Controller
	recorder *MockRetriableMockRecorder
}

// MockRetriableMockRecorder is the mock recorder for MockRetriable.
type MockRetriableMockRecorder struct {
	mock *MockRetriable
}

// NewMockRetriable creates a new mock instance.
func NewMockRetriable(ctrl *gomock.Controller) *MockRetriable {
	mock := &MockRetriable{ctrl: ctrl}
	mock.recorder = &MockRetriableMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRetriable) EXPECT() *MockRetriableMockRecorder {
	return m.recorder
}

// Add mocks base method.
func (m *MockRetriable) Add(hash hash.SHA256Hash) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Add", hash)
	ret0, _ := ret[0].(error)
	return ret0
}

// Add indicates an expected call of Add.
func (mr *MockRetriableMockRecorder) Add(hash interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Add", reflect.TypeOf((*MockRetriable)(nil).Add), hash)
}

// Close mocks base method.
func (m *MockRetriable) Close() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Close")
	ret0, _ := ret[0].(error)
	return ret0
}

// Close indicates an expected call of Close.
func (mr *MockRetriableMockRecorder) Close() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*MockRetriable)(nil).Close))
}

// Configure mocks base method.
func (m *MockRetriable) Configure() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Configure")
	ret0, _ := ret[0].(error)
	return ret0
}

// Configure indicates an expected call of Configure.
func (mr *MockRetriableMockRecorder) Configure() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Configure", reflect.TypeOf((*MockRetriable)(nil).Configure))
}

// Remove mocks base method.
func (m *MockRetriable) Remove(hash hash.SHA256Hash) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Remove", hash)
	ret0, _ := ret[0].(error)
	return ret0
}

// Remove indicates an expected call of Remove.
func (mr *MockRetriableMockRecorder) Remove(hash interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Remove", reflect.TypeOf((*MockRetriable)(nil).Remove), hash)
}

// Start mocks base method.
func (m *MockRetriable) Start() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Start")
	ret0, _ := ret[0].(error)
	return ret0
}

// Start indicates an expected call of Start.
func (mr *MockRetriableMockRecorder) Start() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Start", reflect.TypeOf((*MockRetriable)(nil).Start))
}
