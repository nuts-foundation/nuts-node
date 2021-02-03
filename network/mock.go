// Code generated by MockGen. DO NOT EDIT.
// Source: network/interface.go

// Package network is a generated GoMock package.
package network

import (
	gomock "github.com/golang/mock/gomock"
	hash "github.com/nuts-foundation/nuts-node/crypto/hash"
	dag "github.com/nuts-foundation/nuts-node/network/dag"
	reflect "reflect"
	time "time"
)

// MockNetwork is a mock of Network interface
type MockNetwork struct {
	ctrl     *gomock.Controller
	recorder *MockNetworkMockRecorder
}

// MockNetworkMockRecorder is the mock recorder for MockNetwork
type MockNetworkMockRecorder struct {
	mock *MockNetwork
}

// NewMockNetwork creates a new mock instance
func NewMockNetwork(ctrl *gomock.Controller) *MockNetwork {
	mock := &MockNetwork{ctrl: ctrl}
	mock.recorder = &MockNetworkMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockNetwork) EXPECT() *MockNetworkMockRecorder {
	return m.recorder
}

// Subscribe mocks base method
func (m *MockNetwork) Subscribe(documentType string, receiver dag.Receiver) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Subscribe", documentType, receiver)
}

// Subscribe indicates an expected call of Subscribe
func (mr *MockNetworkMockRecorder) Subscribe(documentType, receiver interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Subscribe", reflect.TypeOf((*MockNetwork)(nil).Subscribe), documentType, receiver)
}

// GetDocumentPayload mocks base method
func (m *MockNetwork) GetDocumentPayload(documentRef hash.SHA256Hash) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetDocumentPayload", documentRef)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetDocumentPayload indicates an expected call of GetDocumentPayload
func (mr *MockNetworkMockRecorder) GetDocumentPayload(documentRef interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetDocumentPayload", reflect.TypeOf((*MockNetwork)(nil).GetDocumentPayload), documentRef)
}

// GetDocument mocks base method
func (m *MockNetwork) GetDocument(documentRef hash.SHA256Hash) (dag.Document, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetDocument", documentRef)
	ret0, _ := ret[0].(dag.Document)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetDocument indicates an expected call of GetDocument
func (mr *MockNetworkMockRecorder) GetDocument(documentRef interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetDocument", reflect.TypeOf((*MockNetwork)(nil).GetDocument), documentRef)
}

// CreateDocument mocks base method
func (m *MockNetwork) CreateDocument(payloadType string, payload []byte, signingKeyID string, attachKey bool, timestamp time.Time, fieldsOpts ...dag.FieldOpt) (dag.Document, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{payloadType, payload, signingKeyID, attachKey, timestamp}
	for _, a := range fieldsOpts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "CreateDocument", varargs...)
	ret0, _ := ret[0].(dag.Document)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateDocument indicates an expected call of CreateDocument
func (mr *MockNetworkMockRecorder) CreateDocument(payloadType, payload, signingKeyID, attachKey, timestamp interface{}, fieldsOpts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{payloadType, payload, signingKeyID, attachKey, timestamp}, fieldsOpts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateDocument", reflect.TypeOf((*MockNetwork)(nil).CreateDocument), varargs...)
}

// ListDocuments mocks base method
func (m *MockNetwork) ListDocuments() ([]dag.Document, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListDocuments")
	ret0, _ := ret[0].([]dag.Document)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListDocuments indicates an expected call of ListDocuments
func (mr *MockNetworkMockRecorder) ListDocuments() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListDocuments", reflect.TypeOf((*MockNetwork)(nil).ListDocuments))
}

// Walk mocks base method
func (m *MockNetwork) Walk(walker dag.WalkerAlgorithm, visitor dag.Visitor, startAt hash.SHA256Hash) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Walk", walker, visitor, startAt)
	ret0, _ := ret[0].(error)
	return ret0
}

// Walk indicates an expected call of Walk
func (mr *MockNetworkMockRecorder) Walk(walker, visitor, startAt interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Walk", reflect.TypeOf((*MockNetwork)(nil).Walk), walker, visitor, startAt)
}
