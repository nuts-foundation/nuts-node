// Code generated by MockGen. DO NOT EDIT.
// Source: didman/types.go

// Package didman is a generated GoMock package.
package didman

import (
	url "net/url"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	go_did "github.com/nuts-foundation/go-did"
	did "github.com/nuts-foundation/go-did/did"
)

// MockDidman is a mock of Didman interface.
type MockDidman struct {
	ctrl     *gomock.Controller
	recorder *MockDidmanMockRecorder
}

// MockDidmanMockRecorder is the mock recorder for MockDidman.
type MockDidmanMockRecorder struct {
	mock *MockDidman
}

// NewMockDidman creates a new mock instance.
func NewMockDidman(ctrl *gomock.Controller) *MockDidman {
	mock := &MockDidman{ctrl: ctrl}
	mock.recorder = &MockDidmanMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDidman) EXPECT() *MockDidmanMockRecorder {
	return m.recorder
}

// AddCompoundService mocks base method.
func (m *MockDidman) AddCompoundService(id did.DID, serviceType string, references map[string]go_did.URI) (*did.Service, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddCompoundService", id, serviceType, references)
	ret0, _ := ret[0].(*did.Service)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AddCompoundService indicates an expected call of AddCompoundService.
func (mr *MockDidmanMockRecorder) AddCompoundService(id, serviceType, references interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddCompoundService", reflect.TypeOf((*MockDidman)(nil).AddCompoundService), id, serviceType, references)
}

// AddEndpoint mocks base method.
func (m *MockDidman) AddEndpoint(id did.DID, serviceType string, u url.URL) (*did.Service, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddEndpoint", id, serviceType, u)
	ret0, _ := ret[0].(*did.Service)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AddEndpoint indicates an expected call of AddEndpoint.
func (mr *MockDidmanMockRecorder) AddEndpoint(id, serviceType, u interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddEndpoint", reflect.TypeOf((*MockDidman)(nil).AddEndpoint), id, serviceType, u)
}

// DeleteEndpoint mocks base method.
func (m *MockDidman) DeleteEndpointsByType(id did.DID, serviceType string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteEndpointsByType", id, serviceType)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteEndpoint indicates an expected call of DeleteEndpoint.
func (mr *MockDidmanMockRecorder) DeleteEndpoint(id, serviceType interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteEndpointsByType", reflect.TypeOf((*MockDidman)(nil).DeleteEndpointsByType), id, serviceType)
}

// DeleteService mocks base method.
func (m *MockDidman) DeleteService(id go_did.URI) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteService", id)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteService indicates an expected call of DeleteService.
func (mr *MockDidmanMockRecorder) DeleteService(id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteService", reflect.TypeOf((*MockDidman)(nil).DeleteService), id)
}

// GetCompoundServices mocks base method.
func (m *MockDidman) GetCompoundServices(id did.DID) ([]did.Service, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetCompoundServices", id)
	ret0, _ := ret[0].([]did.Service)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetCompoundServices indicates an expected call of GetCompoundServices.
func (mr *MockDidmanMockRecorder) GetCompoundServices(id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetCompoundServices", reflect.TypeOf((*MockDidman)(nil).GetCompoundServices), id)
}

// GetContactInformation mocks base method.
func (m *MockDidman) GetContactInformation(id did.DID) (*ContactInformation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetContactInformation", id)
	ret0, _ := ret[0].(*ContactInformation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetContactInformation indicates an expected call of GetContactInformation.
func (mr *MockDidmanMockRecorder) GetContactInformation(id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetContactInformation", reflect.TypeOf((*MockDidman)(nil).GetContactInformation), id)
}

// UpdateContactInformation mocks base method.
func (m *MockDidman) UpdateContactInformation(id did.DID, information ContactInformation) (*ContactInformation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateContactInformation", id, information)
	ret0, _ := ret[0].(*ContactInformation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateContactInformation indicates an expected call of UpdateContactInformation.
func (mr *MockDidmanMockRecorder) UpdateContactInformation(id, information interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateContactInformation", reflect.TypeOf((*MockDidman)(nil).UpdateContactInformation), id, information)
}
