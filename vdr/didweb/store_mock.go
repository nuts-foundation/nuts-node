// Code generated by MockGen. DO NOT EDIT.
// Source: vdr/didweb/store.go
//
// Generated by this command:
//
//	mockgen -destination=vdr/didweb/store_mock.go -package=didweb -source=vdr/didweb/store.go
//

// Package didweb is a generated GoMock package.
package didweb

import (
	reflect "reflect"

	ssi "github.com/nuts-foundation/go-did"
	did "github.com/nuts-foundation/go-did/did"
	gomock "go.uber.org/mock/gomock"
)

// Mockstore is a mock of store interface.
type Mockstore struct {
	ctrl     *gomock.Controller
	recorder *MockstoreMockRecorder
}

// MockstoreMockRecorder is the mock recorder for Mockstore.
type MockstoreMockRecorder struct {
	mock *Mockstore
}

// NewMockstore creates a new mock instance.
func NewMockstore(ctrl *gomock.Controller) *Mockstore {
	mock := &Mockstore{ctrl: ctrl}
	mock.recorder = &MockstoreMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *Mockstore) EXPECT() *MockstoreMockRecorder {
	return m.recorder
}

// create mocks base method.
func (m *Mockstore) create(subjectDID did.DID, methods ...did.VerificationMethod) error {
	m.ctrl.T.Helper()
	varargs := []any{subjectDID}
	for _, a := range methods {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "create", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// create indicates an expected call of create.
func (mr *MockstoreMockRecorder) create(subjectDID any, methods ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{subjectDID}, methods...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "create", reflect.TypeOf((*Mockstore)(nil).create), varargs...)
}

// createService mocks base method.
func (m *Mockstore) createService(subjectDID did.DID, service did.Service) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "createService", subjectDID, service)
	ret0, _ := ret[0].(error)
	return ret0
}

// createService indicates an expected call of createService.
func (mr *MockstoreMockRecorder) createService(subjectDID, service any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "createService", reflect.TypeOf((*Mockstore)(nil).createService), subjectDID, service)
}

// deleteService mocks base method.
func (m *Mockstore) deleteService(subjectDID did.DID, id ssi.URI) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "deleteService", subjectDID, id)
	ret0, _ := ret[0].(error)
	return ret0
}

// deleteService indicates an expected call of deleteService.
func (mr *MockstoreMockRecorder) deleteService(subjectDID, id any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "deleteService", reflect.TypeOf((*Mockstore)(nil).deleteService), subjectDID, id)
}

// get mocks base method.
func (m *Mockstore) get(subjectDID did.DID) ([]did.VerificationMethod, []did.Service, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "get", subjectDID)
	ret0, _ := ret[0].([]did.VerificationMethod)
	ret1, _ := ret[1].([]did.Service)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// get indicates an expected call of get.
func (mr *MockstoreMockRecorder) get(subjectDID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "get", reflect.TypeOf((*Mockstore)(nil).get), subjectDID)
}

// list mocks base method.
func (m *Mockstore) list() ([]did.DID, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "list")
	ret0, _ := ret[0].([]did.DID)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// list indicates an expected call of list.
func (mr *MockstoreMockRecorder) list() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "list", reflect.TypeOf((*Mockstore)(nil).list))
}

// updateService mocks base method.
func (m *Mockstore) updateService(subjectDID did.DID, id ssi.URI, service did.Service) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "updateService", subjectDID, id, service)
	ret0, _ := ret[0].(error)
	return ret0
}

// updateService indicates an expected call of updateService.
func (mr *MockstoreMockRecorder) updateService(subjectDID, id, service any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "updateService", reflect.TypeOf((*Mockstore)(nil).updateService), subjectDID, id, service)
}
