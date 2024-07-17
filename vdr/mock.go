// Code generated by MockGen. DO NOT EDIT.
// Source: vdr/interface.go
//
// Generated by this command:
//
//	mockgen -destination=vdr/mock.go -package=vdr -source=vdr/interface.go
//

// Package vdr is a generated GoMock package.
package vdr

import (
	reflect "reflect"

	did "github.com/nuts-foundation/go-did/did"
	didsubject "github.com/nuts-foundation/nuts-node/vdr/didsubject"
	resolver "github.com/nuts-foundation/nuts-node/vdr/resolver"
	gomock "go.uber.org/mock/gomock"
)

// MockVDR is a mock of VDR interface.
type MockVDR struct {
	ctrl     *gomock.Controller
	recorder *MockVDRMockRecorder
}

// MockVDRMockRecorder is the mock recorder for MockVDR.
type MockVDRMockRecorder struct {
	mock *MockVDR
}

// NewMockVDR creates a new mock instance.
func NewMockVDR(ctrl *gomock.Controller) *MockVDR {
	mock := &MockVDR{ctrl: ctrl}
	mock.recorder = &MockVDRMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockVDR) EXPECT() *MockVDRMockRecorder {
	return m.recorder
}

// ConflictedDocuments mocks base method.
func (m *MockVDR) ConflictedDocuments() ([]did.Document, []resolver.DocumentMetadata, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ConflictedDocuments")
	ret0, _ := ret[0].([]did.Document)
	ret1, _ := ret[1].([]resolver.DocumentMetadata)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// ConflictedDocuments indicates an expected call of ConflictedDocuments.
func (mr *MockVDRMockRecorder) ConflictedDocuments() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ConflictedDocuments", reflect.TypeOf((*MockVDR)(nil).ConflictedDocuments))
}

// DocumentOwner mocks base method.
func (m *MockVDR) DocumentOwner() didsubject.DocumentOwner {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DocumentOwner")
	ret0, _ := ret[0].(didsubject.DocumentOwner)
	return ret0
}

// DocumentOwner indicates an expected call of DocumentOwner.
func (mr *MockVDRMockRecorder) DocumentOwner() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DocumentOwner", reflect.TypeOf((*MockVDR)(nil).DocumentOwner))
}

// NutsDocumentManager mocks base method.
func (m *MockVDR) NutsDocumentManager() didsubject.DocumentManager {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NutsDocumentManager")
	ret0, _ := ret[0].(didsubject.DocumentManager)
	return ret0
}

// NutsDocumentManager indicates an expected call of NutsDocumentManager.
func (mr *MockVDRMockRecorder) NutsDocumentManager() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NutsDocumentManager", reflect.TypeOf((*MockVDR)(nil).NutsDocumentManager))
}

// ResolveManaged mocks base method.
func (m *MockVDR) ResolveManaged(id did.DID) (*did.Document, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResolveManaged", id)
	ret0, _ := ret[0].(*did.Document)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ResolveManaged indicates an expected call of ResolveManaged.
func (mr *MockVDRMockRecorder) ResolveManaged(id any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResolveManaged", reflect.TypeOf((*MockVDR)(nil).ResolveManaged), id)
}

// Resolver mocks base method.
func (m *MockVDR) Resolver() resolver.DIDResolver {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Resolver")
	ret0, _ := ret[0].(resolver.DIDResolver)
	return ret0
}

// Resolver indicates an expected call of Resolver.
func (mr *MockVDRMockRecorder) Resolver() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Resolver", reflect.TypeOf((*MockVDR)(nil).Resolver))
}

// SupportedMethods mocks base method.
func (m *MockVDR) SupportedMethods() []string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SupportedMethods")
	ret0, _ := ret[0].([]string)
	return ret0
}

// SupportedMethods indicates an expected call of SupportedMethods.
func (mr *MockVDRMockRecorder) SupportedMethods() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SupportedMethods", reflect.TypeOf((*MockVDR)(nil).SupportedMethods))
}
