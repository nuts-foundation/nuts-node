// Code generated by MockGen. DO NOT EDIT.
// Source: vdr/resolver/did.go
//
// Generated by this command:
//
//	mockgen -destination=vdr/resolver/did_mock.go -package=resolver -source=vdr/resolver/did.go
//

// Package resolver is a generated GoMock package.
package resolver

import (
	reflect "reflect"

	did "github.com/nuts-foundation/go-did/did"
	gomock "go.uber.org/mock/gomock"
)

// MockDIDResolver is a mock of DIDResolver interface.
type MockDIDResolver struct {
	ctrl     *gomock.Controller
	recorder *MockDIDResolverMockRecorder
	isgomock struct{}
}

// MockDIDResolverMockRecorder is the mock recorder for MockDIDResolver.
type MockDIDResolverMockRecorder struct {
	mock *MockDIDResolver
}

// NewMockDIDResolver creates a new mock instance.
func NewMockDIDResolver(ctrl *gomock.Controller) *MockDIDResolver {
	mock := &MockDIDResolver{ctrl: ctrl}
	mock.recorder = &MockDIDResolverMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDIDResolver) EXPECT() *MockDIDResolverMockRecorder {
	return m.recorder
}

// Resolve mocks base method.
func (m *MockDIDResolver) Resolve(id did.DID, metadata *ResolveMetadata) (*did.Document, *DocumentMetadata, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Resolve", id, metadata)
	ret0, _ := ret[0].(*did.Document)
	ret1, _ := ret[1].(*DocumentMetadata)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// Resolve indicates an expected call of Resolve.
func (mr *MockDIDResolverMockRecorder) Resolve(id, metadata any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Resolve", reflect.TypeOf((*MockDIDResolver)(nil).Resolve), id, metadata)
}
