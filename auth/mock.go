// Code generated by MockGen. DO NOT EDIT.
// Source: auth/interface.go
//
// Generated by this command:
//
//	mockgen -destination=auth/mock.go -package=auth -source=auth/interface.go
//

// Package auth is a generated GoMock package.
package auth

import (
	url "net/url"
	reflect "reflect"

	iam "github.com/nuts-foundation/nuts-node/auth/client/iam"
	services "github.com/nuts-foundation/nuts-node/auth/services"
	oauth "github.com/nuts-foundation/nuts-node/auth/services/oauth"
	gomock "go.uber.org/mock/gomock"
)

// MockAuthenticationServices is a mock of AuthenticationServices interface.
type MockAuthenticationServices struct {
	ctrl     *gomock.Controller
	recorder *MockAuthenticationServicesMockRecorder
}

// MockAuthenticationServicesMockRecorder is the mock recorder for MockAuthenticationServices.
type MockAuthenticationServicesMockRecorder struct {
	mock *MockAuthenticationServices
}

// NewMockAuthenticationServices creates a new mock instance.
func NewMockAuthenticationServices(ctrl *gomock.Controller) *MockAuthenticationServices {
	mock := &MockAuthenticationServices{ctrl: ctrl}
	mock.recorder = &MockAuthenticationServicesMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAuthenticationServices) EXPECT() *MockAuthenticationServicesMockRecorder {
	return m.recorder
}

// AuthorizationEndpointEnabled mocks base method.
func (m *MockAuthenticationServices) AuthorizationEndpointEnabled() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AuthorizationEndpointEnabled")
	ret0, _ := ret[0].(bool)
	return ret0
}

// AuthorizationEndpointEnabled indicates an expected call of AuthorizationEndpointEnabled.
func (mr *MockAuthenticationServicesMockRecorder) AuthorizationEndpointEnabled() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AuthorizationEndpointEnabled", reflect.TypeOf((*MockAuthenticationServices)(nil).AuthorizationEndpointEnabled))
}

// AuthzServer mocks base method.
func (m *MockAuthenticationServices) AuthzServer() oauth.AuthorizationServer {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AuthzServer")
	ret0, _ := ret[0].(oauth.AuthorizationServer)
	return ret0
}

// AuthzServer indicates an expected call of AuthzServer.
func (mr *MockAuthenticationServicesMockRecorder) AuthzServer() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AuthzServer", reflect.TypeOf((*MockAuthenticationServices)(nil).AuthzServer))
}

// ContractNotary mocks base method.
func (m *MockAuthenticationServices) ContractNotary() services.ContractNotary {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ContractNotary")
	ret0, _ := ret[0].(services.ContractNotary)
	return ret0
}

// ContractNotary indicates an expected call of ContractNotary.
func (mr *MockAuthenticationServicesMockRecorder) ContractNotary() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ContractNotary", reflect.TypeOf((*MockAuthenticationServices)(nil).ContractNotary))
}

// IAMClient mocks base method.
func (m *MockAuthenticationServices) IAMClient() iam.Client {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IAMClient")
	ret0, _ := ret[0].(iam.Client)
	return ret0
}

// IAMClient indicates an expected call of IAMClient.
func (mr *MockAuthenticationServicesMockRecorder) IAMClient() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IAMClient", reflect.TypeOf((*MockAuthenticationServices)(nil).IAMClient))
}

// PublicURL mocks base method.
func (m *MockAuthenticationServices) PublicURL() *url.URL {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PublicURL")
	ret0, _ := ret[0].(*url.URL)
	return ret0
}

// PublicURL indicates an expected call of PublicURL.
func (mr *MockAuthenticationServicesMockRecorder) PublicURL() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PublicURL", reflect.TypeOf((*MockAuthenticationServices)(nil).PublicURL))
}

// RelyingParty mocks base method.
func (m *MockAuthenticationServices) RelyingParty() oauth.RelyingParty {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RelyingParty")
	ret0, _ := ret[0].(oauth.RelyingParty)
	return ret0
}

// RelyingParty indicates an expected call of RelyingParty.
func (mr *MockAuthenticationServicesMockRecorder) RelyingParty() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RelyingParty", reflect.TypeOf((*MockAuthenticationServices)(nil).RelyingParty))
}

// SupportedDIDMethods mocks base method.
func (m *MockAuthenticationServices) SupportedDIDMethods() []string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SupportedDIDMethods")
	ret0, _ := ret[0].([]string)
	return ret0
}

// SupportedDIDMethods indicates an expected call of SupportedDIDMethods.
func (mr *MockAuthenticationServicesMockRecorder) SupportedDIDMethods() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SupportedDIDMethods", reflect.TypeOf((*MockAuthenticationServices)(nil).SupportedDIDMethods))
}
