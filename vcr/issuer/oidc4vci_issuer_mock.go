// Code generated by MockGen. DO NOT EDIT.
// Source: vcr/issuer/oidc4vci_issuer.go

// Package issuer is a generated GoMock package.
package issuer

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	vc "github.com/nuts-foundation/go-did/vc"
	oidc4vci "github.com/nuts-foundation/nuts-node/vcr/oidc4vci"
)

// MockOIDCIssuer is a mock of OIDCIssuer interface.
type MockOIDCIssuer struct {
	ctrl     *gomock.Controller
	recorder *MockOIDCIssuerMockRecorder
}

// MockOIDCIssuerMockRecorder is the mock recorder for MockOIDCIssuer.
type MockOIDCIssuerMockRecorder struct {
	mock *MockOIDCIssuer
}

// NewMockOIDCIssuer creates a new mock instance.
func NewMockOIDCIssuer(ctrl *gomock.Controller) *MockOIDCIssuer {
	mock := &MockOIDCIssuer{ctrl: ctrl}
	mock.recorder = &MockOIDCIssuerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockOIDCIssuer) EXPECT() *MockOIDCIssuerMockRecorder {
	return m.recorder
}

// GetCredential mocks base method.
func (m *MockOIDCIssuer) GetCredential(ctx context.Context, accessToken string) (vc.VerifiableCredential, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetCredential", ctx, accessToken)
	ret0, _ := ret[0].(vc.VerifiableCredential)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetCredential indicates an expected call of GetCredential.
func (mr *MockOIDCIssuerMockRecorder) GetCredential(ctx, accessToken interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetCredential", reflect.TypeOf((*MockOIDCIssuer)(nil).GetCredential), ctx, accessToken)
}

// Metadata mocks base method.
func (m *MockOIDCIssuer) Metadata() oidc4vci.CredentialIssuerMetadata {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Metadata")
	ret0, _ := ret[0].(oidc4vci.CredentialIssuerMetadata)
	return ret0
}

// Metadata indicates an expected call of Metadata.
func (mr *MockOIDCIssuerMockRecorder) Metadata() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Metadata", reflect.TypeOf((*MockOIDCIssuer)(nil).Metadata))
}

// Offer mocks base method.
func (m *MockOIDCIssuer) Offer(ctx context.Context, credential vc.VerifiableCredential, walletURL string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Offer", ctx, credential, walletURL)
	ret0, _ := ret[0].(error)
	return ret0
}

// Offer indicates an expected call of Offer.
func (mr *MockOIDCIssuerMockRecorder) Offer(ctx, credential, walletURL interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Offer", reflect.TypeOf((*MockOIDCIssuer)(nil).Offer), ctx, credential, walletURL)
}

// ProviderMetadata mocks base method.
func (m *MockOIDCIssuer) ProviderMetadata() oidc4vci.ProviderMetadata {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ProviderMetadata")
	ret0, _ := ret[0].(oidc4vci.ProviderMetadata)
	return ret0
}

// ProviderMetadata indicates an expected call of ProviderMetadata.
func (mr *MockOIDCIssuerMockRecorder) ProviderMetadata() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ProviderMetadata", reflect.TypeOf((*MockOIDCIssuer)(nil).ProviderMetadata))
}

// RequestAccessToken mocks base method.
func (m *MockOIDCIssuer) RequestAccessToken(ctx context.Context, preAuthorizedCode string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RequestAccessToken", ctx, preAuthorizedCode)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RequestAccessToken indicates an expected call of RequestAccessToken.
func (mr *MockOIDCIssuerMockRecorder) RequestAccessToken(ctx, preAuthorizedCode interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RequestAccessToken", reflect.TypeOf((*MockOIDCIssuer)(nil).RequestAccessToken), ctx, preAuthorizedCode)
}
