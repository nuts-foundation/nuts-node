// Code generated by MockGen. DO NOT EDIT.
// Source: auth/client/iam/interface.go
//
// Generated by this command:
//
//	mockgen -destination=auth/client/iam/mock.go -package=iam -source=auth/client/iam/interface.go
//

// Package iam is a generated GoMock package.
package iam

import (
	context "context"
	reflect "reflect"

	vc "github.com/nuts-foundation/go-did/vc"
	oauth "github.com/nuts-foundation/nuts-node/auth/oauth"
	pe "github.com/nuts-foundation/nuts-node/vcr/pe"
	gomock "go.uber.org/mock/gomock"
)

// MockClient is a mock of Client interface.
type MockClient struct {
	ctrl     *gomock.Controller
	recorder *MockClientMockRecorder
	isgomock struct{}
}

// MockClientMockRecorder is the mock recorder for MockClient.
type MockClientMockRecorder struct {
	mock *MockClient
}

// NewMockClient creates a new mock instance.
func NewMockClient(ctrl *gomock.Controller) *MockClient {
	mock := &MockClient{ctrl: ctrl}
	mock.recorder = &MockClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockClient) EXPECT() *MockClientMockRecorder {
	return m.recorder
}

// AccessToken mocks base method.
func (m *MockClient) AccessToken(ctx context.Context, code, tokenURI, callbackURI, subject, clientID, codeVerifier string, useDPoP bool) (*oauth.TokenResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AccessToken", ctx, code, tokenURI, callbackURI, subject, clientID, codeVerifier, useDPoP)
	ret0, _ := ret[0].(*oauth.TokenResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AccessToken indicates an expected call of AccessToken.
func (mr *MockClientMockRecorder) AccessToken(ctx, code, tokenURI, callbackURI, subject, clientID, codeVerifier, useDPoP any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AccessToken", reflect.TypeOf((*MockClient)(nil).AccessToken), ctx, code, tokenURI, callbackURI, subject, clientID, codeVerifier, useDPoP)
}

// AuthorizationServerMetadata mocks base method.
func (m *MockClient) AuthorizationServerMetadata(ctx context.Context, oauthIssuer string) (*oauth.AuthorizationServerMetadata, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AuthorizationServerMetadata", ctx, oauthIssuer)
	ret0, _ := ret[0].(*oauth.AuthorizationServerMetadata)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AuthorizationServerMetadata indicates an expected call of AuthorizationServerMetadata.
func (mr *MockClientMockRecorder) AuthorizationServerMetadata(ctx, oauthIssuer any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AuthorizationServerMetadata", reflect.TypeOf((*MockClient)(nil).AuthorizationServerMetadata), ctx, oauthIssuer)
}

// ClientMetadata mocks base method.
func (m *MockClient) ClientMetadata(ctx context.Context, endpoint string) (*oauth.OAuthClientMetadata, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ClientMetadata", ctx, endpoint)
	ret0, _ := ret[0].(*oauth.OAuthClientMetadata)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ClientMetadata indicates an expected call of ClientMetadata.
func (mr *MockClientMockRecorder) ClientMetadata(ctx, endpoint any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ClientMetadata", reflect.TypeOf((*MockClient)(nil).ClientMetadata), ctx, endpoint)
}

// OpenIDConfiguration mocks base method.
func (m *MockClient) OpenIDConfiguration(ctx context.Context, issuer string) (*oauth.OpenIDConfiguration, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "OpenIDConfiguration", ctx, issuer)
	ret0, _ := ret[0].(*oauth.OpenIDConfiguration)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// OpenIDConfiguration indicates an expected call of OpenIDConfiguration.
func (mr *MockClientMockRecorder) OpenIDConfiguration(ctx, issuer any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OpenIDConfiguration", reflect.TypeOf((*MockClient)(nil).OpenIDConfiguration), ctx, issuer)
}

// OpenIdCredentialIssuerMetadata mocks base method.
func (m *MockClient) OpenIdCredentialIssuerMetadata(ctx context.Context, oauthIssuerURI string) (*oauth.OpenIDCredentialIssuerMetadata, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "OpenIdCredentialIssuerMetadata", ctx, oauthIssuerURI)
	ret0, _ := ret[0].(*oauth.OpenIDCredentialIssuerMetadata)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// OpenIdCredentialIssuerMetadata indicates an expected call of OpenIdCredentialIssuerMetadata.
func (mr *MockClientMockRecorder) OpenIdCredentialIssuerMetadata(ctx, oauthIssuerURI any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OpenIdCredentialIssuerMetadata", reflect.TypeOf((*MockClient)(nil).OpenIdCredentialIssuerMetadata), ctx, oauthIssuerURI)
}

// PostAuthorizationResponse mocks base method.
func (m *MockClient) PostAuthorizationResponse(ctx context.Context, vp vc.VerifiablePresentation, presentationSubmission pe.PresentationSubmission, verifierResponseURI, state string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PostAuthorizationResponse", ctx, vp, presentationSubmission, verifierResponseURI, state)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// PostAuthorizationResponse indicates an expected call of PostAuthorizationResponse.
func (mr *MockClientMockRecorder) PostAuthorizationResponse(ctx, vp, presentationSubmission, verifierResponseURI, state any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PostAuthorizationResponse", reflect.TypeOf((*MockClient)(nil).PostAuthorizationResponse), ctx, vp, presentationSubmission, verifierResponseURI, state)
}

// PostError mocks base method.
func (m *MockClient) PostError(ctx context.Context, auth2Error oauth.OAuth2Error, verifierResponseURI, verifierClientState string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PostError", ctx, auth2Error, verifierResponseURI, verifierClientState)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// PostError indicates an expected call of PostError.
func (mr *MockClientMockRecorder) PostError(ctx, auth2Error, verifierResponseURI, verifierClientState any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PostError", reflect.TypeOf((*MockClient)(nil).PostError), ctx, auth2Error, verifierResponseURI, verifierClientState)
}

// PresentationDefinition mocks base method.
func (m *MockClient) PresentationDefinition(ctx context.Context, endpoint string) (*pe.PresentationDefinition, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PresentationDefinition", ctx, endpoint)
	ret0, _ := ret[0].(*pe.PresentationDefinition)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// PresentationDefinition indicates an expected call of PresentationDefinition.
func (mr *MockClientMockRecorder) PresentationDefinition(ctx, endpoint any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PresentationDefinition", reflect.TypeOf((*MockClient)(nil).PresentationDefinition), ctx, endpoint)
}

// RequestObjectByGet mocks base method.
func (m *MockClient) RequestObjectByGet(ctx context.Context, requestURI string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RequestObjectByGet", ctx, requestURI)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RequestObjectByGet indicates an expected call of RequestObjectByGet.
func (mr *MockClientMockRecorder) RequestObjectByGet(ctx, requestURI any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RequestObjectByGet", reflect.TypeOf((*MockClient)(nil).RequestObjectByGet), ctx, requestURI)
}

// RequestObjectByPost mocks base method.
func (m *MockClient) RequestObjectByPost(ctx context.Context, requestURI string, walletMetadata oauth.AuthorizationServerMetadata) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RequestObjectByPost", ctx, requestURI, walletMetadata)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RequestObjectByPost indicates an expected call of RequestObjectByPost.
func (mr *MockClientMockRecorder) RequestObjectByPost(ctx, requestURI, walletMetadata any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RequestObjectByPost", reflect.TypeOf((*MockClient)(nil).RequestObjectByPost), ctx, requestURI, walletMetadata)
}

// RequestRFC021AccessToken mocks base method.
func (m *MockClient) RequestRFC021AccessToken(ctx context.Context, clientID, subjectDID, authServerURL, scopes string, useDPoP bool, credentials []vc.VerifiableCredential) (*oauth.TokenResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RequestRFC021AccessToken", ctx, clientID, subjectDID, authServerURL, scopes, useDPoP, credentials)
	ret0, _ := ret[0].(*oauth.TokenResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RequestRFC021AccessToken indicates an expected call of RequestRFC021AccessToken.
func (mr *MockClientMockRecorder) RequestRFC021AccessToken(ctx, clientID, subjectDID, authServerURL, scopes, useDPoP, credentials any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RequestRFC021AccessToken", reflect.TypeOf((*MockClient)(nil).RequestRFC021AccessToken), ctx, clientID, subjectDID, authServerURL, scopes, useDPoP, credentials)
}

// VerifiableCredentials mocks base method.
func (m *MockClient) VerifiableCredentials(ctx context.Context, credentialEndpoint, accessToken, proofJWT string) (*CredentialResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "VerifiableCredentials", ctx, credentialEndpoint, accessToken, proofJWT)
	ret0, _ := ret[0].(*CredentialResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// VerifiableCredentials indicates an expected call of VerifiableCredentials.
func (mr *MockClientMockRecorder) VerifiableCredentials(ctx, credentialEndpoint, accessToken, proofJWT any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VerifiableCredentials", reflect.TypeOf((*MockClient)(nil).VerifiableCredentials), ctx, credentialEndpoint, accessToken, proofJWT)
}
