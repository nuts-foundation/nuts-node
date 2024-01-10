// Code generated by MockGen. DO NOT EDIT.
// Source: auth/services/oauth/interface.go
//
// Generated by this command:
//
//	mockgen -destination=auth/services/oauth/mock.go -package=oauth -source=auth/services/oauth/interface.go
//

// Package oauth is a generated GoMock package.
package oauth

import (
	context "context"
	url "net/url"
	reflect "reflect"

	did "github.com/nuts-foundation/go-did/did"
	vc "github.com/nuts-foundation/go-did/vc"
	oauth "github.com/nuts-foundation/nuts-node/auth/oauth"
	services "github.com/nuts-foundation/nuts-node/auth/services"
	pe "github.com/nuts-foundation/nuts-node/vcr/pe"
	gomock "go.uber.org/mock/gomock"
)

// MockRelyingParty is a mock of RelyingParty interface.
type MockRelyingParty struct {
	ctrl     *gomock.Controller
	recorder *MockRelyingPartyMockRecorder
}

// MockRelyingPartyMockRecorder is the mock recorder for MockRelyingParty.
type MockRelyingPartyMockRecorder struct {
	mock *MockRelyingParty
}

// NewMockRelyingParty creates a new mock instance.
func NewMockRelyingParty(ctrl *gomock.Controller) *MockRelyingParty {
	mock := &MockRelyingParty{ctrl: ctrl}
	mock.recorder = &MockRelyingPartyMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRelyingParty) EXPECT() *MockRelyingPartyMockRecorder {
	return m.recorder
}

// CreateAuthorizationRequest mocks base method.
func (m *MockRelyingParty) CreateAuthorizationRequest(ctx context.Context, requestHolder, verifier did.DID, scopes, clientState string) (*url.URL, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateAuthorizationRequest", ctx, requestHolder, verifier, scopes, clientState)
	ret0, _ := ret[0].(*url.URL)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateAuthorizationRequest indicates an expected call of CreateAuthorizationRequest.
func (mr *MockRelyingPartyMockRecorder) CreateAuthorizationRequest(ctx, requestHolder, verifier, scopes, clientState any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateAuthorizationRequest", reflect.TypeOf((*MockRelyingParty)(nil).CreateAuthorizationRequest), ctx, requestHolder, verifier, scopes, clientState)
}

// CreateJwtGrant mocks base method.
func (m *MockRelyingParty) CreateJwtGrant(ctx context.Context, request services.CreateJwtGrantRequest) (*services.JwtBearerTokenResult, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateJwtGrant", ctx, request)
	ret0, _ := ret[0].(*services.JwtBearerTokenResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateJwtGrant indicates an expected call of CreateJwtGrant.
func (mr *MockRelyingPartyMockRecorder) CreateJwtGrant(ctx, request any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateJwtGrant", reflect.TypeOf((*MockRelyingParty)(nil).CreateJwtGrant), ctx, request)
}

// RequestRFC003AccessToken mocks base method.
func (m *MockRelyingParty) RequestRFC003AccessToken(ctx context.Context, jwtGrantToken string, authServerEndpoint url.URL) (*oauth.TokenResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RequestRFC003AccessToken", ctx, jwtGrantToken, authServerEndpoint)
	ret0, _ := ret[0].(*oauth.TokenResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RequestRFC003AccessToken indicates an expected call of RequestRFC003AccessToken.
func (mr *MockRelyingPartyMockRecorder) RequestRFC003AccessToken(ctx, jwtGrantToken, authServerEndpoint any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RequestRFC003AccessToken", reflect.TypeOf((*MockRelyingParty)(nil).RequestRFC003AccessToken), ctx, jwtGrantToken, authServerEndpoint)
}

// RequestRFC021AccessToken mocks base method.
func (m *MockRelyingParty) RequestRFC021AccessToken(ctx context.Context, requestHolder, verifier did.DID, scopes string) (*oauth.TokenResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RequestRFC021AccessToken", ctx, requestHolder, verifier, scopes)
	ret0, _ := ret[0].(*oauth.TokenResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RequestRFC021AccessToken indicates an expected call of RequestRFC021AccessToken.
func (mr *MockRelyingPartyMockRecorder) RequestRFC021AccessToken(ctx, requestHolder, verifier, scopes any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RequestRFC021AccessToken", reflect.TypeOf((*MockRelyingParty)(nil).RequestRFC021AccessToken), ctx, requestHolder, verifier, scopes)
}

// MockAuthorizationServer is a mock of AuthorizationServer interface.
type MockAuthorizationServer struct {
	ctrl     *gomock.Controller
	recorder *MockAuthorizationServerMockRecorder
}

// MockAuthorizationServerMockRecorder is the mock recorder for MockAuthorizationServer.
type MockAuthorizationServerMockRecorder struct {
	mock *MockAuthorizationServer
}

// NewMockAuthorizationServer creates a new mock instance.
func NewMockAuthorizationServer(ctrl *gomock.Controller) *MockAuthorizationServer {
	mock := &MockAuthorizationServer{ctrl: ctrl}
	mock.recorder = &MockAuthorizationServerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAuthorizationServer) EXPECT() *MockAuthorizationServerMockRecorder {
	return m.recorder
}

// Configure mocks base method.
func (m *MockAuthorizationServer) Configure(clockSkewInMilliseconds int, secureMode bool) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Configure", clockSkewInMilliseconds, secureMode)
	ret0, _ := ret[0].(error)
	return ret0
}

// Configure indicates an expected call of Configure.
func (mr *MockAuthorizationServerMockRecorder) Configure(clockSkewInMilliseconds, secureMode any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Configure", reflect.TypeOf((*MockAuthorizationServer)(nil).Configure), clockSkewInMilliseconds, secureMode)
}

// CreateAccessToken mocks base method.
func (m *MockAuthorizationServer) CreateAccessToken(ctx context.Context, request services.CreateAccessTokenRequest) (*oauth.TokenResponse, *oauth.OAuth2Error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateAccessToken", ctx, request)
	ret0, _ := ret[0].(*oauth.TokenResponse)
	ret1, _ := ret[1].(*oauth.OAuth2Error)
	return ret0, ret1
}

// CreateAccessToken indicates an expected call of CreateAccessToken.
func (mr *MockAuthorizationServerMockRecorder) CreateAccessToken(ctx, request any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateAccessToken", reflect.TypeOf((*MockAuthorizationServer)(nil).CreateAccessToken), ctx, request)
}

// IntrospectAccessToken mocks base method.
func (m *MockAuthorizationServer) IntrospectAccessToken(ctx context.Context, token string) (*services.NutsAccessToken, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IntrospectAccessToken", ctx, token)
	ret0, _ := ret[0].(*services.NutsAccessToken)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// IntrospectAccessToken indicates an expected call of IntrospectAccessToken.
func (mr *MockAuthorizationServerMockRecorder) IntrospectAccessToken(ctx, token any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IntrospectAccessToken", reflect.TypeOf((*MockAuthorizationServer)(nil).IntrospectAccessToken), ctx, token)
}

// MockVerifier is a mock of Verifier interface.
type MockVerifier struct {
	ctrl     *gomock.Controller
	recorder *MockVerifierMockRecorder
}

// MockVerifierMockRecorder is the mock recorder for MockVerifier.
type MockVerifierMockRecorder struct {
	mock *MockVerifier
}

// NewMockVerifier creates a new mock instance.
func NewMockVerifier(ctrl *gomock.Controller) *MockVerifier {
	mock := &MockVerifier{ctrl: ctrl}
	mock.recorder = &MockVerifierMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockVerifier) EXPECT() *MockVerifierMockRecorder {
	return m.recorder
}

// AuthorizationServerMetadata mocks base method.
func (m *MockVerifier) AuthorizationServerMetadata(ctx context.Context, webdid did.DID) (*oauth.AuthorizationServerMetadata, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AuthorizationServerMetadata", ctx, webdid)
	ret0, _ := ret[0].(*oauth.AuthorizationServerMetadata)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AuthorizationServerMetadata indicates an expected call of AuthorizationServerMetadata.
func (mr *MockVerifierMockRecorder) AuthorizationServerMetadata(ctx, webdid any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AuthorizationServerMetadata", reflect.TypeOf((*MockVerifier)(nil).AuthorizationServerMetadata), ctx, webdid)
}

// ClientMetadataURL mocks base method.
func (m *MockVerifier) ClientMetadataURL(webdid did.DID) (*url.URL, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ClientMetadataURL", webdid)
	ret0, _ := ret[0].(*url.URL)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ClientMetadataURL indicates an expected call of ClientMetadataURL.
func (mr *MockVerifierMockRecorder) ClientMetadataURL(webdid any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ClientMetadataURL", reflect.TypeOf((*MockVerifier)(nil).ClientMetadataURL), webdid)
}

// MockHolder is a mock of Holder interface.
type MockHolder struct {
	ctrl     *gomock.Controller
	recorder *MockHolderMockRecorder
}

// MockHolderMockRecorder is the mock recorder for MockHolder.
type MockHolderMockRecorder struct {
	mock *MockHolder
}

// NewMockHolder creates a new mock instance.
func NewMockHolder(ctrl *gomock.Controller) *MockHolder {
	mock := &MockHolder{ctrl: ctrl}
	mock.recorder = &MockHolderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockHolder) EXPECT() *MockHolderMockRecorder {
	return m.recorder
}

// BuildPresentation mocks base method.
func (m *MockHolder) BuildPresentation(ctx context.Context, walletDID did.DID, presentationDefinition pe.PresentationDefinition, acceptedFormats map[string]map[string][]string, nonce string) (*vc.VerifiablePresentation, *pe.PresentationSubmission, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "BuildPresentation", ctx, walletDID, presentationDefinition, acceptedFormats, nonce)
	ret0, _ := ret[0].(*vc.VerifiablePresentation)
	ret1, _ := ret[1].(*pe.PresentationSubmission)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// BuildPresentation indicates an expected call of BuildPresentation.
func (mr *MockHolderMockRecorder) BuildPresentation(ctx, walletDID, presentationDefinition, acceptedFormats, nonce any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BuildPresentation", reflect.TypeOf((*MockHolder)(nil).BuildPresentation), ctx, walletDID, presentationDefinition, acceptedFormats, nonce)
}

// ClientMetadata mocks base method.
func (m *MockHolder) ClientMetadata(ctx context.Context, endpoint string) (*oauth.OAuthClientMetadata, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ClientMetadata", ctx, endpoint)
	ret0, _ := ret[0].(*oauth.OAuthClientMetadata)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ClientMetadata indicates an expected call of ClientMetadata.
func (mr *MockHolderMockRecorder) ClientMetadata(ctx, endpoint any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ClientMetadata", reflect.TypeOf((*MockHolder)(nil).ClientMetadata), ctx, endpoint)
}

// PostAuthorizationResponse mocks base method.
func (m *MockHolder) PostAuthorizationResponse(ctx context.Context, vp vc.VerifiablePresentation, presentationSubmission pe.PresentationSubmission, verifierResponseURI, state string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PostAuthorizationResponse", ctx, vp, presentationSubmission, verifierResponseURI, state)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// PostAuthorizationResponse indicates an expected call of PostAuthorizationResponse.
func (mr *MockHolderMockRecorder) PostAuthorizationResponse(ctx, vp, presentationSubmission, verifierResponseURI, state any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PostAuthorizationResponse", reflect.TypeOf((*MockHolder)(nil).PostAuthorizationResponse), ctx, vp, presentationSubmission, verifierResponseURI, state)
}

// PostError mocks base method.
func (m *MockHolder) PostError(ctx context.Context, auth2Error oauth.OAuth2Error, verifierResponseURI string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PostError", ctx, auth2Error, verifierResponseURI)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// PostError indicates an expected call of PostError.
func (mr *MockHolderMockRecorder) PostError(ctx, auth2Error, verifierResponseURI any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PostError", reflect.TypeOf((*MockHolder)(nil).PostError), ctx, auth2Error, verifierResponseURI)
}

// PresentationDefinition mocks base method.
func (m *MockHolder) PresentationDefinition(ctx context.Context, presentationDefinitionURI string) (*pe.PresentationDefinition, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PresentationDefinition", ctx, presentationDefinitionURI)
	ret0, _ := ret[0].(*pe.PresentationDefinition)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// PresentationDefinition indicates an expected call of PresentationDefinition.
func (mr *MockHolderMockRecorder) PresentationDefinition(ctx, presentationDefinitionURI any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PresentationDefinition", reflect.TypeOf((*MockHolder)(nil).PresentationDefinition), ctx, presentationDefinitionURI)
}
