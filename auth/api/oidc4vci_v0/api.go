package oidc4vci_v0

import "context"

// TODO: Split this file into multiple files, per role (issuer/holder)

type Wrapper struct {
}

func (w Wrapper) GetOIDCProviderMeta(ctx context.Context, request GetOIDCProviderMetaRequestObject) (GetOIDCProviderMetaResponseObject, error) {
	//TODO implement me
	panic("implement me")
}

func (w Wrapper) GetOIDCIssuerMeta(ctx context.Context, request GetOIDCIssuerMetaRequestObject) (GetOIDCIssuerMetaResponseObject, error) {
	//TODO implement me
	panic("implement me")
}

func (w Wrapper) ReceiveCredentialOffer(ctx context.Context, request ReceiveCredentialOfferRequestObject) (ReceiveCredentialOfferResponseObject, error) {
	//TODO implement me
	panic("implement me")
}

func (w Wrapper) GetCredential(ctx context.Context, request GetCredentialRequestObject) (GetCredentialResponseObject, error) {
	//TODO implement me
	panic("implement me")
}

func (w Wrapper) RequestAccessToken(ctx context.Context, request RequestAccessTokenRequestObject) (RequestAccessTokenResponseObject, error) {
	//TODO implement me
	panic("implement me")
}
