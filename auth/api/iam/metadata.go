package iam

func authorizationServerMetadata(identity string) OAuthAuthorizationServerMetadata {
	return OAuthAuthorizationServerMetadata{
		Issuer:                 identity,
		AuthorizationEndpoint:  identity + "/authorize",
		ResponseTypesSupported: responseTypesSupported,
		ResponseModesSupported: responseModesSupported,
		TokenEndpoint:          identity + "/token",
		GrantTypesSupported:    grantTypesSupported,
		PreAuthorizedGrantAnonymousAccessSupported: true,
		VPFormatsSupported:                         vpFormatsSupported,
		ClientIdSchemesSupported:                   clientIdSchemesSupported,
	}
}
