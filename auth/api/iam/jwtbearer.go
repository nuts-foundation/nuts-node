package iam

import (
	"context"
	"errors"
)

func (r Wrapper) handleJWTBearerAccessTokenRequest(ctx context.Context, subject string, scope string, clientID string, clientAssertion string, assertion string) (HandleTokenRequestResponseObject, error) {
	// TODO: how to determine what credentials need to be presented?
	// We can use scope, but we want to make scope more flexible, since
	return nil, errors.New("to be implemented")
}
