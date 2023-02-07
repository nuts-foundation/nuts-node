package tokenV2

import (
	"fmt"
	"strings"

  	"github.com/nuts-foundation/nuts-node/http/log"

        "github.com/labstack/echo/v4"
        "github.com/lestrrat-go/jwx/jwk"
        //"github.com/lestrrat-go/jwx/jws"
        "github.com/lestrrat-go/jwx/jwt"
)

// New returns a new token authenticator middleware given the contents of an SSH
// authorized_keys file. Requests containing a JWT Bearer token signed by one of
// the specified keys will be authorized, and those not will receive an HTTP 401
// error.
func New(authorizedKeys []byte) (Middleware, error) {
	// Parse the authorized keys, returning an error if it fails
	parsed, err := parseAuthorizedKeys(authorizedKeys)
	if err != nil {
		return nil, fmt.Errorf("failed to parse authorizedKeys: %v", err)
	}

	// Return the private struct implementing the public interface
	impl := &middlewareImpl{
		authorizedKeys: parsed,
	}
	return impl, nil
}

// NewFromFile is like New but it takes the path for an authorized_keys file
func NewFromFile(authorizedKeysPath string) (Middleware, error) {
	// Read the specified path
	contents, err := os.ReadFile(authorizedKeysPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read %v: %w", authorizedKeysPath, err)
	}

	// Use the contents of the file to create a new middleware
	return New(contents)
}

// Middleware defines the public interface to be set with Use() on an echo server
type Middleware interface {
	Handler(next echo.HandlerFunc) echo.HandlerFunc
}

// middlewareImpl implements the Middleware interface with a private type
type middlewareImpl struct {
	authorizedKeys []authorizedKey
}

// Handler returns an echo HandlerFunc for processing incoming requests
func (m middlewareImpl) Handler(next echo.HandlerFunc) echo.HandlerFunc {
	return func(context echo.Context) error {
		// Extract the authentication credential for this request
		credential := authenticationCredential(context)

		// Empty credentials will receive a 401 response
		if credential == "" {
			return unauthorizedError("missing/malformed credential")
		}

		// Check each authorized key for a valid signature
		for _, authorizedKey := range m.authorizedKeys {
			log.Logger().Infof("checking key %v", authorizedKey.JWK.KeyID())
			keySet := jwk.NewSet()
			keySet.Add(authorizedKey.JWK)
			
			// Parse the token without verifying the signature
			token, err := jwt.ParseRequest(context.Request(), jwt.WithKeySet(keySet), jwt.InferAlgorithmFromKey(true))
			if err != nil {
				log.Logger().Errorf("failed to parse JWT: %v", err)
				continue
			}       
			
			// Ensure the token is valid
			validateError := jwt.Validate(token)
			log.Logger().Infof("validateError: %v", validateError)
			if validateError != nil {
				continue
			}

			// The user is authorized
			log.Logger().Infof("authorized user %v", authorizedKey.Comment)
			return next(context)
		} 

		return unauthorizedError("credential not signed by an authorized key")
	}
}

// authenticationCredential returns the token present in the Authorization
// header of the HTTP request.
func authenticationCredential(context echo.Context) string {
	// Extract the authorization header from the request
	credential := context.Request().Header.Get("Authorization")
	if credential == "" {
		return ""
	}

	// Ignore any credential which is not a bearer token
	if !strings.HasPrefix(credential, "Bearer ") {
		return ""
	}

	// Return the credential with the type (Bearer) stripped
	return strings.TrimPrefix(credential, "Bearer ")
}

// unauthorizedError returns an echo unauthorized error
func unauthorizedError(message string) *echo.HTTPError {
	return &echo.HTTPError {
		Code: 401,
		Message: "Unauthorized",
		Internal: fmt.Errorf(message),
	}
}
