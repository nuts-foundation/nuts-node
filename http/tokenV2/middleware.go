package tokenV2

import (
	"fmt"
	"os"
	"strings"

  	"github.com/nuts-foundation/nuts-node/http/log"

        "github.com/labstack/echo/v4"
        "github.com/lestrrat-go/jwx/jwa"
        "github.com/lestrrat-go/jwx/jwk"
        "github.com/lestrrat-go/jwx/jws"
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
		return nil, fmt.Errorf("failed to parse authorizedKeys: %w", err)
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

		// Ensure the credential meetsrsecurity standards
		if err := credentialIsSecure(credential); err != nil {
			return unauthorizedError(fmt.Sprintf("insecure credential: %w", err))
		}

		// Attempt verifying the JWT using every available authorized key
		for _, authorizedKey := range m.authorizedKeys {
			log.Logger().Infof("checking key %v", authorizedKey.JWK.KeyID())

			// Put this authorized key into a JWK keyset which can be easily used for verification
			keySet := jwk.NewSet()
			keySet.Add(authorizedKey.JWK)
			
			// Parse the token, requesting verification using the keyset constructed above
			token, err := jwt.ParseRequest(context.Request(), jwt.WithKeySet(keySet), jwt.InferAlgorithmFromKey(true))
			if err != nil {
				log.Logger().Errorf("failed to parse JWT: %w", err)
				continue
			}       
			
			// Attempt to verify the signature of the JWT using this authorized key, which may
			// not be the key used to sign the token even if it is valid
			validateError := jwt.Validate(token)
			log.Logger().Infof("validateError: %w", validateError)
			if validateError != nil {
				// Since the signature could not be validated using this authorized key
				// try the next authorized key
				continue
			}

			// The user is authorized
			log.Logger().Infof("authorized user %v", authorizedKey.Comment)
			return next(context)
		} 

		// No authorized keys were able to verify the JWT, so this is an unauthorized request
		return unauthorizedError("credential not signed by an authorized key")
	}
}

// credentialIsSecure returns true,nil if a credential meets the minimum security
// standards. This can cover things like sufficiently secure signing algorithms,
// key size, etc.
func credentialIsSecure(credential string) error {
	// Parse the credential as a JWS (JSON Web Signature) containing a message. This works
	// because a JWT (JSON Web Token) is built on a JWS where the claims are a signed message.
	message, err := jws.ParseString(credential)
	if err != nil {
		return fmt.Errorf("cannot parse credential: jwk.ParseString: %w", err)
	}

	// Inspect the signatures in the message
	secureSignatureCount := 0
	for _, signature := range message.Signatures() {
		// Reject credentials signed with insecure algorithms
		algorithm := signature.ProtectedHeaders().Algorithm()
		if !acceptableSignatureAlgorithm(algorithm) {
			return fmt.Errorf("signing algorithm %v is not permitted", algorithm)
		}

		// Keep track of how many secure signatures are found
		secureSignatureCount++
	}

	// Accept messages containing secure signatures
	if secureSignatureCount > 0 {
		return nil
	}

	// By default this method rejects messages
	return fmt.Errorf("no signatures found")
}

// acceptableSignatureAlgorithm returns true if a signature algorithm
// is considered acceptable in terms of security.
func acceptableSignatureAlgorithm(algorithm jwa.SignatureAlgorithm) bool {
	switch algorithm {
	// The following algorithms are secure enough for credential signing
	case jwa.ES256, jwa.ES384, jwa.ES512, jwa.EdDSA, jwa.RS512:
		return true

	// Explicitly reject messages signed by the "none" algorithm. This
	// would technically be covered by the default case below but it makes
	// the intent clear in case somebody tries to turn this from a whitelist
	// approach into a blacklist approach in the future.
	case jwa.NoSignature:
		return false

	// Only explicitly allowed signing algorithms are acceptable
	default:
		return false
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

