package tokenV2

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/http/log"

	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"

	"github.com/google/uuid"
)

type SkipperFunc func(context echo.Context) bool

// MaximumCredentialLength defines the maximum number of characters in a credential
const MaximumCredentialLength = 4096

// New returns a new token authenticator middleware given the contents of an SSH
// authorized_keys file. Requests containing a JWT Bearer token signed by one of
// the specified keys will be authorized, and those not will receive an HTTP 401
// error.
func New(skipper SkipperFunc, audience string, authorizedKeys []byte) (Middleware, error) {
	// Parse the authorized keys, returning an error if it fails
	parsed, err := parseAuthorizedKeys(authorizedKeys)
	if err != nil {
		return nil, fmt.Errorf("failed to parse API authorized keys: %w", err)
	}

	// Log a warning to administrators when their authorized_keys files don't seem to
	// contain any valid keys.
	if len(parsed) == 0 {
		log.Logger().Warn("No keys were parsed from authorized_keys")
	}

	// Return the private struct implementing the public interface
	impl := &middlewareImpl{
		audience:       audience,
		authorizedKeys: parsed,
		skipper:        skipper,
	}
	return impl, nil
}

// NewFromFile is like New but it takes the path for an authorized_keys file
func NewFromFile(skipper SkipperFunc, audience string, authorizedKeysPath string) (Middleware, error) {
	// Read the specified path
	contents, err := os.ReadFile(authorizedKeysPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read %v: %w", authorizedKeysPath, err)
	}

	// Use the contents of the file to create a new middleware
	return New(skipper, audience, contents)
}

// Middleware defines the public interface to be set with Use() on an echo server
type Middleware interface {
	Handler(next echo.HandlerFunc) echo.HandlerFunc
}

// middlewareImpl implements the Middleware interface with a private type
type middlewareImpl struct {
	// audience defines the enforced audience for JWT credentials
	audience string

	// authorizedKeys defines a number of SSH formatted public keys trusted to sign JWT credentials
	authorizedKeys []authorizedKey

	// skipper provides optional external logic for skipping authorization enforcement on certain requests
	skipper SkipperFunc
}

// Handler returns an echo HandlerFunc for processing incoming requests
func (m middlewareImpl) Handler(next echo.HandlerFunc) echo.HandlerFunc {
	return func(context echo.Context) error {
		// Allow skipping enforcement on certain requests using external logic
		if m.skipper != nil && m.skipper(context) {
			log.Logger().Tracef("Skipping authorization enforcement for request context: %v", context)
			return next(context)
		}

		// Extract the authentication credential for this request
		credential := authenticationCredential(context)

		// Empty credentials will receive a 401 response
		if credential == "" {
			return unauthorizedError(context, errors.New("missing/malformed credential"))
		}

		// Ensure the credential meets security standards
		if err := credentialIsSecure(credential); err != nil {
			return unauthorizedError(context, fmt.Errorf("insecure credential: %w", err))
		}

		// Attempt verifying the JWT using every available authorized key
		for _, authorizedKey := range m.authorizedKeys {
			log.Logger().Tracef("Checking key %v", authorizedKey.JWK.KeyID())

			// Put this authorized key into a JWK keyset which can be easily used for verification
			keySet := jwk.NewSet()
			keySet.Add(authorizedKey.JWK)

			// Parse the token, requesting verification using the keyset constructed above.
			// If the JWT was not signed by this key then this will fail.
			//
			// WARNING: A nil error return from this function is not enough to authenticate a request
			// as the token may be expired etc. A further check with .Validate() is required in order
			// to authenticate the request.
			token, err := jwt.ParseString(credential, jwt.WithKeySet(keySet), jwt.InferAlgorithmFromKey(true))
			if err != nil {
				log.Logger().Errorf("Failed to parse JWT: %v", err)
				continue
			}

			// The JWT was indeed signed by this authorized key, but that is not enough to authorize the request.
			// Attempt to validate the parameters of the JWT, which ensures the audience, issued at, expiration, etc.
			// are valid.
			if err := jwt.Validate(token, jwt.WithAudience(m.audience)); err != nil {
				// Since the parameters of this properly signed JWT could not be validated, reject the request
				return unauthorizedError(context, fmt.Errorf("jwt.Validate: %w", err))
			}

			// The token was properly signed and the essential fields are valid, but now we need to ensure that
			// best practices are being followed in terms of what fields are present and how they are being used.
			if err := bestPracticesCheck(token); err != nil {
				return unauthorizedError(context, fmt.Errorf("insecure credential: %w", err))
			}

			// The user is authorized, log a message accordingly
			log.Logger().Tracef("Authorized user %v", authorizedKey.Comment)

			// Log an entry in the audit log about this user access
			auditLog(context, authorizedKey.Comment, audit.AccessGrantedEvent)

			// Set the username from authorized_keys as the username in the context
			context.Set(core.UserContextKey, authorizedKey.Comment)

			// Call the next handler/middleware, probably serving some content/processing the API request
			return next(context)
		}

		// No authorized keys were able to verify the JWT, so this is an unauthorized request
		return unauthorizedError(context, errors.New("credential not signed by an authorized key"))
	}
}

// credentialIsSecure returns true,nil if a credential meets the minimum security
// standards. This can cover things like sufficiently secure signing algorithms,
// key size, etc.
//
// WARNING: A credential passing this check is not yet considered properly signed
// or having valid essential claims such as NotBefore, Expiration, etc.
func credentialIsSecure(credential string) error {
	// Ignore very long credentials
	if len(credential) > MaximumCredentialLength {
		return fmt.Errorf("credential is too long")
	}

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

// mandatoryJWTFields returns the mandatory fields of the JWT, and is effectively a constant
func mandatoryJWTFields() []string {
	return []string{jwt.JwtIDKey, jwt.IssuedAtKey, jwt.ExpirationKey, jwt.NotBeforeKey, jwt.AudienceKey}
}

// tokenJTI returns the JWT's JTI as a string
func tokenJTI(token jwt.Token) string {
	// Retrieve the JwtID from the token, but it comes out as an interface{}
	if jtiIface, ok := token.Get(jwt.JwtIDKey); ok {
		// Convert the interface{} to a string so the typed value can be returned
		if jtiStr, ok := jtiIface.(string); ok {
			return jtiStr
		}
	}

	// Simply return an empty string if either the jti field wasn't present or it wasn't a string
	return ""
}

// bestPracticesCheck ensures tokens are crafted in a sensible way, ensuring that even a valid signer must
// conform to certain security controls such as not creating long lived credentials etc.
//
// WARNING: This check does not verify signatures or even the essential claims such as NotBefore, Expiration, etc.
func bestPracticesCheck(token jwt.Token) error {
	// Ensure the mandatory fields are present
	for _, field := range mandatoryJWTFields() {
		if _, ok := token.Get(field); !ok {
			return fmt.Errorf("missing field: %v", field)
		}
	}

	// Ensure JTI is a UUID
	jti := tokenJTI(token)
	if _, err := uuid.Parse(jti); err != nil {
		return fmt.Errorf("token jti is not a valid uuid: %w", err)
	}

	// Ensure the expiration is no more than 24.5 hours after NotBefore
	maxExpirationAfterNotBefore := token.NotBefore().Add(time.Minute * time.Duration(1470))
	if token.Expiration().After(maxExpirationAfterNotBefore) {
		return errors.New("token expires too long after nbf")
	}

	// Ensure the expiration is no more than 24.5 hours after IssuedAt
	maxExpirationAfterIssuedAt := token.IssuedAt().Add(time.Minute * time.Duration(1470))
	if token.Expiration().After(maxExpirationAfterIssuedAt) {
		return errors.New("token expires too long after iat")
	}

	// Ensure the IssuedAt is <= the NotBefore date
	if token.IssuedAt().After(token.NotBefore()) {
		return errors.New("token nbf occurs before iat")
	}

	// No best practices issues were found, so return nil
	return nil
}

// acceptableSignatureAlgorithm returns true if a signature algorithm
// is considered acceptable in terms of security.
//
// For a good discussion on JWT signing algorithms see:
// https://dev.to/scottbrady91/jwts-which-signing-algorithm-should-i-use-3m79
func acceptableSignatureAlgorithm(algorithm jwa.SignatureAlgorithm) bool {
	switch algorithm {
	// The following algorithms are supported for elliptic curve keys
	case jwa.ES256, jwa.ES384, jwa.ES512:
		return true

	// The RS512/PS512 algorithms are supported for RSA keys, but less secure
	// alternatives (RS256, RS384, PS256, PS384) are not supported.
	//
	// If you're wondering why, see RFC 8017:
	// https://www.rfc-editor.org/rfc/rfc8017#page-31
	// """
	// Two signature schemes with appendix are specified in this document:
	// RSASSA-PSS and RSASSA-PKCS1-v1_5.  Although no attacks are known
	// against RSASSA-PKCS1-v1_5, in the interest of increased robustness,
	// RSASSA-PSS is REQUIRED in new applications.  RSASSA-PKCS1-v1_5 is
	// included only for compatibility with existing applications.
	// """
	//
	// In short, the RFC snippet above claims that the RS* algorithms should be
	// deprecated in favor of the PS* algorithms. The RS512 algorithm is
	// supported here so that ssh-agent based JWT generation can support RSA
	// keys as RS512 is the most secure signature algorithm supported in
	// the ssh-agent protocol. It seems the ssh ecosystem has generally moved
	// beyond RSA support in favor of trying to maximize security within the
	// scope of RSA use. Perhaps we could consider doing the same.
	case jwa.RS512, jwa.PS512:
		return true

	// Edwards curve signatures are considered secure and are therefore supported
	case jwa.EdDSA:
		return true

	// Explicitly reject messages signed by the "none" algorithm. This
	// would technically be covered by the default case below but it makes
	// the intent clear in case somebody tries to turn this from a whitelist
	// approach into a blacklist approach in the future. Not to mention this
	// going wrong would result in a catastrophic security hole, so it's worth
	// having a special case for it.
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

	// Split the authorization header on whitespace
	fields := strings.Fields(credential)

	// Ignore any header unless it has precisely 2 fields
	if len(fields) != 2 {
		return ""
	}

	// Ignore non-bearer headers
	if strings.ToLower(fields[0]) != "bearer" {
		return ""
	}

	// Return the supplied credential
	return fields[1]
}

// unauthorizedError returns an echo unauthorized error
func unauthorizedError(context echo.Context, reason error) *echo.HTTPError {
	// Explicitly set the response to 401 Unauthorized rather than relying on any default behaviour
	context.String(http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))

	// Set an empty username for this context
	context.Set(core.UserContextKey, "")

	// Log an entry in the audit log about this failure
	auditLog(context, defaultActor(context), audit.AccessDeniedEvent)

	// Return the appropriate echo error to ensure complete logging
	return &echo.HTTPError{
		Code:     http.StatusUnauthorized,
		Message:  http.StatusText(http.StatusUnauthorized),
		Internal: reason,
	}
}

// defaultActor returns some suitable default representation for the remote actor
func defaultActor(context echo.Context) string {
	// If available use the real IP of the caller as the default actor name
	realIP := context.RealIP()
	if realIP != "" {
		return realIP
	}

	return "unknown"
}

// auditLog logs a security event about an actor given a certain echo context
func auditLog(context echo.Context, actor string, event string) {
	auditContext := audit.Context(context.Request().Context(), actor, "tokenV2", "middleware")
	audit.Log(auditContext, log.Logger(), event)
}
