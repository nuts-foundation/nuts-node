package http

import (
	b64 "encoding/base64"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"

  	"github.com/nuts-foundation/nuts-node/http/log"

        "github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

func tokenv2Middleware(next echo.HandlerFunc) echo.HandlerFunc {
	content, err := os.ReadFile("authorized_keys")
	if err != nil {
		log.Logger().Fatalf("failed to read authorized_keys: %v", err)
	}

        authorizedKeys, err := parseAuthorizedKeys(string(content))
        if err != nil {
                log.Logger().Fatalf("failed to parse authorized_keys: %v", err)
        }
	log.Logger().Infof("loaded authorizedKeys: %v", authorizedKeys)

	return func(context echo.Context) error {
		for _, authorizedKey := range authorizedKeys {
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

		return &echo.HTTPError {
			Code: 401,
			Message: "Unauthorized",
			Internal: err,
		}
	}
}

type authorizedKey struct {
        Key ssh.PublicKey
        Comment string
        Options []string
        JWK jwk.Key     
}               
                
func (a authorizedKey) String() string {
        return fmt.Sprintf("%v %v %v %v", a.Key.Type(), b64.RawStdEncoding.EncodeToString(a.Key.Marshal()), a.Comment, a.Options)         
}  

func parseAuthorizedKeys(contents string) ([]authorizedKey, error) {
        // Split the contents by read
        lines := strings.Split(contents, "\n")
        
        // Loop over each line in the authorized_keys file
        var authorizedKeys []authorizedKey
        for _, line := range lines {
                // Trim leading and trailing whitespace
                line = strings.TrimLeft(line, " \t")
                line = strings.TrimRight(line, " \t")
                
                // Skip empty lines
                if line == "" {
                        continue
                }       
                
                // Parse this single authorized key entry
                publicKey, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(line))
                if err != nil {
                        return nil, fmt.Errorf("unparseable line (%v): %v", line, err)
                }       
                
                // Ensure rest is empty, meaning the entire line was parsed
                if rest != nil {
                        return nil, fmt.Errorf("line not completely parseable: %v: rest=%v", line, string(rest))
                }       
                
                jwkPublicKey, err := jwkKeyFromSSHKey(publicKey)
                if err != nil {
                        return nil, err
                }       
                
                authorizedKeys = append(authorizedKeys, authorizedKey{
                        Key: publicKey,
                        Comment: comment,
                        Options: options,
                        JWK: jwkPublicKey,
                })      
        }       
        
        return authorizedKeys, nil
}

func jwkKeyFromSSHKey(key ssh.PublicKey) (jwk.Key, error) {
        jwkKey, err := jwk.New(key.(ssh.CryptoPublicKey).CryptoPublicKey())
        
        // On successful conversion also set the key ID
        if err == nil {
                if err := jwkKey.Set(jwk.KeyIDKey, ssh.FingerprintSHA256(key)); err != nil {
                        return nil, fmt.Errorf("failed to set key id: %v", err)
                }
        }
        
        return jwkKey, err
}

