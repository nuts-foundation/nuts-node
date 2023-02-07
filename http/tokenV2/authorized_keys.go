package tokenV2

import (
	b64 "encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/lestrrat-go/jwx/jwk"
)

// authorizedKey is an SSH authorized key
type authorizedKey struct {
        Key ssh.PublicKey
        Comment string
        Options []string
        JWK jwk.Key     
}               

// String returns a string representation of an authorized key 
func (a authorizedKey) String() string {
        return fmt.Sprintf("%v %v %v %v", a.Key.Type(), b64.RawStdEncoding.EncodeToString(a.Key.Marshal()), a.Comment, a.Options)         
}  

// jwkFromSSHKey converts a standard SSH library key to a JWX jwk.Key type
func jwkFromSSHKey(key ssh.PublicKey) (jwk.Key, error) {
	// Ensure the provided key implements the optional ssh.CryptoPublicKey interface, which
	// is able to return standard go crypto primitives. These primitives are needed to convert
	// the key into a JWX jwk key.
	var standardKey interface{}
	if cryptoPublicKey, ok := key.(ssh.CryptoPublicKey); ok {
		// Convert the ssh.PublicKey type to a go standard library crypto type (of unknown/interface{} type).
		standardKey = cryptoPublicKey.CryptoPublicKey()
	} else {
		return nil, fmt.Errorf("key %v does not implement the ssh.CryptoPublicKey interface and cannot be converted")
	}

	// Use the standard key type to create the jwk key type
	converted, err := jwk.New(standardKey)
	if err != nil {
		return nil, err
	}
        
        // On successful conversion also set the key ID
	if err := converted.Set(jwk.KeyIDKey, ssh.FingerprintSHA256(key)); err != nil {
		return nil, fmt.Errorf("failed to set key id: %v", err)
	}
        
        return converted, nil
}

// parseAuthorizedKeys parses the contents of an SSH authorized_keys file
// into data structures and usable crypto primitives
func parseAuthorizedKeys(contents []byte) ([]authorizedKey, error) {
        // Split the contents by read
        lines := strings.Split(string(contents), "\n")
        
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
                
                jwkPublicKey, err := jwkFromSSHKey(publicKey)
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

