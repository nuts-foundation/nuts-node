/*
 * Copyright (C) 2024 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

package didx509

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// PolicyName represents the name of a policy in an X.509 DID (Decentralized Identifier).
type PolicyName string

// PolicyKey represents a key-value pair where 'name' specifies the policy name and 'key' identifies the specific attribute.
type PolicyKey struct {
	name PolicyName
	key  string
}

const (

	// PolicyNameSubject specifies that the policy is related to the subject attributes of an X.509 certificate.
	PolicyNameSubject PolicyName = "subject"

	// PolicyNameSan represents a policy for Subject Alternative Name (SAN) in an X.509 DID.
	PolicyNameSan PolicyName = "san"
)

var (

	// SubjectPolicySerialNumber represents the serial number attribute in the subject field of an X.509 certificate.
	SubjectPolicySerialNumber = PolicyKey{
		name: PolicyNameSubject,
		key:  "serialNumber",
	}

	// SubjectPolicyCommonName represents a policy key for the Common Name (CN) attribute in the subject of an X.509 certificate.
	SubjectPolicyCommonName = PolicyKey{
		name: PolicyNameSubject,
		key:  "CN",
	}

	// SubjectPolicyLocality represents the policy key for the subject's locality attribute in an X.509 certificate.
	SubjectPolicyLocality = PolicyKey{
		name: PolicyNameSubject,
		key:  "L",
	}

	// SubjectPolicyCountry defines the policy key for the country attribute of the subject in an X.509 certificate.
	SubjectPolicyCountry = PolicyKey{
		name: PolicyNameSubject,
		key:  "C",
	}

	// SubjectPolicyOrganization represents the policy key for the 'Organization' attribute in the subject of an X.509 certificate.
	SubjectPolicyOrganization = PolicyKey{
		name: PolicyNameSubject,
		key:  "O",
	}

	// SubjectPolicyOrganizationalUnit represents the policy key for the organizational unit (OU) attribute of the subject
	SubjectPolicyOrganizationalUnit = PolicyKey{
		name: PolicyNameSubject,
		key:  "OU",
	}

	// SubjectPolicyState represents the state or province attribute in the subject of an X.509 certificate.
	SubjectPolicyState = PolicyKey{
		name: PolicyNameSubject,
		key:  "ST",
	}

	// SubjectPolicyStreet is a PolicyKey for the 'streetAddress' attribute in the subject of an X.509 certificate.
	SubjectPolicyStreet = PolicyKey{
		name: PolicyNameSubject,
		key:  "STREET",
	}
)

var (

	// SanPolicyOtherName represents a policy key for the "otherName" attribute within the Subject Alternative Name (SAN) policy.
	SanPolicyOtherName = PolicyKey{
		name: PolicyNameSan,
		key:  "otherName",
	}

	// SanPolicyDNS represents a policy key for the 'dns' attribute in the Subject Alternative Name (SAN) extension of an X.509 certificate.
	SanPolicyDNS = PolicyKey{
		name: PolicyNameSan,
		key:  "dns",
	}

	// SanPolicyEmail is a PolicyKey for validating the email attribute within the Subject Alternative Name (SAN) of a certificate.
	SanPolicyEmail = PolicyKey{
		name: PolicyNameSan,
		key:  "email",
	}

	// SanPolicyIPAddress represents a policy key for IP address in Subject Alternative Name (SAN) validation.
	SanPolicyIPAddress = PolicyKey{
		name: PolicyNameSan,
		key:  "ip",
	}
)

var (

	// ErrDidMalformed indicates that the DID (Decentralized Identifier) is malformed and does not adhere to the expected format.
	ErrDidMalformed = errors.New("did:x509 is malformed")

	// ErrDidVersion indicates that the DID:x509 does not have version 0.
	ErrDidVersion = errors.New("did:x509 does not have version 0")

	// ErrDidPolicyMalformed indicates that the did:x509 policy is malformed.
	ErrDidPolicyMalformed = errors.New("did:x509 policy is malformed")

	// ErrUnkPolicyType indicates that the encountered policy type is unknown or unsupported.
	ErrUnkPolicyType = errors.New("unknown policy type")
)

// validationFunction defines a function type for validating specific attributes within an x509.Certificate.
type validationFunction func(cert *x509.Certificate, key string, value string) error

// validatorMap maps PolicyKey to their corresponding validation functions for certificate attributes.
var validatorMap = map[PolicyKey]validationFunction{
	SanPolicyOtherName: func(cert *x509.Certificate, key string, value string) error {
		nameValues, err := findOtherNameValues(cert)
		if err != nil {
			return err
		}
		if !slices.Contains(nameValues, value) {
			return fmt.Errorf("the SAN attribute %s does not match the query", key)
		}
		return nil
	},
	SanPolicyDNS: func(cert *x509.Certificate, key string, value string) error {
		if !slices.Contains(cert.DNSNames, value) {
			return fmt.Errorf("the SAN attribute %s does not match the query", key)
		}
		return nil
	},
	SanPolicyEmail: func(cert *x509.Certificate, key string, value string) error {
		if !slices.Contains(cert.EmailAddresses, value) {
			return fmt.Errorf("the SAN attribute %s does not match the query", key)
		}
		return nil
	},
	SanPolicyIPAddress: func(cert *x509.Certificate, key string, value string) error {
		ok := false
		for _, ip := range cert.IPAddresses {
			if ip.String() == value {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("the SAN attribute %s does not match the query", key)
		}
		return nil
	},
	SubjectPolicySerialNumber: func(cert *x509.Certificate, key string, value string) error {
		subject := cert.Subject
		if subject.SerialNumber != value {
			return fmt.Errorf("query does not match the subject : %s", key)
		}
		return nil
	},
	SubjectPolicyCommonName: func(cert *x509.Certificate, key string, value string) error {
		subject := cert.Subject
		if subject.CommonName != value {
			return fmt.Errorf("query does not match the subject : %s", key)
		}
		return nil
	},
	SubjectPolicyLocality: func(cert *x509.Certificate, key string, value string) error {
		subject := cert.Subject
		if !slices.Contains(subject.Locality, value) {
			return fmt.Errorf("query does not match the subject : %s", key)
		}
		return nil
	},
	SubjectPolicyCountry: func(cert *x509.Certificate, key string, value string) error {
		subject := cert.Subject
		if !slices.Contains(subject.Country, value) {
			return fmt.Errorf("query does not match the subject : %s", key)
		}
		return nil
	},
	SubjectPolicyState: func(cert *x509.Certificate, key string, value string) error {
		subject := cert.Subject
		if !slices.Contains(subject.Province, value) {
			return fmt.Errorf("query does not match the subject : %s", key)
		}
		return nil
	},
	SubjectPolicyStreet: func(cert *x509.Certificate, key string, value string) error {
		subject := cert.Subject
		if !slices.Contains(subject.StreetAddress, value) {
			return fmt.Errorf("query does not match the subject : %s", key)
		}
		return nil
	},
	SubjectPolicyOrganization: func(cert *x509.Certificate, key string, value string) error {
		subject := cert.Subject
		if !slices.Contains(subject.Organization, value) {
			return fmt.Errorf("query does not match the subject : %s", key)
		}
		return nil
	},
	SubjectPolicyOrganizationalUnit: func(cert *x509.Certificate, key string, value string) error {
		subject := cert.Subject
		if !slices.Contains(subject.OrganizationalUnit, value) {
			return fmt.Errorf("query does not match the subject : %s", key)
		}
		return nil
	},
}

// validatePolicy validates an X.509 certificate against a set of policies defined in X509DidReference.
func validatePolicy(ref *X509DidReference, cert *x509.Certificate) error {
	for _, policy := range ref.Policies {
		var err error
		switch policy.Name {
		case PolicyNameSubject, PolicyNameSan:
			err = validate(&policy, cert)
		default:
			err = ErrUnkPolicyType
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// validate checks if an X.509 certificate conforms to a given DID policy.
// Errors are returned if the policy is malformed, unknown, or if the certificate attributes don't match the policy requirements.
func validate(ref *X509DidPolicy, cert *x509.Certificate) error {

	keyValue := strings.Split(ref.Value, ":")
	if len(keyValue)%2 != 0 {
		return ErrDidPolicyMalformed
	}
	for i := 0; i < len(keyValue); i = i + 2 {
		key := keyValue[i]
		policyName := PolicyKey{
			name: ref.Name,
			key:  key,
		}
		value, err := url.QueryUnescape(keyValue[i+1])
		if err != nil {
			return err
		}
		f := validatorMap[policyName]
		if f == nil {
			return fmt.Errorf("unknown policy key: %s for policy: %s", policyName.key, policyName.name)
		}
		err = f(cert, string(key), value)
		if err != nil {
			return err
		}

	}
	return nil
}
