package didx509

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

type PolicyName string
type PolicyKey struct {
	name PolicyName
	key  string
}

const (
	PolicyNameSubject PolicyName = "subject"
	PolicyNameSan     PolicyName = "san"
)

var (
	SubjectPolicySerialNumber = PolicyKey{
		name: PolicyNameSubject,
		key:  "serialNumber",
	}
	SubjectPolicyCommonName = PolicyKey{
		name: PolicyNameSubject,
		key:  "CN",
	}
	SubjectPolicyLocality = PolicyKey{
		name: PolicyNameSubject,
		key:  "L",
	}
	SubjectPolicyCountry = PolicyKey{
		name: PolicyNameSubject,
		key:  "C",
	}
	SubjectPolicyOrganization = PolicyKey{
		name: PolicyNameSubject,
		key:  "O",
	}
	SubjectPolicyOrganizationalUnit = PolicyKey{
		name: PolicyNameSubject,
		key:  "OU",
	}
	SubjectPolicyState = PolicyKey{
		name: PolicyNameSubject,
		key:  "ST",
	}
	SubjectPolicyStreet = PolicyKey{
		name: PolicyNameSubject,
		key:  "STREET",
	}
)

var (
	SanPolicyOtherName = PolicyKey{
		name: PolicyNameSan,
		key:  "otherName",
	}
	SanPolicyDNS = PolicyKey{
		name: PolicyNameSan,
		key:  "dns",
	}
	SanPolicyEmail = PolicyKey{
		name: PolicyNameSan,
		key:  "email",
	}
	SanPolicyIPAddress = PolicyKey{
		name: PolicyNameSan,
		key:  "ip",
	}
)

var (
	ErrDidMalformed       = errors.New("did:x509 is malformed")
	ErrDidVersion         = errors.New("did:x509 does not have version 0")
	ErrDidPolicyMalformed = errors.New("did:x509 policy is malformed")
	ErrUnkPolicyType      = errors.New("unknown policy type")
)

type validationFunction func(cert *x509.Certificate, key string, value string) error

// validatorMap maps PolicyKey to their corresponding validation functions for certificate attributes.
var validatorMap = map[PolicyKey]validationFunction{
	SanPolicyOtherName: func(cert *x509.Certificate, key string, value string) error {
		nameValue, err := findOtherNameValue(cert)
		if err != nil {
			return err
		}
		if nameValue != value {
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

// ValidatePolicy validates a certificate against a given X509DidReference and its policies.
func ValidatePolicy(ref *X509DidReference, cert *x509.Certificate) error {
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

// validate checks if the given certificate adheres to the policy defined by the X509DidReference.
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
