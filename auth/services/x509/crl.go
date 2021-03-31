package x509

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"net/http"
	"time"
)

// CRLGetter defines functions for a service that retrieves CRLs.
type CRLGetter interface {
	GetCRL(url string) (*pkix.CertificateList, error)
}

// Compiler check if HTTPCRLService implements the CRLGetter
var _ CRLGetter = (*HTTPCRLService)(nil)

// HTTPCRLService is a CRLGetter that retrieves CRLs over HTTP.
type HTTPCRLService struct {
}

// GetCRL accepts a url and will try to make a http request to that endpoint. The results will be parsed into a CertificateList.
// Note: The call is blocking. It is advisable to use this service behind a caching mechanism or use cachedHTTPCRLGetter
func (h HTTPCRLService) GetCRL(url string) (*pkix.CertificateList, error) {
	// TODO: this is a rather naive implementation of a http crl getter. It will not scale under high load and will
	// block requests when the crl endpoint is down.
	// https://github.com/nuts-foundation/nuts-node/auth/issues/136
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	} else if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("failed to retrieve CRL: '%s' statuscode: %s", url, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("could not read the crl response body: %w", err)
	}
	resp.Body.Close()

	return x509.ParseCRL(body)
}

var _ CRLGetter = (*memoryCRLService)(nil)

type memoryCRLService struct {
	crls map[string]*pkix.CertificateList
}

// newMemoryCRLService returns a CRL service that caches the CRLs in-memory.
func newMemoryCRLService() memoryCRLService {
	return memoryCRLService{
		crls: make(map[string]*pkix.CertificateList),
	}
}

func (m memoryCRLService) GetCRL(url string) (*pkix.CertificateList, error) {
	crl, ok := m.crls[url]
	if !ok {
		return nil, fmt.Errorf("unknown crl '%s'", url)
	}
	return crl, nil
}

var _ CRLGetter = (*cachedHTTPCRLGetter)(nil)

type cachedHTTPCRLGetter struct {
	httpCRLService   HTTPCRLService
	memoryCRLService memoryCRLService
}

// NewCachedHTTPCRLGetter returns a CRLGetter that retrieves CRLs over HTTP and caches them in-memory
func NewCachedHTTPCRLGetter() CRLGetter {
	return &cachedHTTPCRLGetter{
		httpCRLService:   HTTPCRLService{},
		memoryCRLService: newMemoryCRLService(),
	}
}

func (c *cachedHTTPCRLGetter) GetCRL(url string) (crl *pkix.CertificateList, err error) {
	expiredOrErr := true

	crl, err = c.memoryCRLService.GetCRL(url)
	if err == nil {
		expiredOrErr = crl.HasExpired(time.Now())
	}

	if expiredOrErr {
		crl, err = c.httpCRLService.GetCRL(url)
		if err == nil {
			c.memoryCRLService.crls[url] = crl
		}
	}
	return
}
