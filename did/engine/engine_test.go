/*
 * Nuts registry
 * Copyright (C) 2020. Nuts community
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
package engine

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"github.com/nuts-foundation/nuts-go-test/io"
	"github.com/spf13/cobra"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-crypto/pkg/cert"
	core "github.com/nuts-foundation/nuts-go-core"
	"github.com/nuts-foundation/nuts-registry/mock"
	"github.com/nuts-foundation/nuts-registry/pkg"
	"github.com/nuts-foundation/nuts-registry/pkg/db"
	"github.com/nuts-foundation/nuts-registry/pkg/events"
	"github.com/nuts-foundation/nuts-registry/pkg/events/domain"
	"github.com/nuts-foundation/nuts-registry/test"
	"github.com/stretchr/testify/assert"
)

func TestServer(t *testing.T) {
	configureIdentity()
	// Register test instance singleton
	pkg.NewTestRegistryInstance(io.TestDirectory(t))
	command := cmd()
	t.Run("SIGINT stops server", func(t *testing.T) {
		command.SetArgs([]string{"server"})
		go func() {
			println("Waiting for server to start...")
			for {
				conn, _ := net.Dial("tcp", pkg.DefaultRegistryConfig().Address)
				if conn != nil {
					println("Started!")
					conn.Close()
					break
				}
				time.Sleep(time.Second)
			}
			syscall.Kill(syscall.Getpid(), syscall.SIGINT)
		}()
		err := command.Execute()
		assert.NoError(t, err)
	})
}

func TestRegisterVendor(t *testing.T) {
	// Register test instance singleton
	pkg.NewTestRegistryInstance(io.TestDirectory(t))
	command := cmd()
	t.Run("ok", withMock(func(t *testing.T, client *mock.MockRegistryClient) {
		client.EXPECT().RegisterVendor(gomock.Any()).Return(events.CreateEvent(domain.RegisterVendor, domain.RegisterVendorEvent{}, nil), nil)
		command.SetArgs([]string{"register-vendor", "../test/certificate.pem"})
		err := command.Execute()
		assert.NoError(t, err)
	}))
	t.Run("error - file does not exist", withMock(func(t *testing.T, client *mock.MockRegistryClient) {
		command.SetArgs([]string{"register-vendor", "non-existent"})
		err := command.Execute()
		assert.EqualError(t, err, "open non-existent: no such file or directory")
	}))
	t.Run("error - invalid PEM", withMock(func(t *testing.T, client *mock.MockRegistryClient) {
		command.SetArgs([]string{"register-vendor", "../test/invalid.pem"})
		err := command.Execute()
		assert.EqualError(t, err, "found 28 rest bytes after decoding PEM: failed to decode PEM block containing certificate")
	}))
	t.Run("error - unable to register", withMock(func(t *testing.T, client *mock.MockRegistryClient) {
		client.EXPECT().RegisterVendor(gomock.Any()).Return(nil, errors.New("failed"))
		command.SetArgs([]string{"register-vendor", "../test/certificate.pem"})
		err := command.Execute()
		assert.EqualError(t, err, "failed")
	}))
}

func TestVendorClaim(t *testing.T) {
	// Register test instance singleton
	pkg.NewTestRegistryInstance(io.TestDirectory(t))
	command := cmd()
	orgID := test.OrganizationID("orgId")
	t.Run("ok", withMock(func(t *testing.T, client *mock.MockRegistryClient) {
		event := events.CreateEvent(domain.VendorClaim, domain.RegisterVendorEvent{}, nil)
		client.EXPECT().VendorClaim(orgID, "orgName", nil).Return(event, nil)
		command.SetArgs([]string{"vendor-claim", orgID.String(), "orgName"})
		err := command.Execute()
		assert.NoError(t, err)
	}))
	t.Run("error", withMock(func(t *testing.T, client *mock.MockRegistryClient) {
		client.EXPECT().VendorClaim(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("failed"))
		command.SetArgs([]string{"vendor-claim", orgID.String(), "orgName"})
		command.Execute()
	}))
}

func TestRefreshOrganizationCertificate(t *testing.T) {
	// Register test instance singleton
	pkg.NewTestRegistryInstance(io.TestDirectory(t))
	command := cmd()
	orgID := test.OrganizationID("123")
	t.Run("ok", withMock(func(t *testing.T, client *mock.MockRegistryClient) {
		event := events.CreateEvent(domain.VendorClaim, domain.VendorClaimEvent{OrgKeys: []interface{}{generateCertificate()}}, nil)
		client.EXPECT().RefreshOrganizationCertificate(orgID).Return(event, nil)
		command.SetArgs([]string{"refresh-organization-cert", orgID.String()})
		err := command.Execute()
		assert.NoError(t, err)
	}))
	t.Run("ok - no certs", withMock(func(t *testing.T, client *mock.MockRegistryClient) {
		event := events.CreateEvent(domain.VendorClaim, domain.VendorClaimEvent{}, nil)
		client.EXPECT().RefreshOrganizationCertificate(orgID).Return(event, nil)
		command.SetArgs([]string{"refresh-organization-cert", orgID.String()})
		err := command.Execute()
		assert.NoError(t, err)
	}))
	t.Run("error", withMock(func(t *testing.T, client *mock.MockRegistryClient) {
		client.EXPECT().RefreshOrganizationCertificate(orgID).Return(nil, errors.New("failed"))
		command.SetArgs([]string{"refresh-organization-cert", orgID.String()})
		command.Execute()
	}))
}

func TestVerify(t *testing.T) {
	// Register test instance singleton
	pkg.NewTestRegistryInstance(io.TestDirectory(t))
	t.Run("ok - fix data", withMock(func(t *testing.T, client *mock.MockRegistryClient) {
		client.EXPECT().Verify(true).Return(nil, false, nil)
		command := cmd()
		command.SetArgs([]string{"verify", "-f"})
		err := command.Execute()
		assert.NoError(t, err)
	}))
	t.Run("ok - nothing to do", withMock(func(t *testing.T, client *mock.MockRegistryClient) {
		client.EXPECT().Verify(false).Return(nil, false, nil)
		command := cmd()
		command.SetArgs([]string{"verify"})
		err := command.Execute()
		assert.NoError(t, err)
	}))

	t.Run("ok - data needs fixing", withMock(func(t *testing.T, client *mock.MockRegistryClient) {
		client.EXPECT().Verify(false).Return(nil, true, nil)
		command := cmd()
		command.SetArgs([]string{"verify"})
		err := command.Execute()
		assert.NoError(t, err)
	}))
	t.Run("ok - events emitted", withMock(func(t *testing.T, client *mock.MockRegistryClient) {
		client.EXPECT().Verify(true).Return([]events.Event{events.CreateEvent("foobar", struct{}{}, nil)}, true, nil)
		command := cmd()
		command.SetArgs([]string{"verify", "-f"})
		err := command.Execute()
		assert.NoError(t, err)
	}))
	t.Run("error", withMock(func(t *testing.T, client *mock.MockRegistryClient) {
		client.EXPECT().Verify(false).Return(nil, false, errors.New("failed"))
		command := cmd()
		command.SetArgs([]string{"verify"})
		err := command.Execute()
		assert.Error(t, err)
	}))
}

func TestRegisterEndpoint(t *testing.T) {
	// Register test instance singleton
	pkg.NewTestRegistryInstance(io.TestDirectory(t))
	command := cmd()
	var orgID, _ = core.ParsePartyID("urn:oid:1.2.3:foo")
	t.Run("ok - bare minimum parameters", withMock(func(t *testing.T, client *mock.MockRegistryClient) {
		event := events.CreateEvent(domain.RegisterEndpoint, domain.RegisterEndpointEvent{}, nil)
		client.EXPECT().RegisterEndpoint(orgID, "", "url", "type", db.StatusActive, map[string]string{}).Return(event, nil)
		command.SetArgs([]string{"register-endpoint", orgID.String(), "type", "url"})
		err := command.Execute()
		assert.NoError(t, err)
	}))
	t.Run("ok - all parameters", withMock(func(t *testing.T, client *mock.MockRegistryClient) {
		event := events.CreateEvent(domain.RegisterEndpoint, domain.RegisterEndpointEvent{}, nil)
		client.EXPECT().RegisterEndpoint(orgID, "id", "url", "type", db.StatusActive, map[string]string{"k1": "v1", "k2": "v2"}).Return(event, nil)
		command.SetArgs([]string{"register-endpoint", orgID.String(), "type", "url", "-i", "id", "-p", "k1=v1", "-p", "k2=v2"})
		err := command.Execute()
		assert.NoError(t, err)
	}))
	t.Run("error", withMock(func(t *testing.T, client *mock.MockRegistryClient) {
		client.EXPECT().RegisterEndpoint(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("failed"))
		command.SetArgs([]string{"register-endpoint", orgID.String(), "type", "url"})
		command.Execute()
	}))
}

func TestSearchOrg(t *testing.T) {
	// Register test instance singleton
	pkg.NewTestRegistryInstance(io.TestDirectory(t))
	command := cmd()
	t.Run("ok", withMock(func(t *testing.T, client *mock.MockRegistryClient) {
		client.EXPECT().SearchOrganizations("foo")
		command.SetArgs([]string{"search", "foo"})
		err := command.Execute()
		assert.NoError(t, err)
	}))
}

func TestPrintVersion(t *testing.T) {
	// Register test instance singleton
	pkg.NewTestRegistryInstance(io.TestDirectory(t))
	command := cmd()
	command.SetArgs([]string{"version"})
	err := command.Execute()
	assert.NoError(t, err)
}

func Test_flagSet(t *testing.T) {
	assert.NotNil(t, flagSet())
}

func TestNewRegistryEngine(t *testing.T) {
	// Register test instance singleton
	pkg.NewTestRegistryInstance(io.TestDirectory(t))
	t.Run("instance", func(t *testing.T) {
		assert.NotNil(t, NewRegistryEngine())
	})

	t.Run("configuration", func(t *testing.T) {
		e := NewRegistryEngine()
		cfg := core.NutsConfig()
		cfg.RegisterFlags(e.Cmd, e)
		assert.NoError(t, cfg.InjectIntoEngine(e))
	})
}

func withMock(test func(t *testing.T, client *mock.MockRegistryClient)) func(t *testing.T) {
	return func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		defer mockCtrl.Finish()
		registryClient := mock.NewMockRegistryClient(mockCtrl)
		registryClientCreator = func() pkg.RegistryClient {
			return registryClient
		}
		test(t, registryClient)
	}
}

func generateCertificate() map[string]interface{} {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	certAsBytes := test.GenerateCertificateEx(time.Now(), 1, privateKey)
	certificate, _ := x509.ParseCertificate(certAsBytes)
	certAsJWK, _ := cert.CertificateToJWK(certificate)
	certAsMap, _ := cert.JwkToMap(certAsJWK)
	return certAsMap
}

func configureIdentity() {
	os.Setenv("NUTS_IDENTITY", test.VendorID("4").String())
	core.NutsConfig().Load(&cobra.Command{})
}
