/*
 * Copyright (C) 2021 Nuts community
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

package x509

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/nuts-foundation/nuts-node/pki"
)

const uziSignedJwt = `eyJ4NWMiOlsiTUlJSGN6Q0NCVnVnQXdJQkFnSVVIUFU4cVZYS3FEZXByWUhDQ1dLQmkrdkp0Vll3RFFZSktvWklodmNOQVFFTEJRQXdhakVMTUFrR0ExVUVCaE1DVGt3eERUQUxCZ05WQkFvTUJFTkpRa2N4RnpBVkJnTlZCR0VNRGs1VVVrNU1MVFV3TURBd05UTTFNVE13TVFZRFZRUUREQ3BVUlZOVUlGVmFTUzF5WldkcGMzUmxjaUJOWldSbGQyVnlhMlZ5SUc5d0lHNWhZVzBnUTBFZ1J6TXdIaGNOTWpBd056RTNNVEl6TkRFNVdoY05Nak13TnpFM01USXpOREU1V2pDQmhURUxNQWtHQTFVRUJoTUNUa3d4SURBZUJnTlZCQW9NRjFURHFYTjBJRnB2Y21kcGJuTjBaV3hzYVc1bklEQXpNUll3RkFZRFZRUUVEQTEwWlhOMExUa3dNREUzT1RRek1Rd3dDZ1lEVlFRcURBTktZVzR4RWpBUUJnTlZCQVVUQ1Rrd01EQXlNVEl4T1RFYU1CZ0dBMVVFQXd3UlNtRnVJSFJsYzNRdE9UQXdNVGM1TkRNd2dnRWlNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUUNoVFloUEE3WDBTNWNWQnhHYzdHWi81RHZxSWVzaWowYUpadllMcVhrRmkzOU5EQjRLSDM4c3JIbHRGVWYyOVF3YlBSUm9KOEJJYXpFTnhkdTg4WUQvZXBKSGhmOUhpMkx1UGhoZmdSU3FjSnp4dDNPYStKME91YzdnZzBZaytnV01USkJ5R2ZSYlRQR3V5eVFFMnJOUFJteDRoOUNLSDZiNHVZam1ESDJWdXlhM3BtY0UrR2wxbmUvQnJjYnRsSmpCa2d6Vkw2cmVTYzdPUXhvbi9ZbmFRanhvakJpZ2xhT0hub2JESU9tczluQkZFQ29uUzVKNGZvb1VRVTg3anFMSGlHckJNL2xNdHlaOUVrblhGQ3U2U3VRb3ZDNlR1eUZ2c0JnT0MyNzNGZ0JaR2VybHkzbTFEVXczTlROUG15dlJEUXREWEJHTi9BVkVJLzR4VGdGL0FnTUJBQUdqZ2dMek1JSUM3ekJSQmdOVkhSRUVTakJJb0VZR0ExVUZCYUEvRmoweUxqRTJMalV5T0M0eExqRXdNRGN1T1RrdU1qRTRMVEV0T1RBd01ESXhNakU1TFU0dE9UQXdNREF6T0RJdE1EQXVNREF3TFRBd01EQXdNREF3TUF3R0ExVWRFd0VCL3dRQ01BQXdId1lEVlIwakJCZ3dGb0FVeWZBR0RwTGZOaThJZFRpODMrNUJlYkpkd0Y4d2dhc0dDQ3NHQVFVRkJ3RUJCSUdlTUlHYk1Hc0dDQ3NHQVFVRkJ6QUNobDlvZEhSd09pOHZkM2QzTG5WNmFTMXlaV2RwYzNSbGNpMTBaWE4wTG01c0wyTmhZMlZ5ZEhNdk1qQXhPVEExTURGZmRHVnpkRjkxZW1rdGNtVm5hWE4wWlhKZmJXVmtaWGRsY210bGNsOXZjRjl1WVdGdFgyTmhYMmN6TG1ObGNqQXNCZ2dyQmdFRkJRY3dBWVlnYUhSMGNEb3ZMMjlqYzNBdWRYcHBMWEpsWjJsemRHVnlMWFJsYzNRdWJtd3dnZ0VHQmdOVkhTQUVnZjR3Z2Zzd2dmZ0dDV0NFRUFHSGIyT0JWRENCNmpBL0JnZ3JCZ0VGQlFjQ0FSWXphSFIwY0hNNkx5OWhZMk5sY0hSaGRHbGxMbnB2Y21kamMzQXVibXd2WTNCekwzVjZhUzF5WldkcGMzUmxjaTVvZEcxc01JR21CZ2dyQmdFRkJRY0NBakNCbVF5QmxrTmxjblJwWm1sallXRjBJSFZwZEhOc2RXbDBaVzVrSUdkbFluSjFhV3RsYmlCMFpXNGdZbVZvYjJWMlpTQjJZVzRnWkdVZ1ZFVlRWQ0IyWVc0Z2FHVjBJRlZhU1MxeVpXZHBjM1JsY2k0Z1NHVjBJRlZhU1MxeVpXZHBjM1JsY2lCcGN5QnBiaUJuWldWdUlHZGxkbUZzSUdGaGJuTndjbUZyWld4cGFtc2dkbTl2Y2lCbGRtVnVkSFZsYkdVZ2MyTm9ZV1JsTGpBZkJnTlZIU1VFR0RBV0JnZ3JCZ0VGQlFjREJBWUtLd1lCQkFHQ053b0REREJqQmdOVkhSOEVYREJhTUZpZ1ZxQlVobEpvZEhSd09pOHZkM2QzTG5WNmFTMXlaV2RwYzNSbGNpMTBaWE4wTG01c0wyTmtjQzkwWlhOMFgzVjZhUzF5WldkcGMzUmxjbDl0WldSbGQyVnlhMlZ5WDI5d1gyNWhZVzFmWTJGZlp6TXVZM0pzTUIwR0ExVWREZ1FXQkJTWTBkclhRMEpINmhIdi9zejFTK3lyakVoU1F6QU9CZ05WSFE4QkFmOEVCQU1DQmtBd0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dJQkFGMDdXWmhoNkx5ZWdjMjJscDIwb0x5K2tnUlB3Ti9TL0lTdkxGVEY0RFBBSTY2RmtVSnNGUmFmbXVhMFpsL0JPZ2U1SXZwMHM5dEVqaHBaMTZYNGVZQm1qOE1VMHhBTjM0OC9PakFtSUZTR0l1d2kxU2RyendIUnF2VUxmMHNWcXZUOEpEVTZkMHEvaVBPRThEYU9OWXppbUlkZ1dFOXBOODhBb1ptT3VkSDQzSjk3WkRnMXYrWnU3NnMwdFI4WXpXSElUVDEvbmJRbDUzeU9mR3dER1RSdk42T1hkelBMVXpUbGhmdEdYZUZPRmNrb0Q4c2NRTGFaV1loQTVaVDRxLzlncE02WXU1TTMzWVJ0empGek4yTWVWaFpsUmV5NUY1NmVWcDV6MkM0U3NnM2FCemkyandnRzExY3pvMVBGdldod21zckNTTFpJUHdhWFduQ3hnYW5FZkxzeXVKcmpuVXYyUXdaeldCT1VoRjhSN2FtUk9xUHN6VGJwNE9yZWUyWmFyc04wYzNSLzdYdmJvcVdhb3NRa3Q1MFlxOHpCQ0Z4clFMZkZKN1pUcEhHWENEQmtzcVg4WWVrZ2RxdDhIMmdSS2p2OVNLY2RjejA0a2VJUEIyRU85K2ZQTHcwckZqRGVLdFFjYmRXTDlFSHRNOHAwcXBmTHNLcUdqbXdSdHhYbVRYUHNVS0FKQ1RKdWI4cnVRZVpsQlhZVC91YjNEMER1RzB2YUlNcjE3aDZydEdYR1hDWFV2VUxYMzBnczFyS3VUVkZkR0xFRUdid3JHbFVUZUdHRXFQbU4xdWFmNWpEdkR1UDE5R2RTV0VZMW4xTjYvV1paODhVS2ZnZHpxSVlKemt1RzV6bGZLUWdEREJvZXNyd3BCZXlkTXo0M0diZEZieS8zUm9MNSJdLCJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJtZXNzYWdlIjoiTkw6QmVoYW5kZWxhYXJMb2dpbjp2MSBPbmRlcmdldGVrZW5kZSBnZWVmdCB0b2VzdGVtbWluZyBhYW4gRGVtbyBFSFIgb20gbmFtZW5zIHZlcnBsZWVnaHVpcyBEZSBub290amVzIGVuIG9uZGVyZ2V0ZWtlbmRlIGhldCBOdXRzIG5ldHdlcmsgdGUgYmV2cmFnZW4uIERlemUgdG9lc3RlbW1pbmcgaXMgZ2VsZGlnIHZhbiBkaW5zZGFnLCAxIG9rdG9iZXIgMjAxOSAxMzozMDo0MiB0b3QgZGluc2RhZywgMSBva3RvYmVyIDIwMTkgMTQ6MzA6NDIuIiwiaWF0IjoxNjA0MzE3ODg5fQ.FMekUy0UoOwhbEciJ9Q1TESh7fE-MQuUEZI5M65RuwtTlPlqN2P1KGFel8FDh42k2R79S8RB4x1XF0UkZtu8YOkNqFuX2h5Ow3xhaAquHR3iqzJy8wBKo0ZnctPDSJGfn0k-UzF9MS6665JuDAnvE5ETop1ASou2lPC6885Rh8QRxBDSKz48pHsLh2oQrn7Qs5BfhHMgkDrwnPrN1tIhyKPNvbhFvy7nYbrdKg6O3W8xK9jHyES7ts_ahkI3GYH9nOa2VhX3lySLzsY3qH5NPDNCj3IE1St6Ab4rm7RfCQ8tWVRf0qQG1X0bALgCNMY8ALUrIoUUn4zxpAGCNRBmig`

func TestNewUziValidator(t *testing.T) {
	t.Run("production certificates", func(t *testing.T) {
		truststore, err := LoadUziTruststore(UziProduction)
		require.NoError(t, err)

		_, err = NewUziValidator(truststore, &contract.StandardContractTemplates, pki.New())
		require.NoError(t, err)
	})

	t.Run("acceptation certificates", func(t *testing.T) {
		truststore, err := LoadUziTruststore(UziAcceptation)
		require.NoError(t, err)

		_, err = NewUziValidator(truststore, &contract.StandardContractTemplates, pki.New())
		require.NoError(t, err)
	})
}

func TestUziValidator_SignedAttributes(t *testing.T) {
	cert := &x509.Certificate{}

	asnName, err := asn1.Marshal("0-1-2-3-4-5-6")
	assert.NoError(t, err)

	asnNames, err := asn1.Marshal(generalNames{
		OtherName: otherName{
			OID: asn1.ObjectIdentifier{1, 1, 1, 1},
			Value: asn1.RawValue{
				Class: asn1.ClassContextSpecific,
				Bytes: asnName,
			},
		},
	})
	assert.NoError(t, err)

	cert.Extensions = append(cert.Extensions, pkix.Extension{
		Id:    subjectAltNameID,
		Value: asnNames,
	})

	uziToken := UziSignedToken{
		jwtX509Token: &JwtX509Token{chain: []*x509.Certificate{cert}},
		contract:     &contract.Contract{},
	}

	attr, err := uziToken.SignerAttributes()

	assert.NoError(t, err)
	assert.Equal(t, map[string]string{
		"oidCa":    "0",
		"version":  "1",
		"uziNr":    "2",
		"cardType": "3",
		"orgID":    "4",
		"roleCode": "5",
		"agbCode":  "6",
	}, attr)
}

func TestUziValidator(t *testing.T) {
	t.Skip("Still uses v1 contract, migrate to v3")

	t.Run("ok - acceptation environment", func(t *testing.T) {
		truststore, err := LoadUziTruststore(UziAcceptation)
		require.NoError(t, err)
		uziValidator, err := NewUziValidator(truststore, &contract.StandardContractTemplates, pki.New())
		require.NoError(t, err)

		signedToken, err := uziValidator.Parse(uziSignedJwt)

		require.NoError(t, err)
		require.Implements(t, (*services.SignedToken)(nil), signedToken)

		expected := map[string]string{
			"agbCode":  "00000000",
			"cardType": "N",
			"oidCa":    "2.16.528.1.1007.99.218", // CIBG.Uzi test identifiers
			"orgID":    "90000382",
			"roleCode": "00.000",
			"uziNr":    "900021219",
			"version":  "1",
		}
		attrs, err := signedToken.SignerAttributes()

		assert.NoError(t, err)
		assert.Equal(t, expected, attrs)
		assert.Equal(t, contract.Type("BehandelaarLogin"), signedToken.Contract().Template.Type)
		assert.Equal(t, contract.Language("NL"), signedToken.Contract().Template.Language)
		assert.Equal(t, contract.Version("v1"), signedToken.Contract().Template.Version)

		err = uziValidator.Verify(signedToken)
		assert.NoError(t, err)
	})
}
