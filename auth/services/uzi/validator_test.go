/*
 * Nuts node
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
 */

package uzi

import (
	"errors"
	"fmt"
	"testing"

	"github.com/nuts-foundation/nuts-node/auth/services"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-node/auth/contract"
)

func TestUziValidator_VerifyVP(t *testing.T) {
	proofValue := "uziSignedProofValue123"

	vp := []byte(
		fmt.Sprintf(`{
  "@context": [ "https://www.w3.org/2018/credentials/v1" ],
  "type": ["VerifiablePresentation", "NutsUziPresentation", "OtherPresentation"],
  "proof": {
    "type": "NutsUziSignedContract",
    "proofValue": "%s"
  }
}`, proofValue))

	t.Run("ok - valid uzi signed VP", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		signedToken := services.NewMockSignedToken(ctrl)
		signedToken.EXPECT().SignerAttributes().Return(map[string]string{"name": "Henk de Vries"}, nil)
		signedToken.EXPECT().Contract().Return(contract.Contract{Params: map[string]string{"validFrom": "2020-12-10T13:57:00"}})

		tokenParser := services.NewMockVPProofValueParser(ctrl)
		tokenParser.EXPECT().Parse(proofValue).Return(signedToken, nil)
		tokenParser.EXPECT().Verify(gomock.Any()).Return(nil)
		uziVerifier := &Verifier{UziValidator: tokenParser}

		res, err := uziVerifier.VerifyVP(vp, nil)
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, res)
		assert.Equal(t, contract.Valid, res.Validity())
		assert.Equal(t, "Henk de Vries", res.DisclosedAttribute("name"))
		assert.Equal(t, "2020-12-10T13:57:00", res.ContractAttribute("validFrom"))
	})

	t.Run("nok - garbage input", func(t *testing.T) {
		uziVerifier := &Verifier{}
		res, err := uziVerifier.VerifyVP([]byte("123"), nil)
		if !assert.Error(t, err) {
			return
		}
		assert.Equal(t, "could not parse raw verifiable presentation: json: cannot unmarshal number into Go value of type uzi.verifiablePresentation", err.Error())
		assert.Nil(t, res)
	})

	t.Run("nok - missing proof", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		tokenParser := services.NewMockVPProofValueParser(ctrl)
		uziVerifier := &Verifier{UziValidator: tokenParser}

		vp := []byte(`{ "@context": [ "https://www.w3.org/2018/credentials/v1" ] }`)

		res, err := uziVerifier.VerifyVP(vp, nil)

		if !assert.Error(t, err) {
			return
		}
		assert.Equal(t, "could not verify empty proof", err.Error())

		assert.Nil(t, res)
	})

	t.Run("nok - wrong presentation type", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		vp := []byte(
			fmt.Sprintf(`{
  "@context": [ "https://www.w3.org/2018/credentials/v1" ],
  "type": ["VerifiablePresentation", "OtherPresentation"],
  "proof": {
    "type": "NutsUziSignedContract",
    "proofValue": "%s"
  }
}`, proofValue))

		tokenParser := services.NewMockVPProofValueParser(ctrl)
		uziVerifier := &Verifier{UziValidator: tokenParser}

		res, err := uziVerifier.VerifyVP(vp, nil)
		if !assert.Error(t, err) {
			return
		}
		assert.Equal(t, "could not verify this verification type: '[VerifiablePresentation OtherPresentation]', should contain type: NutsUziPresentation", err.Error())

		assert.Nil(t, res)

	})

	t.Run("nok - unparseable proof", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		tokenParser := services.NewMockVPProofValueParser(ctrl)
		tokenParser.EXPECT().Parse(proofValue).Return(nil, errors.New("could not parse"))
		uziVerifier := &Verifier{UziValidator: tokenParser}

		res, err := uziVerifier.VerifyVP(vp, nil)

		if !assert.Error(t, err) {
			return
		}
		assert.Equal(t, "could not verify verifiable presentation: could not parse the proof: could not parse", err.Error())

		assert.Nil(t, res)
	})

	t.Run("nok - unparseable signer attributes", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		signedToken := services.NewMockSignedToken(ctrl)
		signedToken.EXPECT().SignerAttributes().Return(nil, errors.New("could not parse certificate"))

		tokenParser := services.NewMockVPProofValueParser(ctrl)
		tokenParser.EXPECT().Parse(proofValue).Return(signedToken, nil)
		tokenParser.EXPECT().Verify(gomock.Any()).Return(nil)
		uziVerifier := &Verifier{UziValidator: tokenParser}

		res, err := uziVerifier.VerifyVP(vp, nil)

		if !assert.Error(t, err) {
			return
		}
		assert.Equal(t, "could not get disclosed attributes from signed contract: could not parse certificate", err.Error())

		assert.Nil(t, res)
	})

	t.Run("nok - invalid proof", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		signedToken := &services.MockSignedToken{}

		tokenParser := services.NewMockVPProofValueParser(ctrl)
		tokenParser.EXPECT().Parse(proofValue).Return(signedToken, nil)
		tokenParser.EXPECT().Verify(signedToken).Return(errors.New("invalid proof"))
		uziVerifier := &Verifier{UziValidator: tokenParser}

		res, err := uziVerifier.VerifyVP(vp, nil)
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, res)
		assert.Equal(t, contract.Invalid, res.Validity())
		assert.Empty(t, res.DisclosedAttributes())
		assert.Empty(t, res.ContractAttributes())
	})
}
