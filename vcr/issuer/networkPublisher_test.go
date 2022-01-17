package issuer

import (
	"errors"
	"fmt"
	"github.com/golang/mock/gomock"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/doc"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_networkPublisher_resolveNutsCommServiceOwner(t *testing.T) {
	serviceID, _ := ssi.ParseURI(fmt.Sprintf("%s#1", vdr.TestDIDA.String()))
	expectedURIA, _ := ssi.ParseURI(fmt.Sprintf("%s/serviceEndpoint?type=NutsComm", vdr.TestDIDA.String()))
	service := did.Service{ID: *serviceID}

	t.Run("ok - correct did from service ID", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		sut := networkPublisher{}
		mockServiceResolver := doc.NewMockServiceResolver(ctrl)
		sut.serviceResolver = mockServiceResolver

		mockServiceResolver.EXPECT().Resolve(*expectedURIA, 5).Return(service, nil)

		serviceOwner, err := sut.resolveNutsCommServiceOwner(*vdr.TestDIDA)

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, vdr.TestDIDA, serviceOwner)
	})

	t.Run("error from resolver", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		sut := networkPublisher{}
		mockServiceResolver := doc.NewMockServiceResolver(ctrl)
		sut.serviceResolver = mockServiceResolver
		mockServiceResolver.EXPECT().Resolve(*expectedURIA, 5).Return(did.Service{}, errors.New("b00m!"))

		_, err := sut.resolveNutsCommServiceOwner(*vdr.TestDIDA)

		if !assert.Error(t, err) {
			return
		}
		assert.EqualError(t, err, "could not resolve NutsComm service owner: b00m!")
	})
}
