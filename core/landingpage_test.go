package core

import (
	"github.com/golang/mock/gomock"
	"testing"
)

func TestLandingPage_Routes(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	e := NewMockEchoRouter(ctrl)
	e.EXPECT().Add("GET", "/", gomock.Any())
	LandingPage{}.Routes(e)
}
