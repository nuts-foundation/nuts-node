package core

import (
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestLandingPage_Routes(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	e := NewMockEchoRouter(ctrl)
	e.EXPECT().Add("GET", "/", gomock.Any())
	LandingPage{}.Routes(e)
}

func TestLandingPage_load(t *testing.T) {
	contents, err := LandingPage{}.load()
	assert.NoError(t, err)
	assert.Contains(t, contents, "<html>")
}
