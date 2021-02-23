package test

import (
	"fmt"
	"github.com/golang/mock/gomock"
	"strings"
)

func Contains(needle string) gomock.Matcher {
	return &containsMatcher{needle: needle}
}

type containsMatcher struct {
	needle string
}

func (c containsMatcher) Matches(x interface{}) bool {
	return strings.Contains(fmt.Sprintf("%s", x), c.needle)
}

func (c containsMatcher) String() string {
	return "contains string: " + c.needle
}
