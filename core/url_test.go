package core

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestJoinURLPaths(t *testing.T) {
	assert.Equal(t, "http://example.com/path", JoinURLPaths("http://example.com", "/path"))
	assert.Equal(t, "http://example.com/path", JoinURLPaths("http://example.com", "path"))
	assert.Equal(t, "http://example.com/path", JoinURLPaths("http://example.com/", "/path"))
	assert.Equal(t, "http://example.com/path/", JoinURLPaths("http://example.com/", "/path/"))
	assert.Equal(t, "http://example.com", JoinURLPaths("http://example.com"))
	assert.Equal(t, "", JoinURLPaths())
}
