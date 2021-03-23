package net

import (
	"github.com/magiconair/properties/assert"
	"net/url"
	"testing"
)

func TestUnescapePathIfEscaped(t *testing.T) {
	assert.Equal(t, "abc", UnescapePathIfEscaped("abc"))
	assert.Equal(t, "a:b:c", UnescapePathIfEscaped("a:b:c"))
	assert.Equal(t, "a:b:c", UnescapePathIfEscaped(url.PathEscape("a:b:c")))
}
