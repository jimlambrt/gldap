package gldap

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_WithDescription(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	opts := getTestOpts(WithDescription("desc"))
	testOpts := testDefaults()
	testOpts.withDescription = "desc"
	assert.Equal(opts, testOpts)
}
