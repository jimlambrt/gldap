package gldap

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_WithDiagnosticMessage(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	opts := getResponseOpts(WithDiagnosticMessage("msg"))
	testOpts := responseDefaults()
	testOpts.withDiagnosticMessage = "msg"
	assert.Equal(opts, testOpts)
}

func Test_WithMatchedDN(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	opts := getResponseOpts(WithMatchedDN("dn"))
	testOpts := responseDefaults()
	testOpts.withMatchedDN = "dn"
	assert.Equal(opts, testOpts)
}

func Test_WithResponseCode(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	opts := getResponseOpts(WithResponseCode(LDAPResultNoSuchOperation))
	testOpts := responseDefaults()
	testOpts.withResponseCode = intPtr(LDAPResultNoSuchOperation)
	assert.Equal(opts, testOpts)
}

func Test_WithApplicationCode(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	opts := getResponseOpts(WithApplicationCode(ApplicationAbandonRequest))
	testOpts := responseDefaults()
	testOpts.withApplicationCode = intPtr(ApplicationAbandonRequest)
	assert.Equal(opts, testOpts)
}

func Test_WithAttributes(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	attrs := map[string][]string{
		"email": {"alice@alice.com"},
	}
	opts := getResponseOpts(WithAttributes(attrs))
	testOpts := responseDefaults()
	testOpts.withAttributes = attrs
	assert.Equal(opts, testOpts)
}
