// Copyright (c) Jim Lambert
// SPDX-License-Identifier: MIT

package gldap

import (
	"crypto/tls"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
)

func Test_WithLogger(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	opts := getConfigOpts(WithLogger(hclog.Default()))
	testOpts := configDefaults()
	testOpts.withLogger = hclog.Default()
	assert.Equal(opts, testOpts)
}

func Test_WithTLSConfig(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	opts := getConfigOpts(WithTLSConfig(&tls.Config{}))
	testOpts := configDefaults()
	testOpts.withTLSConfig = &tls.Config{}
	assert.Equal(opts, testOpts)
}

func Test_WithReadTimeout(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	timeout := 1 * time.Microsecond
	opts := getConfigOpts(WithReadTimeout(timeout))
	testOpts := configDefaults()
	testOpts.withReadTimeout = timeout
	assert.Equal(opts, testOpts)
}

func Test_WithWriteTimeout(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	timeout := 1 * time.Microsecond
	opts := getConfigOpts(WithWriteTimeout(timeout))
	testOpts := configDefaults()
	testOpts.withWriteTimeout = timeout
	assert.Equal(opts, testOpts)
}

func Test_WithDisablePanicRecovery(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	opts := getConfigOpts(WithDisablePanicRecovery())
	testOpts := configDefaults()
	testOpts.withDisablePanicRecovery = true
	assert.Equal(opts, testOpts)
}

func Test_WitOnClose(t *testing.T) {
	t.Parallel()
	fn := func(int) {}
	assert := assert.New(t)
	opts := getConfigOpts(WithOnClose(fn))
	testOpts := configDefaults()
	testOpts.withOnClose = fn
	assert.Equal(runtime.FuncForPC(reflect.ValueOf(opts.withOnClose).Pointer()).Name(),
		runtime.FuncForPC(reflect.ValueOf(testOpts.withOnClose).Pointer()).Name())
}
