// Copyright (c) Jim Lambert
// SPDX-License-Identifier: MIT

package gldap

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_WithLabel(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	opts := getRouteOpts(WithLabel("label"))
	testOpts := routeDefaults()
	testOpts.withLabel = "label"
	assert.Equal(opts, testOpts)
}

func Test_WithBaseDN(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	opts := getRouteOpts(WithBaseDN("baseDN"))
	testOpts := routeDefaults()
	testOpts.withBaseDN = "baseDN"
	assert.Equal(opts, testOpts)
}

func Test_WithFilter(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	opts := getRouteOpts(WithFilter("filter"))
	testOpts := routeDefaults()
	testOpts.withFilter = "filter"
	assert.Equal(opts, testOpts)
}

func Test_WithScope(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	opts := getRouteOpts(WithScope(SingleLevel))
	testOpts := routeDefaults()
	testOpts.withScope = SingleLevel
	assert.Equal(opts, testOpts)
}
