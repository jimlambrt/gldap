package gldap

import (
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_getGeneralOpts(t *testing.T) {
	testWriter := new(strings.Builder)

	tests := []struct {
		name string
		opts []Option
		want interface{}
	}{
		{
			name: "nil-opt",
			opts: []Option{nil},
			want: generalDefaults(),
		},
		{
			name: "simple",
			opts: []Option{WithWriter(testWriter)},
			want: generalOptions{
				withWriter: testWriter,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			opts := getGeneralOpts(tc.opts...)
			assert.Equal(tc.want, opts)
		})
	}
}

func Test_isNil(t *testing.T) {
	var testWriter io.Writer
	testWriter = new(strings.Builder)
	tests := []struct {
		name string
		i    interface{}
		want bool
	}{
		{
			name: "nil",
			want: true,
		},
		{
			name: "not-nil",
			i:    new(strings.Builder),
			want: false,
		},
		{
			name: "not-nil-interface",
			i:    testWriter,
			want: false,
		},
		{
			name: "not-nil-struct",
			i:    generalDefaults(),
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			got := isNil(tc.i)
			assert.Equal(tc.want, got)
		})
	}
}
