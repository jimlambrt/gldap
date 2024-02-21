// Copyright (c) Jim Lambert
// SPDX-License-Identifier: MIT

package gldap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer_Stop(t *testing.T) {
	t.Parallel()
	var testLogger hclog.Logger
	if ok, _ := strconv.ParseBool(os.Getenv("DEBUG")); ok {
		testLogger = hclog.New(&hclog.LoggerOptions{
			Name:  "TestServer_Run-logger",
			Level: hclog.Debug,
		})
	}
	tests := []struct {
		name            string
		server          *Server
		wantErr         bool
		wantErrContains string
	}{
		{
			name: "missing-listener",
			server: func() *Server {
				s, err := NewServer(WithLogger(testLogger))
				require.NoError(t, err)
				s.mu.Lock()
				defer s.mu.Unlock()
				s.listener = nil
				return s
			}(),
		},
		{
			name: "missing-cancel",
			server: func() *Server {
				p := freePort(t)
				l, err := net.Listen("tcp", fmt.Sprintf(":%d", p))
				require.NoError(t, err)
				s, err := NewServer(WithLogger(testLogger))
				require.NoError(t, err)
				s.mu.Lock()
				defer s.mu.Unlock()
				s.listener = l
				s.shutdownCancel = nil
				return s
			}(),
		},
		{
			name: "nothing-to-do",
			server: func() *Server {
				s, err := NewServer(WithLogger(testLogger))
				require.NoError(t, err)
				s.mu.Lock()
				defer s.mu.Unlock()
				s.listener = nil
				s.shutdownCancel = nil
				return s
			}(),
		},
		{
			name: "listener-closed",
			server: func() *Server {
				_, cancel := context.WithCancel(context.Background())
				p := freePort(t)
				l, err := net.Listen("tcp", fmt.Sprintf(":%d", p))
				require.NoError(t, err)
				s, err := NewServer(WithLogger(testLogger))
				require.NoError(t, err)
				s.mu.Lock()
				defer s.mu.Unlock()
				s.listener = l
				s.shutdownCancel = cancel
				l.Close()
				return s
			}(),
		},
		{
			name: "listener-close-err",
			server: func() *Server {
				_, cancel := context.WithCancel(context.Background())
				s, err := NewServer(WithLogger(testLogger))
				require.NoError(t, err)
				s.mu.Lock()
				defer s.mu.Unlock()
				s.listener = &mockListener{}
				s.shutdownCancel = cancel
				return s
			}(),
			wantErr:         true,
			wantErrContains: "mockListener.Close error",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			err := tc.server.Stop()
			if tc.wantErr {
				require.Error(err)
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
		})
	}
}

type mockListener struct {
	net.Listener
}

func (*mockListener) Close() error {
	return errors.New("mockListener.Close error")
}

func TestValidateAddr(t *testing.T) {
	tests := []struct {
		name            string
		addr            string
		expected        string
		wantErrContains string
		wantErrIs       error
	}{
		{
			name:     "valid-IPv4-address",
			addr:     "127.0.0.1:389",
			expected: "127.0.0.1:389",
		},
		{
			name:     "valid-IPv6-address",
			addr:     "[::1]:389",
			expected: "[::1]:389",
		},
		{
			name:     "valid-IPv6",
			addr:     "2001:db8:3333:4444:5555:6666:7777:8888:389",
			expected: "2001:db8:3333:4444:5555:6666:7777:8888:389",
		},
		{
			name:     "valid-IPv6-localhost-without-brackets",
			addr:     "::1:389",
			expected: "[::1]:389",
		},
		{
			name:     "valid-hostname",
			addr:     "localhost:389",
			expected: "localhost:389",
		},
		{
			name:            "err-missing-port-final-colon",
			addr:            "198.165.1.1:",
			wantErrContains: "missing port in addr",
			wantErrIs:       ErrInvalidParameter,
		},
		{
			name:            "missing-port -pv4",
			addr:            "127.0.0.1",
			wantErrContains: "missing port in addr",
			wantErrIs:       ErrInvalidParameter,
		},
		{
			name:            "err-missing-port-ipv6",
			addr:            "[::1]",
			wantErrContains: "missing ']' in ipv6 address [::1]",
			wantErrIs:       ErrInvalidParameter,
		},
		{
			name:            "err-invalid-IPv4-address",
			addr:            "0.0",
			wantErrContains: "missing port in addr 0.0",
			wantErrIs:       ErrInvalidParameter,
		},
		{
			name:            "err-invalid-IPv6-address-missing-bracket",
			addr:            "[::1",
			wantErrContains: "missing ']' in ipv6 address [::1",
			wantErrIs:       ErrInvalidParameter,
		},
		{
			name:            "err-invalid-IPv6",
			addr:            "2001:db8:3333:4444:5555:6666:7777:389",
			wantErrContains: "invalid ipv6 address + port 2001:db8:3333:4444:5555:6666:7777:389",
			wantErrIs:       ErrInvalidParameter,
		},
		{
			name:            "err-missing-port",
			addr:            "invalid",
			expected:        "",
			wantErrContains: "missing port in addr invalid",
			wantErrIs:       ErrInvalidParameter,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			result, err := validateAddr(tc.addr)
			if tc.wantErrContains != "" {
				require.Error(t, err)
				assert.Empty(t, result)
				assert.Contains(t, err.Error(), tc.wantErrContains)
				if tc.wantErrIs != nil {
					assert.ErrorIs(t, err, tc.wantErrIs)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}
}
