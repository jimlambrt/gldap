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
