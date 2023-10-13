// Copyright (c) Jim Lambert
// SPDX-License-Identifier: MIT

package gldap

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMux_serve(t *testing.T) {
	t.Parallel()
	t.Run("no-matching-handler", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		buf := testSafeBuf(t)
		testLogger := hclog.New(&hclog.LoggerOptions{
			Name:   "TestServer_Run-logger",
			Level:  hclog.Debug,
			Output: buf,
		})
		s, err := NewServer(WithLogger(testLogger))
		require.NoError(err)
		port := freePort(t)
		go func() {
			err = s.Run(fmt.Sprintf(":%d", port))
			assert.NoError(err)
		}()
		defer func() { require.NoError(s.Stop()) }()
		for {
			time.Sleep(100 * time.Nanosecond)
			if s.Ready() {
				break
			}
		}
		client, err := ldap.DialURL(fmt.Sprintf("ldap://localhost:%d", port))
		require.NoError(err)
		defer client.Close()
		err = client.UnauthenticatedBind("alice")
		require.Error(err)
		assert.Contains(strings.ToLower(err.Error()), "no matching handler found")
	})
	t.Run("default-route", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		buf := &safeBuf{
			mu:  &sync.Mutex{},
			buf: &strings.Builder{},
		}
		testLogger := hclog.New(&hclog.LoggerOptions{
			Name:   "TestServer_Run-logger",
			Level:  hclog.Debug,
			Output: buf,
		})
		s, err := NewServer(WithLogger(testLogger))
		require.NoError(err)

		mux, err := NewMux()
		require.NoError(err)
		err = mux.DefaultRoute(func(w *ResponseWriter, req *Request) {
			resp := req.NewResponse(WithResponseCode(ResultUnwillingToPerform), WithDiagnosticMessage("default handler"))
			_ = w.Write(resp)
		})
		require.NoError(err)
		err = s.Router(mux)
		require.NoError(err)

		port := freePort(t)
		go func() {
			err = s.Run(fmt.Sprintf(":%d", port))
			assert.NoError(err)
		}()
		defer func() { _ = s.Stop() }()
		for {
			time.Sleep(100 * time.Nanosecond)
			if s.Ready() {
				break
			}
		}
		client, err := ldap.DialURL(fmt.Sprintf("ldap://localhost:%d", port))
		require.NoError(err)
		defer client.Close()
		err = client.UnauthenticatedBind("alice")
		require.Error(err)
		assert.Contains(strings.ToLower(err.Error()), "default handler")
	})
	t.Run("bad-parameters", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		m := &Mux{}
		assert.Panics(
			func() { m.serve(nil, &Request{}) },
			"missing response writer",
		)

		var writerBuf bytes.Buffer
		var logBuf bytes.Buffer
		testLogger := hclog.New(&hclog.LoggerOptions{
			Name:   "TestServer_Run-logger",
			Level:  hclog.Debug,
			Output: &logBuf,
		})
		w, err := newResponseWriter(bufio.NewWriter(&writerBuf), &sync.Mutex{}, testLogger, 1, 2)
		require.NoError(err)
		m.serve(w, nil)
		assert.Contains(logBuf.String(), "missing request")
	})
}

func TestMux_Delete(t *testing.T) {
	tests := []struct {
		name            string
		mux             *Mux
		fn              HandlerFunc
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "missing-fn",
			mux:             func() *Mux { m, err := NewMux(); require.NoError(t, err); return m }(),
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing HandlerFunc",
		},
		{
			name: "valid",
			mux:  func() *Mux { m, err := NewMux(); require.NoError(t, err); return m }(),
			fn:   func(*ResponseWriter, *Request) {},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			err := tc.mux.Delete(tc.fn)
			if tc.wantErr {
				require.Error(err)
				if tc.wantErrIs != nil {
					assert.ErrorIs(err, tc.wantErrIs)
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
		})
	}
}

func TestMux_Unbind(t *testing.T) {
	tests := []struct {
		name            string
		mux             *Mux
		fn              HandlerFunc
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "missing-fn",
			mux:             func() *Mux { m, err := NewMux(); require.NoError(t, err); return m }(),
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing HandlerFunc",
		},
		{
			name: "valid",
			mux:  func() *Mux { m, err := NewMux(); require.NoError(t, err); return m }(),
			fn:   func(*ResponseWriter, *Request) {},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			err := tc.mux.Unbind(tc.fn)
			if tc.wantErr {
				require.Error(err)
				if tc.wantErrIs != nil {
					assert.ErrorIs(err, tc.wantErrIs)
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
		})
	}
}
