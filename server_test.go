// Copyright (c) Jim Lambert
// SPDX-License-Identifier: MIT

package gldap_test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/go-hclog"
	"github.com/jimlambrt/gldap"
	"github.com/jimlambrt/gldap/testdirectory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer_Run(t *testing.T) {
	t.Parallel()
	testLogger := hclog.New(&hclog.LoggerOptions{
		Name:  "TestServer_Run-logger",
		Level: hclog.Error,
	})
	srvTLS, clientTLS := testdirectory.GetTLSConfig(t)

	mtlsSrvTLS, mtlsClientTLS := testdirectory.GetTLSConfig(t, testdirectory.WithMTLS(t))

	tests := []struct {
		name            string
		srvTlS          *tls.Config
		clientTLS       *tls.Config
		urlScheme       string
		runOpts         []gldap.Option
		newOpts         []gldap.Option
		wantErr         bool
		wantErrContains string
	}{
		{
			name:      "tls",
			clientTLS: clientTLS,
			urlScheme: "ldaps",
			newOpts:   []gldap.Option{gldap.WithLogger(testLogger), gldap.WithDisablePanicRecovery()},
			runOpts:   []gldap.Option{gldap.WithTLSConfig(srvTLS)},
		},
		{
			name:      "open",
			urlScheme: "ldap",
			newOpts:   []gldap.Option{gldap.WithLogger(testLogger)},
		},
		{
			name:      "mtls",
			clientTLS: mtlsClientTLS,
			urlScheme: "ldaps",
			runOpts:   []gldap.Option{gldap.WithTLSConfig(mtlsSrvTLS)},
		},
		{
			name:            "read-timeout",
			srvTlS:          srvTLS,
			clientTLS:       clientTLS,
			urlScheme:       "ldaps",
			newOpts:         []gldap.Option{gldap.WithLogger(testLogger), gldap.WithReadTimeout(1 * time.Nanosecond)},
			runOpts:         []gldap.Option{gldap.WithTLSConfig(srvTLS)},
			wantErr:         true,
			wantErrContains: "Network Error",
		},
		{
			name:            "write-timeout",
			srvTlS:          srvTLS,
			clientTLS:       clientTLS,
			urlScheme:       "ldaps",
			newOpts:         []gldap.Option{gldap.WithLogger(testLogger), gldap.WithWriteTimeout(1 * time.Nanosecond)},
			runOpts:         []gldap.Option{gldap.WithTLSConfig(srvTLS)},
			wantErr:         true,
			wantErrContains: "Network Error",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			s, err := gldap.NewServer(tc.newOpts...)
			require.NoError(err)
			require.NotNil(s)

			port := testdirectory.FreePort(t)

			go func() {
				err = s.Run(fmt.Sprintf(":%d", port), tc.runOpts...)
				assert.NoError(err)
			}()
			t.Cleanup(func() { err := s.Stop(); assert.NoError(err) })
			for {
				time.Sleep(100 * time.Nanosecond)
				if s.Ready() {
					break
				}
			}

			var dialOpts []ldap.DialOpt
			if tc.clientTLS != nil {
				dialOpts = append(dialOpts, ldap.DialWithTLSConfig(tc.clientTLS))
			}
			client, err := ldap.DialURL(fmt.Sprintf("%s://localhost:%d", tc.urlScheme, port), dialOpts...)
			if tc.wantErr {
				require.Error(err)
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.NotNil(client)
			time.Sleep(2 * time.Millisecond)
			client.Close()
		})
	}
	t.Run("WithOnClose", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		wg := sync.WaitGroup{}
		wg.Add(1)
		closeCnt := 0
		testOnCloseFn := func(_ int) {
			closeCnt++
			wg.Done()
		}
		s, err := gldap.NewServer(gldap.WithOnClose(testOnCloseFn))
		require.NoError(err)
		require.NotNil(s)

		port := testdirectory.FreePort(t)

		go func() {
			err = s.Run(fmt.Sprintf(":%d", port), gldap.WithLogger(testLogger))
			assert.NoError(err)
		}()
		t.Cleanup(func() { err := s.Stop(); assert.NoError(err) })

		for {
			time.Sleep(100 * time.Nanosecond)
			if s.Ready() {
				break
			}
		}

		var dialOpts []ldap.DialOpt
		client, err := ldap.DialURL(fmt.Sprintf("%s://localhost:%d", "ldap", port), dialOpts...)
		require.NoError(err)
		assert.NotNil(client)
		client.Close()

		wg.Wait()
		assert.Equal(1, closeCnt)
	})
}

func TestServer_shutdownCtx(t *testing.T) {
	t.Parallel()
	t.Run("conn-serveRequests", func(t *testing.T) {
		// testing that conn.serveRequests properly handles checking the
		// shutdownCtx when handling requests for a conn
		l := hclog.New(&hclog.LoggerOptions{
			Name:  "TestServer_shutdownCtx-logger",
			Level: hclog.Error,
		})
		fakeT := &testdirectory.Logger{Logger: l}
		td := testdirectory.Start(fakeT, testdirectory.WithDefaults(t, &testdirectory.Defaults{AllowAnonymousBind: true}))
		time.Sleep(1 * time.Second) // allow time so the test directory will start up.
		go func() {
			certpool := x509.NewCertPool()
			certpool.AppendCertsFromPEM([]byte(td.Cert()))
			tlsConfig := &tls.Config{
				RootCAs: certpool,
			}
			conn, err := ldap.DialURL(fmt.Sprintf("ldaps://localhost:%d", td.Port()), ldap.DialWithTLSConfig(tlsConfig))
			if err != nil {
				return
			}
			defer conn.Close()
			for {
				err := conn.UnauthenticatedBind("alice")
				if err != nil {
					return
				}
			}
		}()
		go func() {
			// allow some time for inflight requests to get started
			time.Sleep(5 * time.Millisecond)
			td.Stop()
		}()
	})
}

func TestServer_Router(t *testing.T) {
	t.Parallel()
	testServer, err := gldap.NewServer()
	require.NoError(t, err)
	tests := []struct {
		name            string
		router          *gldap.Mux
		wantErr         bool
		wantErrContains string
	}{
		{
			name:   "valid-router",
			router: &gldap.Mux{},
		},
		{
			name:            "missing-router",
			wantErr:         true,
			wantErrContains: "missing router",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			err := testServer.Router(tc.router)
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
