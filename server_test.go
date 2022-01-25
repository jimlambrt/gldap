package gldap_test

import (
	"crypto/tls"
	"fmt"
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
				s.Run(fmt.Sprintf(":%d", port), tc.runOpts...)
			}()
			t.Cleanup(func() { err := s.Stop(); assert.NoError(err) })
			// need a bit of a pause to get the service up and running, otherwise we'll
			// get a connection error because the service isn't listening yet.
			time.Sleep(10 * time.Millisecond)

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
}

func TestServer_shutdownCtx(t *testing.T) {
	t.Run("conn-serveRequests", func(t *testing.T) {
		// testing that conn.serveRequests properly handles checking the
		// shutdownCtx when handling requests for a conn
		l := hclog.New(&hclog.LoggerOptions{
			Name:  "TestServer_shutdownCtx-logger",
			Level: hclog.Error,
		})
		fakeT := &testdirectory.Logger{Logger: l}
		td := testdirectory.Start(fakeT, testdirectory.WithDefaults(t, &testdirectory.Defaults{AllowAnonymousBind: true}))
		time.Sleep(5 * time.Millisecond)
		go func() {
			client := td.Conn()
			defer client.Close()
			for {
				err := client.UnauthenticatedBind("alice")
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
