package gldap_test

import (
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
		Name:  "test-logger",
		Level: hclog.Error,
	})
	srvTLS, clientTLS := testdirectory.GetTLSConfig(t)
	t.Run("tls", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		s, err := gldap.NewServer(gldap.WithLogger(testLogger))
		require.NoError(err)
		require.NotNil(s)

		port := testdirectory.FreePort(t)

		go func() {
			s.Run(fmt.Sprintf(":%d", port), gldap.WithTLSConfig(srvTLS))
		}()
		t.Cleanup(func() { err := s.Stop(); assert.NoError(err) })
		// need a bit of a pause to get the service up and running, otherwise we'll
		// get a connection error because the service isn't listening yet.
		time.Sleep(10 * time.Millisecond)

		client, err := ldap.DialURL(fmt.Sprintf("ldaps://localhost:%d", port), ldap.DialWithTLSConfig(clientTLS))
		require.NoError(err)
		assert.NotNil(client)
		client.Close()
	})
	t.Run("open", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		s, err := gldap.NewServer(gldap.WithLogger(testLogger))
		require.NoError(err)
		require.NotNil(s)

		port := testdirectory.FreePort(t)

		go func() {
			s.Run(fmt.Sprintf(":%d", port))
		}()
		t.Cleanup(func() { err := s.Stop(); assert.NoError(err) })
		// need a bit of a pause to get the service up and running, otherwise we'll
		// get a connection error because the service isn't listening yet.
		time.Sleep(10 * time.Millisecond)

		// be sure to NOT use TLS for this "open" connection test
		client, err := ldap.DialURL(fmt.Sprintf("ldap://localhost:%d", port))
		require.NoError(err)
		assert.NotNil(client)
		client.Close()
	})
}
