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
	t.Run("no-matching-handler", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		var buf bytes.Buffer
		testLogger := hclog.New(&hclog.LoggerOptions{
			Name:   "TestServer_Run-logger",
			Level:  hclog.Debug,
			Output: &buf,
		})
		s, err := NewServer(WithLogger(testLogger))
		require.NoError(err)
		port := freePort(t)
		go func() {
			err = s.Run(fmt.Sprintf(":%d", port))
			assert.NoError(err)
		}()
		defer s.Stop()
		time.Sleep(1 * time.Millisecond)
		client, err := ldap.DialURL(fmt.Sprintf("ldap://localhost:%d", port))
		require.NoError(err)
		defer client.Close()
		err = client.UnauthenticatedBind("alice")
		require.Error(err)
		assert.Contains(strings.ToLower(err.Error()), "no matching handler found")
	})
	t.Run("default-route", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		var buf bytes.Buffer
		testLogger := hclog.New(&hclog.LoggerOptions{
			Name:   "TestServer_Run-logger",
			Level:  hclog.Debug,
			Output: &buf,
		})
		s, err := NewServer(WithLogger(testLogger))
		require.NoError(err)

		mux, err := NewMux()
		require.NoError(err)
		mux.DefaultRoute(func(w *ResponseWriter, req *Request) {
			resp := req.NewResponse(WithResponseCode(ResultUnwillingToPerform), WithDiagnosticMessage("default handler"))
			_ = w.Write(resp)
		})
		s.Router(mux)

		port := freePort(t)
		go func() {
			err = s.Run(fmt.Sprintf(":%d", port))
			assert.NoError(err)
		}()
		defer s.Stop()
		time.Sleep(1 * time.Millisecond)
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
