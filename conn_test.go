package gldap

import (
	"bytes"
	"context"
	"net"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_newConn(t *testing.T) {
	testCtx := context.Background()

	server, client := net.Pipe()
	t.Cleanup(func() { server.Close(); client.Close() })

	var buf bytes.Buffer
	testLogger := hclog.New(&hclog.LoggerOptions{
		Name:   "test",
		Output: &buf,
	})

	tests := map[string]struct {
		ctx             context.Context
		id              int
		netConn         net.Conn
		logger          hclog.Logger
		router          *Mux
		want            *conn
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		"missing-ctx": {
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing shutdown context",
		},
		"missing-id": {
			ctx:             testCtx,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing connection id",
		},
		"missing-conn": {
			ctx:             testCtx,
			id:              1,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing connection",
		},
		"missing-logger": {
			ctx:             testCtx,
			id:              1,
			netConn:         server,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing logger",
		},
		"missing-router": {
			ctx:             testCtx,
			id:              1,
			netConn:         server,
			logger:          testLogger,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing router",
		},
		"success": {
			ctx:     testCtx,
			id:      1,
			netConn: server,
			logger:  testLogger,
			router:  &Mux{},
			want: &conn{
				shutdownCtx: testCtx,
				connID:      1,
				netConn:     server,
				logger:      testLogger,
				router:      &Mux{},
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := newConn(tc.ctx, tc.id, tc.netConn, tc.logger, tc.router)
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
			assert.NotNil(got)
			assert.NotEmpty(got.reader)
			assert.NotEmpty(got.writer)
			tc.want.reader = got.reader
			tc.want.writer = got.writer
			assert.Equal(tc.want, got)
		})
	}
}

func Test_initConn(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() { server.Close(); client.Close() })
	tests := map[string]struct {
		c               *conn
		netConn         net.Conn
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		"missing-conn": {
			c:               &conn{},
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing net conn",
		},
		"success": {
			c:       &conn{},
			netConn: server,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			err := tc.c.initConn(tc.netConn)
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
			assert.NotEmpty(tc.c.reader)
			assert.NotEmpty(tc.c.writer)
		})
	}
}
