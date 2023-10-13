// Copyright (c) Jim Lambert
// SPDX-License-Identifier: MIT

package gldap

import (
	"bufio"
	"bytes"
	"io"
	"sync"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_newResponseWriter(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	tests := []struct {
		name            string
		writer          *bufio.Writer
		wLock           *sync.Mutex
		logger          hclog.Logger
		connID          int
		requestID       int
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "missing-writer",
			wLock:           &sync.Mutex{},
			logger:          hclog.Default(),
			connID:          1,
			requestID:       1,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing writer",
		},
		{
			name:            "missing-lock",
			writer:          bufio.NewWriter(&buf),
			logger:          hclog.Default(),
			connID:          1,
			requestID:       1,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing writer lock",
		},
		{
			name:            "missing-logger",
			writer:          bufio.NewWriter(&buf),
			wLock:           &sync.Mutex{},
			connID:          1,
			requestID:       1,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing logger",
		},
		{
			name:            "missing-connID",
			writer:          bufio.NewWriter(&buf),
			wLock:           &sync.Mutex{},
			logger:          hclog.Default(),
			requestID:       1,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing conn ID",
		},
		{
			name:            "missing-requestID",
			writer:          bufio.NewWriter(&buf),
			wLock:           &sync.Mutex{},
			logger:          hclog.Default(),
			connID:          1,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing request ID",
		},
		{
			name:      "valid",
			writer:    bufio.NewWriter(&buf),
			wLock:     &sync.Mutex{},
			logger:    hclog.Default(),
			connID:    1,
			requestID: 1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			w, err := newResponseWriter(tc.writer, tc.wLock, tc.logger, tc.connID, tc.requestID)
			if tc.wantErr {
				require.Error(err)
				require.Nil(w)
				if tc.wantErrIs != nil {
					assert.ErrorIs(err, tc.wantErrIs)
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			require.NotNil(w)
			assert.Equal(w.writer, tc.writer)
			assert.Equal(w.writerMu, tc.wLock)
			assert.Equal(w.logger, tc.logger)
			assert.Equal(w.connID, tc.connID)
			assert.Equal(w.requestID, tc.requestID)
		})
	}
}

func TestResponseWriter_Write(t *testing.T) {
	tests := []struct {
		name            string
		logger          hclog.Logger
		response        Response
		want            string
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name: "missing-response",
			logger: hclog.New(&hclog.LoggerOptions{
				Name:  "TestResponseWriter_Write-logger",
				Level: hclog.Error,
			}),
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing response",
		},
		{
			name: "valid",
			logger: hclog.New(&hclog.LoggerOptions{
				Name:   "TestResponseWriter_Write-logger",
				Level:  hclog.Debug,
				Output: func() io.Writer { var buf bytes.Buffer; return bufio.NewWriter(&buf) }(),
			}),
			response: &testResponse{
				baseResponse: &baseResponse{
					messageID: 1,
				},
				data: "test",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			var buf bytes.Buffer
			w, err := newResponseWriter(
				bufio.NewWriter(&buf),
				&sync.Mutex{},
				tc.logger,
				1, 1)
			require.NoError(err)
			err = w.Write(tc.response)
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
			assert.Equal(tc.response.packet().Bytes(), buf.Bytes())
		})
	}
}

func Test_baseResponse(t *testing.T) {
	assert := assert.New(t)
	b := &baseResponse{}
	t.Run("SetResultCode", func(t *testing.T) {
		b.SetResultCode(42)
		assert.Equal(int16(42), b.code)
	})
	t.Run("SetDiagnosticMessage", func(t *testing.T) {
		b.SetDiagnosticMessage("test")
		assert.Equal("test", b.diagMessage)
	})
	t.Run("SetMatchedDN", func(t *testing.T) {
		b.SetMatchedDN("matched")
		assert.Equal("matched", b.matchedDN)
	})
}

type testResponse struct {
	*baseResponse
	data string
}

func (r *testResponse) packet() *packet {
	p := beginResponse(r.messageID)
	addOptionalResponseChildren(p, WithDiagnosticMessage(r.data))
	return &packet{Packet: p}
}
