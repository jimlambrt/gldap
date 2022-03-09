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
