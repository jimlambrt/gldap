package gldap

import (
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_newRequest(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		requestID       int
		conn            *conn
		packet          *packet
		wantMsg         Message
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:      "missing-conn",
			requestID: 1,
			packet: &packet{
				Packet: &ber.Packet{},
			},
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing connection",
		},
		{
			name:            "missing-packet",
			requestID:       1,
			conn:            &conn{},
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing packet",
		},
		{
			name:      "invalid-message",
			requestID: 1,
			conn:      &conn{},
			packet: &packet{
				Packet: &ber.Packet{},
			},
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "unable to build message",
		},
		{
			name:      "valid-simple-bind",
			requestID: 1,
			conn:      &conn{},
			packet: testSimpleBindRequestPacket(t,
				SimpleBindMessage{baseMessage: baseMessage{id: 1}, UserName: "alice", Password: "fido"},
			),
			wantMsg: &SimpleBindMessage{baseMessage: baseMessage{id: 1}, UserName: "alice", Password: "fido", AuthChoice: "simple"},
		},
		{
			name:      "valid-search",
			requestID: 1,
			conn:      &conn{},
			packet: testSearchRequestPacket(t,
				SearchMessage{baseMessage: baseMessage{id: 1}, Filter: "(uid=alice)"},
			),
			wantMsg: &SearchMessage{baseMessage: baseMessage{id: 1}, Filter: "(uid=alice)", Attributes: []string{}},
		},
		{
			name:      "valid-extended",
			requestID: 1,
			conn:      &conn{},
			packet:    testStartTLSRequestPacket(t, 1),
		},
		{
			name:      "valid-modify",
			requestID: 1,
			conn:      &conn{},
			packet: testModifyRequestPacket(t,
				ModifyMessage{
					baseMessage: baseMessage{id: 1},
					DN:          "uid=alice,ou=people,dc=example,dc=com",
					Changes: []Change{
						{
							Operation: AddAttribute,
							Modification: PartialAttribute{
								Type: "mail", Vals: []string{"alice@example.com"},
							},
						},
					},
					Controls: []Control{
						ldap.NewControlString("generic-control", false, "generic-value"),
					},
				},
			),
			wantMsg: &ModifyMessage{
				baseMessage: baseMessage{id: 1},
				DN:          "uid=alice,ou=people,dc=example,dc=com",
				Changes: []Change{
					{
						Operation: AddAttribute,
						Modification: PartialAttribute{
							Type: "mail", Vals: []string{"\x04\x11alice@example.com"},
						},
					},
				},
				Controls: []Control{
					ldap.NewControlString("generic-control", false, "generic-value"),
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			req, err := newRequest(tc.requestID, tc.conn, tc.packet)
			if tc.wantErr {
				require.Error(err)
				assert.Nil(req)
				if tc.wantErrIs != nil {
					assert.ErrorIs(err, tc.wantErrIs)
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			require.NotNil(req)
			if tc.wantMsg != nil {
				assert.Equal(tc.wantMsg, req.message)
			}
		})
	}
}
