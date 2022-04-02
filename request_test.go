package gldap

import (
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
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
				SimpleBindMessage{
					baseMessage: baseMessage{id: 1},
					UserName:    "alice",
					Password:    "fido",
					Controls: []Control{
						testControlString(t, "generic-control", WithControlValue("generic-value")),
					},
				},
			),
			wantMsg: &SimpleBindMessage{
				baseMessage: baseMessage{id: 1},
				UserName:    "alice",
				Password:    "fido",
				AuthChoice:  "simple",
				Controls: []Control{
					testControlString(t, "generic-control", WithControlValue("generic-value")),
				},
			},
		},
		{
			name:      "valid-unbind",
			requestID: 1,
			conn:      &conn{},
			packet: testUnbindRequestPacket(t,
				UnbindMessage{
					baseMessage: baseMessage{id: 1},
				},
			),
			wantMsg: &UnbindMessage{
				baseMessage: baseMessage{id: 1},
			},
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
						testControlString(t, "generic-control", WithControlValue("generic-value")),
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
					testControlString(t, "generic-control", WithControlValue("generic-value")),
				},
			},
		},
		{
			name:      "valid-add",
			requestID: 1,
			conn:      &conn{},
			packet: testAddRequestPacket(t,
				AddMessage{
					baseMessage: baseMessage{id: 1},
					DN:          "uid=alice,ou=people,dc=example,dc=com",
					Attributes: []Attribute{
						{
							Type: "mail",
							Vals: []string{"alice@example.com"},
						},
						{
							Type: "givenname",
							Vals: []string{"alice"},
						},
					},
					Controls: []Control{
						testControlString(t, "generic-control", WithControlValue("generic-value")),
					},
				},
			),
			wantMsg: &AddMessage{
				baseMessage: baseMessage{id: 1},
				DN:          "uid=alice,ou=people,dc=example,dc=com",
				Attributes: []Attribute{
					{
						Type: "mail",
						Vals: []string{"alice@example.com"},
					},
					{
						Type: "givenname",
						Vals: []string{"alice"},
					},
				},
				Controls: []Control{
					testControlString(t, "generic-control", WithControlValue("generic-value")),
				},
			},
		},
		{
			name:      "invalid-add",
			requestID: 1,
			conn:      &conn{},
			packet: func() *packet {
				envelope := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
				envelope.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(1), "MessageID"))

				pkt := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationAddRequest, nil, "Add Request")
				pkt.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "uid=alice", "DN"))
				attributes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
				pkt.AppendChild(attributes)
				seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attribute")
				seq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypeConstructed, ber.TagBoolean, "false", "invalid-type-bool"))
				// missing values
				attributes.AppendChild(seq)
				envelope.AppendChild(pkt)
				return &packet{Packet: envelope}
			}(),
			wantErr:         true,
			wantErrContains: "failed to decode attribute packet",
		},
		{
			name:      "valid-delete",
			requestID: 1,
			conn:      &conn{},
			packet: testDeleteRequestPacket(t,
				DeleteMessage{
					baseMessage: baseMessage{id: 1},
					DN:          "uid=alice,ou=people,dc=example,dc=com",
					Controls: []Control{
						testControlString(t, "generic-control", WithControlValue("generic-value")),
					},
				},
			),
			wantMsg: &DeleteMessage{
				baseMessage: baseMessage{id: 1},
				DN:          "uid=alice,ou=people,dc=example,dc=com",
				Controls: []Control{
					testControlString(t, "generic-control", WithControlValue("generic-value")),
				},
			},
		},
		{
			name:      "invalid-delete",
			requestID: 1,
			conn:      &conn{},
			packet: func() *packet {
				envelope := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
				envelope.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(1), "MessageID"))
				return &packet{Packet: envelope}
			}(),
			wantErr:         true,
			wantErrContains: "unable to build message for request",
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

func TestRequest_GetDeleteMessage(t *testing.T) {
	tests := []struct {
		name            string
		r               *Request
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "invalid",
			r:               &Request{},
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "not a delete request",
		},
		{
			name: "valid",
			r:    &Request{message: &DeleteMessage{}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			m, err := tc.r.GetDeleteMessage()
			if tc.wantErr {
				require.Error(err)
				assert.Nil(m)
				if tc.wantErrIs != nil {
					assert.ErrorIs(err, tc.wantErrIs)
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.NotNil(m)
		})
	}
}
