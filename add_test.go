// Copyright (c) Jim Lambert
// SPDX-License-Identifier: MIT

package gldap

import (
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAttribute_decode(t *testing.T) {
	tests := []struct {
		name            string
		packet          *ber.Packet
		want            *Attribute
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "missing packet",
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing ber packet",
		},
		{
			name: "not-attr-packet",
			packet: func() *ber.Packet {
				return ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.Tag(ber.TypePrimitive), nil, "invalid-primitive")
			}(),
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing/invalid attributes ber packet",
		},
		{
			name: "missing-type-child",
			packet: func() *ber.Packet {
				return ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.Tag(ber.TagSequence), nil, "Attribute")
			}(),
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing/invalid attributes type",
		},
		{
			name: "invalid-type-child",
			packet: func() *ber.Packet {
				seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.Tag(ber.TagSequence), nil, "Attribute")
				seq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypeConstructed, ber.TagBoolean, "false", "invalid-type-bool"))
				return seq
			}(),
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing/invalid attributes type",
		},
		{
			name: "missing-values",
			packet: func() *ber.Packet {
				seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.Tag(ber.TagSequence), nil, "Attribute")
				seq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "email", "Type"))
				return seq
			}(),
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing/invalid attributes values",
		},
		{
			name: "bad-values",
			packet: func() *ber.Packet {
				seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.Tag(ber.TagSequence), nil, "Attribute")
				seq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "email", "Type"))
				set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "AttributeValue")
				set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, "false", "invalid-type-bool"))
				seq.AppendChild(set)
				return seq
			}(),
			wantErr:         true,
			wantErrContains: "invalid attribute values packet",
		},
		{
			name: "success",
			packet: func() *ber.Packet {
				attr := Attribute{
					Type: "email",
					Vals: []string{"alice@example.com"},
				}
				return attr.encode()
			}(),
			want: &Attribute{
				Type: "email",
				Vals: []string{"alice@example.com"},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := decodeAttribute(tc.packet)
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
		})
	}
}
