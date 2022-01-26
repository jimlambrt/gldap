package gldap

import ber "github.com/go-asn1-ber/asn1-ber"

// Control defines a common interface for all ldap controls
type Control interface {
	// GetControlType returns the OID
	GetControlType() string
	// Encode returns the ber packet representation
	Encode() *ber.Packet
	// String returns a human-readable description
	String() string
}

func encodeControls(controls []Control) *ber.Packet {
	packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "Controls")
	for _, control := range controls {
		packet.AppendChild(control.Encode())
	}
	return packet
}
