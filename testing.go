package gldap

import (
	"net"
	"os"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/require"
)

func freePort(t *testing.T) int {
	t.Helper()
	require := require.New(t)
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	require.NoError(err)

	l, err := net.ListenTCP("tcp", addr)
	require.NoError(err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func testStartTLSRequestPacket(t *testing.T, messageID int) *packet {
	t.Helper()
	envelope := testRequestEnvelope(t, int(messageID))

	request := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationExtendedRequest, nil, "Start TLS")
	request.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, "1.3.6.1.4.1.1466.20037", "TLS Extended Command"))
	envelope.AppendChild(request)

	return &packet{
		Packet: envelope,
	}
}

func testSearchRequestPacket(t *testing.T, s SearchMessage) *packet {
	t.Helper()
	require := require.New(t)
	envelope := testRequestEnvelope(t, int(s.GetID()))
	pkt := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchRequest, nil, "Search Request")
	pkt.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, s.BaseDN, "Base DN"))
	pkt.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(s.Scope), "Scope"))
	pkt.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(s.DerefAliases), "Deref Aliases"))
	pkt.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(s.SizeLimit), "Size Limit"))
	pkt.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(s.TimeLimit), "Time Limit"))
	pkt.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, s.TypesOnly, "Types Only"))

	// compile and encode filter
	filterPacket, err := ldap.CompileFilter(s.Filter)
	require.NoError(err)
	pkt.AppendChild(filterPacket)

	attributesPacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	for _, attribute := range s.Attributes {
		attributesPacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, attribute, "Attribute"))
	}
	pkt.AppendChild(attributesPacket)

	envelope.AppendChild(pkt)
	if len(s.Controls) > 0 {
		envelope.AppendChild(encodeControls(s.Controls))
	}

	return &packet{
		Packet: envelope,
	}
}

func testSimpleBindRequestPacket(t *testing.T, m SimpleBindMessage) *packet {
	t.Helper()

	envelope := testRequestEnvelope(t, int(m.GetID()))
	pkt := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindRequest, nil, "Bind Request")
	pkt.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(3), "Version"))
	pkt.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, m.UserName, "User Name"))
	pkt.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, string(m.Password), "Password"))
	envelope.AppendChild(pkt)

	if len(m.Controls) > 0 {
		envelope.AppendChild(encodeControls(m.Controls))
	}

	return &packet{
		Packet: envelope,
	}
}

func testModifyRequestPacket(t *testing.T, m ModifyMessage) *packet {
	t.Helper()
	envelope := testRequestEnvelope(t, int(m.GetID()))
	pkt := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationModifyRequest, nil, "Modify Request")
	pkt.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, m.DN, "DN"))
	changes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Changes")
	for _, change := range m.Changes {
		changes.AppendChild(change.encode())
	}
	pkt.AppendChild(changes)

	envelope.AppendChild(pkt)
	if len(m.Controls) > 0 {
		envelope.AppendChild(encodeControls(m.Controls))
	}
	return &packet{
		Packet: envelope,
	}
}

func testRequestEnvelope(t *testing.T, messageID int) *ber.Packet {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(messageID), "MessageID"))
	return p
}

func TestWithDebug(t *testing.T) bool {
	t.Helper()
	if strings.ToLower(os.Getenv("DEBUG")) == "true" {
		return true
	}
	return false
}
