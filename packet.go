package gldap

import (
	"fmt"
	"io"

	"github.com/go-ldap/ldap/v3"
	ber "gopkg.in/asn1-ber.v1"
)

type packet struct {
	*ber.Packet
	validated bool
}

func (c *Conn) readPacket(requestID int, r io.Reader) (*packet, error) {
	const op = "ldap.ReadPacket"
	// read a request
	berPacket, err := ber.ReadPacket(r)
	if err != nil {
		return nil, fmt.Errorf("%s: error reading ber packet for %d/%d:  %w", op, c.connID, requestID, err)
	}

	p := &packet{Packet: berPacket}
	// Simple header is first... let's make sure it's an ldap packet with 2
	// children containing:
	//		[0] is a message ID
	//		[1] is a request header
	if err := p.basicValidation(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, ErrInvalidParameter)
	}
	return p, nil
}

func (p *packet) basicValidation() error {
	const op = "gldap.(packet).basicValidation"
	if p.validated {
		return nil
	}
	// Simple header is first... let's make sure it's an ldap packet with 2
	// children containing:
	//		[0] is a message ID
	//		[1] is a request header
	if err := p.assert(ber.ClassUniversal, ber.TypeConstructed, withTag(ber.TagSequence), withMinChildren(minChildren)); err != nil {
		return fmt.Errorf("%s: invalid ldap packet 0: %w", op, ErrInvalidParameter)
	}
	// assert it's ldap v3
	if err := p.assertVersion3(); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	p.validated = true
	return nil
}

func (p *packet) requestPacket() (*packet, error) {
	const op = "ldap.(packet).requestPacket"
	if err := p.basicValidation(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	// assert there's a request type child
	if err := p.assert(ber.ClassApplication, ber.TypeConstructed, withAssertChild(requestChildIdx)); err != nil {
		return nil, fmt.Errorf("%s: missing request child packet: %w", op, err)
	}
	return &packet{Packet: p.Children[requestChildIdx]}, nil
}

func (p *packet) requestType() (requestType, error) {
	const op = "gldap.(Packet).requestType"
	requestPacket, err := p.requestPacket()
	if err != nil {
		return unknownRequestType, fmt.Errorf("%s: %w", op, err)
	}

	switch requestPacket.Tag {
	case ldap.ApplicationBindRequest:
		return bindRequestType, nil
	case ldap.ApplicationSearchRequest:
		return searchRequestType, nil
	default:
		return unknownRequestType, fmt.Errorf("%s: unhandled request type %d: %w", op, requestPacket.Tag, ErrInternal)
	}
}

type Password string

func (p *packet) simpleBindParameters() (string, Password, error) {
	const op = "gldap.(Packet).simpleBindParameters"
	requestPacket, err := p.requestPacket()
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}
	if err := requestPacket.assert(ber.ClassUniversal, ber.TypePrimitive, withTag(ber.TagOctetString), withAssertChild(requestBindUserNameIdx)); err != nil {
		return "", "", fmt.Errorf("%s: missing/invalid username packet: %w", op, ErrInvalidParameter)
	}
	userName := requestPacket.Children[requestBindUserNameIdx].Data.String()

	// check if there's even an password packet in the request
	if len(requestPacket.Children) > 3 {
		return userName, "", nil
	}
	if err := requestPacket.assert(ber.ClassContext, ber.TypePrimitive, withTag(0), withAssertChild(requestBindPasswordIdx)); err != nil {
		return "", "", fmt.Errorf("%s: missing/invalid password packet: %w", op, ErrInvalidParameter)
	}
	password := requestPacket.Children[requestBindPasswordIdx].Data.String()

	return userName, Password(password), nil
}

func (p *packet) assert(cl ber.Class, ty ber.Type, opt ...Option) error {
	const op = "gldap.assert"
	opts := getMessageOpts(opt...)

	if opts.withLenChildren != nil {
		if len(p.Children) != *opts.withLenChildren {
			return fmt.Errorf("%s: not the correct number of children packets, expected %d but got %d", op, *opts.withLenChildren, len(p.Children))
		}
	}
	if opts.withMinChildren != nil {
		if len(p.Children) < *opts.withMinChildren {
			return fmt.Errorf("%s: not enough children packets, expected %d but got %d", op, *opts.withMinChildren, len(p.Children))
		}
	}

	chkPacket := p.Packet
	if opts.withAssertChild != nil && len(p.Children) > *opts.withAssertChild {
		return fmt.Errorf("%s: missing asserted child %d, but there are only %d", op, *opts.withAssertChild, len(p.Children))
	} else {
		chkPacket = p.Packet.Children[*opts.withAssertChild]
	}

	if chkPacket.ClassType != cl {
		return fmt.Errorf("%s: incorrect class, expected %v but got %v", op, cl, p.ClassType)
	}
	if chkPacket.TagType != ty {
		return fmt.Errorf("%s: incorrect type, expected %v but got %v", op, cl, p.TagType)
	}
	if opts.withTag != nil && chkPacket.Tag != *opts.withTag {
		return fmt.Errorf("%s: incorrect tag, expected %v but got %v", op, cl, p.Tag)
	}
	return nil
}

func (p *packet) assertVersion3() error {
	const op = "ldap.(packet).assertV3"
	if err := p.basicValidation(); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	requestPacket := &packet{Packet: p.Children[requestChildIdx]}
	// assert it's ldap v3
	if err := requestPacket.assert(ber.ClassUniversal, ber.TypePrimitive, withTag(ber.TagInteger)); err != nil {
		return fmt.Errorf("%s: missing/invalid packet: %w", op, err)
	}
	if requestPacket.Value.(int64) != 3 {
		return fmt.Errorf("%s: incorrect ldap version, expected 3 but got %v", op, requestPacket.Value.(int64))
	}
	return nil
}

func (p *packet) Log(out io.Writer, indent int, printBytes bool) {
	indent_str := ""

	for len(indent_str) != indent {
		indent_str += " "
	}

	class_str := ber.ClassMap[p.ClassType]

	tagtype_str := ber.TypeMap[p.TagType]

	tag_str := fmt.Sprintf("0x%02X", p.Tag)

	if p.ClassType == ber.ClassUniversal {
		tag_str = tagMap[p.Tag]
	}

	value := fmt.Sprint(p.Value)
	description := ""

	if p.Description != "" {
		description = p.Description + ": "
	}

	fmt.Fprintf(out, "%s%s(%s, %s, %s) Len=%d %q\n", indent_str, description, class_str, tagtype_str, tag_str, p.Data.Len(), value)

	if printBytes {
		ber.PrintBytes(out, p.Bytes(), indent_str)
	}

	for _, child := range p.Children {
		childPacket := packet{Packet: child}
		childPacket.Log(out, indent+1, printBytes)
	}
}

var tagMap = map[ber.Tag]string{
	ber.TagEOC:              "EOC (End-of-Content)",
	ber.TagBoolean:          "Boolean",
	ber.TagInteger:          "Integer",
	ber.TagBitString:        "Bit String",
	ber.TagOctetString:      "Octet String",
	ber.TagNULL:             "NULL",
	ber.TagObjectIdentifier: "Object Identifier",
	ber.TagObjectDescriptor: "Object Descriptor",
	ber.TagExternal:         "External",
	ber.TagRealFloat:        "Real (float)",
	ber.TagEnumerated:       "Enumerated",
	ber.TagEmbeddedPDV:      "Embedded PDV",
	ber.TagUTF8String:       "UTF8 String",
	ber.TagRelativeOID:      "Relative-OID",
	ber.TagSequence:         "Sequence and Sequence of",
	ber.TagSet:              "Set and Set OF",
	ber.TagNumericString:    "Numeric String",
	ber.TagPrintableString:  "Printable String",
	ber.TagT61String:        "T61 String",
	ber.TagVideotexString:   "Videotex String",
	ber.TagIA5String:        "IA5 String",
	ber.TagUTCTime:          "UTC Time",
	ber.TagGeneralizedTime:  "Generalized Time",
	ber.TagGraphicString:    "Graphic String",
	ber.TagVisibleString:    "Visible String",
	ber.TagGeneralString:    "General String",
	ber.TagUniversalString:  "Universal String",
	ber.TagCharacterString:  "Character String",
	ber.TagBMPString:        "BMP String",
}
