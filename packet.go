package gldap

import (
	"fmt"
	"io"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

type packet struct {
	*ber.Packet
	validated bool
}

func (p *packet) basicValidation() error {
	const (
		op = "gldap.(packet).basicValidation"

		// messageID packet + Request packet
		childMinChildren = 2
	)
	if p.validated {
		return nil
	}
	// Simple header is first... let's make sure it's an ldap packet with 2
	// children containing:
	//		[0] is a message ID
	//		[1] is a request header
	if err := p.assert(ber.ClassUniversal, ber.TypeConstructed, withTag(ber.TagSequence), withMinChildren(childMinChildren)); err != nil {
		return fmt.Errorf("%s: invalid ldap packet 0: %w", op, ErrInvalidParameter)
	}
	p.validated = true
	return nil
}

func (p *packet) requestMessageID() (int64, error) {
	const (
		op = "gldap.(packet).requestMessageID"

		childMessageID = 0
	)
	if err := p.basicValidation(); err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	msgIdPacket := &packet{Packet: p.Children[childMessageID]}
	// assert it's capable of holding the message ID
	if err := msgIdPacket.assert(ber.ClassUniversal, ber.TypePrimitive, withTag(ber.TagInteger)); err != nil {
		return 0, fmt.Errorf("%s: missing/invalid packet: %w", op, err)
	}
	return msgIdPacket.Value.(int64), nil
}

func (p *packet) requestPacket() (*packet, error) {
	const (
		op = "gldap.(packet).requestPacket"

		childApplicationRequest = 1
		childVersionNumber      = 0 // first child of the app request packet
	)
	if err := p.basicValidation(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	// assert there's a request type child
	if err := p.assert(ber.ClassApplication, ber.TypeConstructed, withAssertChild(childApplicationRequest)); err != nil {
		return nil, fmt.Errorf("%s: missing request child packet: %w", op, err)
	}
	requestPacket := &packet{Packet: p.Children[childApplicationRequest]}

	switch requestPacket.Packet.Tag {
	case ldap.ApplicationExtendedRequest:
		// there is no version child.
		// nada todo for now...
	case ldap.ApplicationSearchRequest:
		// nada to do.. no version child.. perhaps all this should be refactored?
	default:
		// assert it's ldap v3
		if err := requestPacket.assert(ber.ClassUniversal, ber.TypePrimitive, withTag(ber.TagInteger), withAssertChild(childVersionNumber)); err != nil {
			return nil, fmt.Errorf("%s: missing/invalid packet: %w", op, err)
		}
		ldapVersion, ok := requestPacket.Packet.Children[childVersionNumber].Value.(int64)
		if !ok {
			return nil, fmt.Errorf("%s: %v is not the expected int64 type: %w", op, requestPacket.Packet.Children[childVersionNumber].Value, ErrInvalidParameter)
		}
		if ldapVersion != 3 {
			return nil, fmt.Errorf("%s: incorrect ldap version, expected 3 but got %v", op, requestPacket.Value.(int64))
		}
	}

	return &packet{Packet: p.Children[childApplicationRequest]}, nil
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
	case ldap.ApplicationExtendedRequest:
		return extendedRequestType, nil
	default:
		return unknownRequestType, fmt.Errorf("%s: unhandled request type %d: %w", op, requestPacket.Tag, ErrInternal)
	}
}

func (p *packet) extendedOperationName() (ExtendedOperationName, error) {
	const (
		op = "gldap.(Packet).simpleBindParameters"

		childExtendedOperationName = 0
	)
	requestPacket, err := p.requestPacket()
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}
	if requestPacket.Packet.Tag != ldap.ApplicationExtendedRequest {
		return "", fmt.Errorf("%s: not an extended operation request, expected tag %d and got %d: %w", op, ldap.ApplicationExtendedRequest, requestPacket.Tag, ErrInvalidParameter)
	}
	if err := requestPacket.assert(ber.ClassContext, ber.TypePrimitive, withTag(0), withAssertChild(childExtendedOperationName)); err != nil {
		return "", fmt.Errorf("%s: missing/invalid username packet: %w", op, ErrInvalidParameter)
	}
	n := requestPacket.Children[childExtendedOperationName].Data.String()
	return ExtendedOperationName(n), nil
}

// Password is a simple bind request password
type Password string

func (p *packet) simpleBindParameters() (string, Password, error) {
	const (
		op = "gldap.(Packet).simpleBindParameters"

		childBindUserName = 1
		childBindPassword = 2
	)
	requestPacket, err := p.requestPacket()
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}
	if err := requestPacket.assert(ber.ClassUniversal, ber.TypePrimitive, withTag(ber.TagOctetString), withAssertChild(childBindUserName)); err != nil {
		return "", "", fmt.Errorf("%s: missing/invalid username packet: %w", op, ErrInvalidParameter)
	}
	userName := requestPacket.Children[childBindUserName].Data.String()

	// check if there's even an password packet in the request
	if len(requestPacket.Children) > 3 {
		return userName, "", nil
	}
	if err := requestPacket.assert(ber.ClassContext, ber.TypePrimitive, withTag(0), withAssertChild(childBindPassword)); err != nil {
		return "", "", fmt.Errorf("%s: missing/invalid password packet: %w", op, ErrInvalidParameter)
	}
	password := requestPacket.Children[childBindPassword].Data.String()

	return userName, Password(password), nil
}

type searchParameters struct {
	baseDN       string
	scope        int64
	derefAliases int64
	sizeLimit    int64
	timeLimit    int64
	typesOnly    bool
	filter       string
	attributes   []string
	controls     []Control
}

func (p *packet) searchParmeters() (*searchParameters, error) {
	const op = "gldap.(Packet).simpleBindParameters"
	const (
		childBaseDN       = 0
		childScope        = 1
		childDerefAliases = 2
		childSizeLimit    = 3
		childTimeLimit    = 4
		childTypesOnly    = 5
		childFilter       = 6
		childAttributes   = 7
	)
	var ok bool
	var searchFor searchParameters
	requestPacket, err := p.requestPacket()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	// validate that it's a search request
	if requestPacket.Packet.Tag != ldap.ApplicationSearchRequest {
		return nil, fmt.Errorf("%s: not an search request, expected tag %d and got %d: %w", op, ldap.ApplicationSearchRequest, requestPacket.Tag, ErrInvalidParameter)
	}
	// baseDN child
	if err := requestPacket.assert(ber.ClassUniversal, ber.TypePrimitive, withTag(ber.TagOctetString), withAssertChild(childBaseDN)); err != nil {
		return nil, fmt.Errorf("%s: missing/invalid baseDN: %w", op, ErrInvalidParameter)
	}
	searchFor.baseDN = requestPacket.Children[childBaseDN].Data.String()

	// scope child
	if err := requestPacket.assert(ber.ClassUniversal, ber.TypePrimitive, withTag(ber.TagEnumerated), withAssertChild(childScope)); err != nil {
		return nil, fmt.Errorf("%s: missing/invalid scope: %w", op, ErrInvalidParameter)
	}
	if searchFor.scope, ok = requestPacket.Children[childScope].Value.(int64); !ok {
		return nil, fmt.Errorf("%s: scope is not an int64", op)
	}

	// deref aliases
	if err := requestPacket.assert(ber.ClassUniversal, ber.TypePrimitive, withTag(ber.TagEnumerated), withAssertChild(childDerefAliases)); err != nil {
		return nil, fmt.Errorf("%s: missing/invalid deref aliases: %w", op, ErrInvalidParameter)
	}
	if searchFor.derefAliases, ok = requestPacket.Children[childDerefAliases].Value.(int64); !ok {
		return nil, fmt.Errorf("%s: deref aliases is not an int64", op)
	}

	// size limit
	if err := requestPacket.assert(ber.ClassUniversal, ber.TypePrimitive, withTag(ber.TagInteger), withAssertChild(childSizeLimit)); err != nil {
		return nil, fmt.Errorf("%s: missing/invalid size limit: %w", op, ErrInvalidParameter)
	}
	if searchFor.sizeLimit, ok = requestPacket.Children[childSizeLimit].Value.(int64); !ok {
		return nil, fmt.Errorf("%s: size limit is not an int64", op)
	}

	// time limit
	if err := requestPacket.assert(ber.ClassUniversal, ber.TypePrimitive, withTag(ber.TagInteger), withAssertChild(childTimeLimit)); err != nil {
		return nil, fmt.Errorf("%s: missing/invalid time limit: %w", op, ErrInvalidParameter)
	}
	if searchFor.timeLimit, ok = requestPacket.Children[childTimeLimit].Value.(int64); !ok {
		return nil, fmt.Errorf("%s: time limit is not an int64", op)
	}

	// types only
	if err := requestPacket.assert(ber.ClassUniversal, ber.TypePrimitive, withTag(ber.TagBoolean), withAssertChild(childTypesOnly)); err != nil {
		return nil, fmt.Errorf("%s: missing/invalid types only: %w", op, ErrInvalidParameter)
	}
	if searchFor.typesOnly, ok = requestPacket.Children[childTypesOnly].Value.(bool); !ok {
		return nil, fmt.Errorf("%s: types only is not a bool", op)
	}

	if len(requestPacket.Children) < childFilter+1 {
		return nil, fmt.Errorf("%s: missing filter: %w", op, ErrInvalidParameter)
	}

	filter, err := ldap.DecompileFilter(requestPacket.Children[childFilter])
	if err != nil {
		return nil, fmt.Errorf("%s: unable to decompile filter: %w", op, err)
	}
	searchFor.filter = filter

	// check for attributes packet
	if len(requestPacket.Children) < childAttributes+1 {
		return &searchFor, nil // there's none, so just return
	}
	if err := requestPacket.assert(ber.ClassUniversal, ber.TypeConstructed, withTag(ber.TagSequence), withAssertChild(childAttributes)); err != nil {
		return nil, fmt.Errorf("%s: invalid attributes: %w", op, err)
	}
	attributesPacket := packet{
		Packet: requestPacket.Children[childAttributes],
	}
	searchFor.attributes = make([]string, 0, len(attributesPacket.Children))
	for idx, attribute := range attributesPacket.Children {
		if err := attributesPacket.assert(ber.ClassUniversal, ber.TypeConstructed, withTag(ber.TagOctetString), withAssertChild(idx)); err != nil {
		}
		searchFor.attributes = append(searchFor.attributes, attribute.Data.String())
	}

	return &searchFor, nil
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
	if opts.withAssertChild != nil {
		if len(p.Children) < *opts.withAssertChild+1 {
			return fmt.Errorf("%s: missing asserted child %d, but there are only %d", op, *opts.withAssertChild, len(p.Children))
		} else {
			chkPacket = p.Packet.Children[*opts.withAssertChild]
		}
	}

	if chkPacket.ClassType != cl {
		return fmt.Errorf("%s: incorrect class, expected %v but got %v", op, cl, chkPacket.ClassType)
	}
	if chkPacket.TagType != ty {
		return fmt.Errorf("%s: incorrect type, expected %v but got %v", op, ty, chkPacket.TagType)
	}
	if opts.withTag != nil && chkPacket.Tag != *opts.withTag {
		return fmt.Errorf("%s: incorrect tag, expected %v but got %v", op, *opts.withTag, chkPacket.Tag)
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