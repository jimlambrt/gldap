package gldap

import (
	"bufio"
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/go-hclog"
)

const (
	ApplicationInternalErrorResponse            = 200
	ApplicationInternalErrorResponseDescription = "Internal"
)

type ResponseWriter struct {
	writer    *bufio.Writer
	logger    hclog.Logger
	connID    int
	requestID int
}

func NewResponseWriter(w *bufio.Writer, logger hclog.Logger, connID, requestID int) (*ResponseWriter, error) {
	const op = "gldap.NewResponseWriter"
	if w == nil {
		return nil, fmt.Errorf("%s: missing writer: %w", op, ErrInvalidParameter)
	}
	if logger == nil {
		return nil, fmt.Errorf("%s: missing logger: %w", op, ErrInvalidParameter)
	}
	return &ResponseWriter{
		writer:    w,
		logger:    logger,
		connID:    connID,
		requestID: requestID,
	}, nil
}

func (rw *ResponseWriter) Write(r Response) error {
	const op = "gldap.(ResponseWriter).Write"
	p := r.packet()
	if rw.logger.IsDebug() {
		rw.logger.Debug("response write", "op", op, "conn", rw.connID, "requestID", rw.requestID)
		p.Log(rw.logger.StandardWriter(&hclog.StandardLoggerOptions{}), 0, false)
	}
	if _, err := rw.writer.Write(r.packet().Bytes()); err != nil {
		return fmt.Errorf("%s: unable to write response: %w", op, err)
	}
	if err := rw.writer.Flush(); err != nil {
		return fmt.Errorf("%s: unable to flush write: %w", op, err)
	}
	rw.logger.Debug("finished writing", "op", op, "conn", rw.connID, "requestID", rw.requestID)
	return nil
}

func beginResponse(messageID int64) *ber.Packet {
	const op = "gldap.beginResponse"
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "MessageID"))
	return p
}

func addOptionalResponseChildren(bindResponse *ber.Packet, opt ...Option) {
	const op = "gldap.addOptionalResponseChildren"
	opts := getResponseOpts(opt...)
	bindResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, opts.withMatchedDN, "matchedDN"))
	bindResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, opts.withDiagnosticMessage, "diagnosticMessage"))
}

// Response represents a response to an ldap request
type Response interface {
	packet() *packet
}

type baseResponse struct {
	messageID   int64
	code        int16
	diagMessage string
	matchedDN   string
}

// SetResultCode the result code for a response.
func (l *baseResponse) SetResultCode(code int) {
	l.code = int16(code)
}

// SetDiagnosticMessage sets the optional diagnostic message for a response.
func (l *baseResponse) SetDiagnosticMessage(msg string) {
	l.diagMessage = msg
}

// SetMatchedDN sets the optional matched DN for a response.
func (l *baseResponse) SetMatchedDN(dn string) {
	l.matchedDN = dn
}

type ExtendedResponse struct {
	*baseResponse
	name ExtendedOperationName
}

func (r *ExtendedResponse) SetResponseName(n ExtendedOperationName) {
	r.name = n
}

// Bytes returned from an extended response
func (r *ExtendedResponse) packet() *packet {
	replyPacket := beginResponse(r.messageID)

	// a new packet for the bind response
	resultPacket := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(ldap.ApplicationExtendedResponse), nil, ldap.ApplicationMap[ldap.ApplicationExtendedResponse])
	// append the result code to the bind response packet
	resultPacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, r.code, ldap.LDAPResultCodeMap[uint16(r.code)]))

	// Add optional diagnostic message and matched DN
	addOptionalResponseChildren(resultPacket, WithDiagnosticMessage(r.diagMessage), WithMatchedDN(r.matchedDN))

	replyPacket.AppendChild(resultPacket)
	return &packet{Packet: replyPacket}
}

// BindResponse represents the response to a bind request
type BindResponse struct {
	*baseResponse
}

// Bytes returned from a bind response
func (r *BindResponse) packet() *packet {
	replyPacket := beginResponse(r.messageID)

	// a new packet for the bind response
	resultPacket := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(ldap.ApplicationBindResponse), nil, ldap.ApplicationMap[ldap.ApplicationBindResponse])
	// append the result code to the bind response packet
	resultPacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, r.code, ldap.LDAPResultCodeMap[uint16(r.code)]))

	// Add optional diagnostic message and matched DN
	addOptionalResponseChildren(resultPacket, WithDiagnosticMessage(r.diagMessage), WithMatchedDN(r.matchedDN))

	replyPacket.AppendChild(resultPacket)
	return &packet{Packet: replyPacket}
}

type GeneralResponse struct {
	*baseResponse
	applicationCode int
}

// Bytes returned from an internal error
func (r *GeneralResponse) packet() *packet {
	const op = "gldap.(GeneralResponse).packet"
	replyPacket := beginResponse(r.messageID)

	var tag ber.Tag
	switch r.applicationCode {
	case 0:
		tag = ldap.ApplicationExtendedResponse
	default:
		tag = ber.Tag(r.applicationCode)
	}

	// a new packet for the bind response
	resultPacket := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(tag), nil, ldap.ApplicationMap[uint8(tag)])
	// append the result code to the bind response packet
	resultPacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, r.code, ldap.LDAPResultCodeMap[uint16(r.code)]))

	// Add optional diagnostic message and matched DN
	addOptionalResponseChildren(resultPacket, WithDiagnosticMessage(r.diagMessage), WithMatchedDN(r.matchedDN))

	replyPacket.AppendChild(resultPacket)
	return &packet{Packet: replyPacket}
}

// SearchResponseDone represents that handling a search requests is done.
type SearchResponseDone struct {
	*baseResponse
}

func (r *SearchResponseDone) packet() *packet {
	const op = "gldap.(SearchDoneResponse).packet"
	replyPacket := beginResponse(r.messageID)

	resultPacket := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultDone, nil, ldap.ApplicationMap[ldap.ApplicationSearchResultDone])
	resultPacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, r.code, ldap.LDAPResultCodeMap[uint16(r.code)]))

	// Add optional diagnostic message and matched DN
	addOptionalResponseChildren(resultPacket, WithDiagnosticMessage(r.diagMessage), WithMatchedDN(r.matchedDN))

	replyPacket.AppendChild(resultPacket)
	return &packet{Packet: replyPacket}
}

type SearchResponseEntry struct {
	*baseResponse
	entry Entry
}

func (r *SearchResponseEntry) AddAttribute(name string, values []string) {
	r.entry.Attributes = append(r.entry.Attributes, newEntryAttribute(name, values))
}

func (r *SearchResponseEntry) packet() *packet {
	const op = "gldap.(SearchEntryResponse).packet"
	replyPacket := beginResponse(r.messageID)

	resultPacket := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, ldap.ApplicationMap[ldap.ApplicationSearchResultEntry])
	resultPacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, r.entry.DN, "DN"))
	attributesPacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	for _, a := range r.entry.Attributes {
		attributesPacket.AppendChild(a.encode())
	}
	resultPacket.AppendChild(attributesPacket)

	// Add optional diagnostic message and matched DN
	addOptionalResponseChildren(resultPacket, WithDiagnosticMessage(r.diagMessage), WithMatchedDN(r.matchedDN))

	replyPacket.AppendChild(resultPacket)
	return &packet{Packet: replyPacket}
}
