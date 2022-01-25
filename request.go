package gldap

import (
	"crypto/tls"
	"fmt"
)

// ExtendedOperationName is an extended operation request/response name
type ExtendedOperationName string

// Extended operation response/request names
const (
	ExtendedOperationDisconnection   ExtendedOperationName = "1.3.6.1.4.1.1466.2003"
	ExtendedOperationCancel          ExtendedOperationName = "1.3.6.1.1.8"
	ExtendedOperationStartTLS        ExtendedOperationName = "1.3.6.1.4.1.1466.20037"
	ExtendedOperationWhoAmI          ExtendedOperationName = "1.3.6.1.4.1.4203.1.11.3"
	ExtendedOperationGetConnectionID ExtendedOperationName = "1.3.6.1.4.1.26027.1.6.2"
	ExtendedOperationPasswordModify  ExtendedOperationName = "1.3.6.1.4.1.4203.1.11.1"
	ExtendedOperationUnknown         ExtendedOperationName = "Unknown"
)

// Request represents an ldap request
type Request struct {
	// ID is the request number for a specific connection.  Every connection has
	// its own request counter which starts at 1.
	ID int

	// conn is needed this for cancellation among other things.
	conn         *conn
	message      Message
	routeOp      routeOperation
	extendedName ExtendedOperationName
}

func newRequest(id int, c *conn, p *packet) (*Request, error) {
	const op = "gldap.newRequest"
	if c == nil {
		return nil, fmt.Errorf("%s: missing connection: %w", op, ErrInvalidParameter)
	}
	if p == nil {
		return nil, fmt.Errorf("%s: missing packet: %w", op, ErrInvalidParameter)
	}

	m, err := newMessage(p)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to build message for request %d: %w", op, id, err)
	}
	var extendedName ExtendedOperationName
	var routeOp routeOperation
	switch v := m.(type) {
	case *SimpleBindMessage:
		routeOp = bindRouteOperation
	case *SearchMessage:
		routeOp = searchRouteOperation
	case *ExtendedOperationMessage:
		routeOp = extendedRouteOperation
		extendedName = v.Name
	default:
		// this should be unreachable, since newMessage defaults to returning an
		// *ExtendedOperationMessage
		return nil, fmt.Errorf("%s: %v is an unsupported route operation: %w", op, v, ErrInternal)
	}

	r := &Request{
		ID:           id,
		conn:         c,
		message:      m,
		routeOp:      routeOp,
		extendedName: extendedName,
	}
	return r, nil
}

// StartTLS will start a TLS connection using the Message's existing connection
func (r *Request) StartTLS(tlsconfig *tls.Config) error {
	const op = "gldap.(Message).StartTLS"
	if tlsconfig == nil {
		return fmt.Errorf("%s: missing tls configuration: %w", op, ErrInvalidParameter)
	}
	tlsConn := tls.Server(r.conn.netConn, tlsconfig)
	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("%s: handshake error: %w", op, err)
	}
	if err := r.conn.initConn(tlsConn); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

// NewResponse creates a general response (not tied to any specific request).
// Supported options: WithResponseCode, WithApplicationCode,
// WithDiagnosticMessage, WithMatchedDN
func (r *Request) NewResponse(opt ...Option) *GeneralResponse {
	const op = "gldap.NewBindResponse"
	opts := getResponseOpts(opt...)
	if opts.withResponseCode == nil {
		opts.withResponseCode = intPtr(ResultUnwillingToPerform)
	}
	if opts.withApplicationCode == nil {
		opts.withApplicationCode = intPtr(ApplicationExtendedResponse)
	}
	return &GeneralResponse{
		baseResponse: &baseResponse{
			messageID:   r.message.GetID(),
			code:        int16(*opts.withResponseCode),
			diagMessage: opts.withDiagnosticMessage,
			matchedDN:   opts.withMatchedDN,
		},
		applicationCode: *opts.withApplicationCode,
	}
}

// NewExtendedResponse creates a new extended response.
// Supported options: WithResponseCode
func (r *Request) NewExtendedResponse(opt ...Option) *ExtendedResponse {
	const op = "gldap.NewExtendedResponse"
	opts := getResponseOpts(opt...)
	resp := &ExtendedResponse{
		baseResponse: &baseResponse{
			messageID: r.message.GetID(),
		},
	}
	if opts.withResponseCode != nil {
		resp.code = int16(*opts.withResponseCode)
	}
	return resp
}

// NewBindResponse creates a new bind response.
// Supported options: WithResponseCode
func (r *Request) NewBindResponse(opt ...Option) *BindResponse {
	const op = "gldap.NewBindResponse"
	opts := getResponseOpts(opt...)
	resp := &BindResponse{
		baseResponse: &baseResponse{
			messageID: r.message.GetID(),
		},
	}
	if opts.withResponseCode != nil {
		resp.code = int16(*opts.withResponseCode)
	}
	return resp
}

// GetSimpleBindMessage retrieves the SimpleBindMessage from the request, which
// allows you handle the request based on the message attributes.
func (r *Request) GetSimpleBindMessage() (*SimpleBindMessage, error) {
	const op = "gldap.(Request).GetSimpleBindMessage"
	s, ok := r.message.(*SimpleBindMessage)
	if !ok {
		return nil, fmt.Errorf("%s: %T not a simple bind request: %w", op, r.message, ErrInvalidParameter)
	}
	return s, nil
}

// NewSearchDoneResponse creates a new search done response.  If there are no
// results found, then set the response code by adding the option
// WithResponseCode(ResultNoSuchObject)
//
// Supported options: WithResponseCode
func (r *Request) NewSearchDoneResponse(opt ...Option) *SearchResponseDone {
	const op = "gldap.(Request).NewSearchDoneResponse"
	opts := getResponseOpts(opt...)
	resp := &SearchResponseDone{
		baseResponse: &baseResponse{
			messageID: r.message.GetID(),
		},
	}
	if opts.withResponseCode != nil {
		resp.code = int16(*opts.withResponseCode)
	}
	return resp
}

// GetSearchMessage retrieves the SearchMessage from the request, which
// allows you handle the request based on the message attributes.
func (r *Request) GetSearchMessage() (*SearchMessage, error) {
	const op = "gldap.(Request).GetSearchMessage"
	s, ok := r.message.(*SearchMessage)
	if !ok {
		return nil, fmt.Errorf("%s: %T not a search request: %w", op, r.message, ErrInvalidParameter)
	}
	return s, nil
}

// NewSearchResponseEntry is a search response entry.
// Supported options: WithAttributes
func (r *Request) NewSearchResponseEntry(entryDN string, opt ...Option) *SearchResponseEntry {
	opts := getResponseOpts(opt...)
	newAttrs := make([]*EntryAttribute, 0, len(opts.withAttributes))
	for name, values := range opts.withAttributes {
		newAttrs = append(newAttrs, newEntryAttribute(name, values))
	}
	return &SearchResponseEntry{
		baseResponse: &baseResponse{
			messageID: r.message.GetID(),
		},
		entry: Entry{
			DN:         entryDN,
			Attributes: newAttrs,
		},
	}
}

func intPtr(i int) *int {
	return &i
}
