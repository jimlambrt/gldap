package gldap

import (
	"crypto/tls"
	"fmt"
)

type Request struct {
	ID int
	// conn is needed this for cancellation among other things.
	conn         *Conn
	Message      Message
	RouteOp      RouteOperation
	ExtendedName string
}

func NewRequest(id int, c *Conn, p *packet) (*Request, error) {
	const op = "ldap.NewRequest"
	if c == nil {
		return nil, fmt.Errorf("%s: missing connection: %w", op, ErrInvalidParameter)
	}
	if p == nil {
		return nil, fmt.Errorf("%s: missing ber packet: %w", op, ErrInvalidParameter)
	}

	m, err := NewMessage(p)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to build message for request %d: %w", op, id, err)
	}
	var extendedName string
	var routeOp RouteOperation
	switch v := m.(type) {
	case SimpleBindMessage:
		routeOp = BindRoute
	case SearchMessage:
		routeOp = SearchRoute
	case ExtendedOperationMessage:
		routeOp = ExtendedOperationRoute
		extendedName = v.Name
	default:
		panic("todo")
	}

	// TODO: determine routeOperation, message, and name
	r := &Request{
		ID:           id,
		conn:         c,
		Message:      m,
		RouteOp:      routeOp,
		ExtendedName: extendedName,
	}
	return r, nil
}

// StartTLS will start a TLS connection using the Message's existing connection
func (r *Request) StartTLS(tlsconfig *tls.Config) error {
	const op = "ldap.(Message).StartTLS"
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
