package gldap

import "fmt"

type ResponseWriter struct {
	conn *Conn
}

func NewResponseWriter(c *Conn) (*ResponseWriter, error) {
	const op = "ldap.NewResponseWriter"
	if c == nil {
		return nil, fmt.Errorf("%s: missing conn: %w", op, ErrInvalidParameter)
	}
	return &ResponseWriter{conn: c}, nil
}
func (w *ResponseWriter) WriteErrorResponse(req *Request, err error) {
	const op = "ldap.WriteErrorResponse"
	w.conn.logger.Error("#############################################")
	w.conn.logger.Error("TODO: proper implementation", "op", op, "err", err)
	w.conn.logger.Error("#############################################")
}
