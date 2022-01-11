package gldap

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/hashicorp/go-hclog"
)

// Conn is a connection to an ldap client
type Conn struct {
	mu sync.Mutex

	connID      int
	netConn     net.Conn
	logger      hclog.Logger
	router      *Mux
	shutdownCtx context.Context
	requestsWg  sync.WaitGroup
	reader      *bufio.Reader
	writer      *bufio.Writer
}

// NewConn will create a new Conn from an accepted net.Conn which will be used
// to serve requests to an ldap client.
func NewConn(shutdownCtx context.Context, connID int, c net.Conn, logger hclog.Logger, router *Mux) (*Conn, error) {
	const op = "ldap.NewConn"
	if connID == 0 {
		return nil, fmt.Errorf("%s: missing connection id: %w", op, ErrInvalidParameter)
	}
	if c == nil {
		return nil, fmt.Errorf("%s: missing connection: %w", op, ErrInvalidParameter)
	}
	if logger == nil {
		return nil, fmt.Errorf("%s: missing logger: %w", op, ErrInvalidParameter)
	}
	if router == nil {
		return nil, fmt.Errorf("%s: missing router: %w", op, ErrInvalidParameter)
	}
	conn := &Conn{
		connID:      connID,
		netConn:     c,
		shutdownCtx: shutdownCtx,
		logger:      logger,
		router:      router,
	}
	if err := conn.initConn(c); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return conn, nil
}

// serveRequests until the connection is closed or the shutdownCtx is cancelled
// as the server stops
func (c *Conn) serveRequests() error {
	const op = "gldap.serveRequests"

	requestID := 0
	for {
		requestID += 1
		select {
		case <-c.shutdownCtx.Done():
			return nil
		default:
			// need a default to fall through to rest of loop...
		}
		// TODO - match router handlers, goroutine for each request
		r, err := c.readRequest(requestID)
		if err == io.EOF || strings.Contains(err.Error(), "unexpected EOF") {
			return nil // connection is closed
		}
		if err != nil {
			return fmt.Errorf("%s: error reading request: %w %t", op, err, err)
		}
		c.logger.Debug("request", "op", op, "conn", c.connID, "requestID", requestID, "req-data", fmt.Sprintf("%+v", r))

		w, err := NewResponseWriter(c)
		if err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}
		c.requestsWg.Add(1)
		go func() {
			localRequestID := requestID
			defer c.requestsWg.Done()
			c.router.serve(w, localRequestID, r)
		}()
	}
}

func (c *Conn) readRequest(requestID int) (*Request, error) {
	const op = "gldap.(Conn).readRequest"

	p, err := c.readPacket(requestID, c.reader)
	if err != nil {
		return nil, fmt.Errorf("%s: error reading packet for %d/%d:  %w", op, c.connID, requestID, err)
	}
	if c.logger.IsDebug() {
		c.logger.Debug("packet read", "op", op, "conn", c.connID, "requestID", requestID)
		p.Log(c.logger.StandardWriter(&hclog.StandardLoggerOptions{}), 0, false)
	}
	r, err := NewRequest(requestID, c, p)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create new in-memory request for %d/%d: %w", op, c.connID, requestID, err)
	}

	return r, nil
}

func (c *Conn) initConn(conn net.Conn) error {
	const op = "ldap.(Conn).initConn"
	if c == nil {
		return fmt.Errorf("%s: missing connection: %w", op, ErrInvalidParameter)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.netConn = conn
	c.reader = bufio.NewReader(c.netConn)
	c.writer = bufio.NewWriter(c.netConn)
	return nil
}

func (c *Conn) close() error {
	c.requestsWg.Wait()
	c.netConn.Close()
	return nil
}
