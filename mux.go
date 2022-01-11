package gldap

import "fmt"

// Mux is an ldap request multiplexer. It matches the inbound request against a
// list of registered route handlers. Routes are matched in the order they're
// added and only one route is called per request.
type Mux struct {
	routes       []route
	defaultRoute route
}

// NewMux creates a new multiplexer.
func NewMux(opt ...Option) (*Mux, error) {
	return &Mux{}, nil
}

// Bind will register a handler for bind requests.
func (m *Mux) Bind(bindFn HandlerFunc, opt ...Option) error {
	panic("todo")
}

// Search will register a handler for search requests.
func (m *Mux) Search(searchFn HandlerFunc, opt ...Option) error {
	panic("todo")
}

// ExtendedOperation will register a handler for extended operation requests.
func (m *Mux) ExtendedOperation(operationFn HandlerFunc, exName string, opt ...Option) error {
	panic("todo")
}

// DefaultRoute will register a default handler requests which have no other
// registered handler.
func (m *Mux) DefaultRoute(noRouteFN HandlerFunc, opt ...Option) error {
	panic("todo")
}

// Routes returns the registered routes along with the registered default route
func (m *Mux) Routes() ([]route, route) {
	return m.routes, m.defaultRoute
}

// serveRequests will find a matching route to serve the request
func (m *Mux) serve(w *ResponseWriter, requestID int, req *Request) {
	const op = "ldap.(Mux).serveRequest"
	if m == nil {
		w.WriteErrorResponse(req, fmt.Errorf("%s: %d/%d missing mux: %w", op, w.conn.connID, requestID, ErrInternal))
		return
	}
	if w == nil {
		w.WriteErrorResponse(req, fmt.Errorf("%s: %d/%d missing response writer: %w", op, w.conn.connID, requestID, ErrInternal))
		return
	}
	if req == nil {
		w.WriteErrorResponse(req, fmt.Errorf("%s: %d/%d missing request: %w", op, w.conn.connID, requestID, ErrInternal))
		return
	}

	// find the first matching route to dispatch the request to and then reture
	for _, r := range m.routes {
		if !r.match(req) {
			continue
		}
		h := r.handler()
		if h == nil {
			w.WriteErrorResponse(req, fmt.Errorf("%s: %s route is missing handler: %w", op, r.op(), ErrInternal))
			return
		}
		// the handler intentionally doesn't return errors, since we want the
		// handler to response to the connection's client with errors.
		h(w, req)
		return
	}
	w.WriteErrorResponse(req, fmt.Errorf("%s: no matching handler found for request (%d/%d %s): %w", op, w.conn.connID, requestID, req.RouteOp, ErrInternal))
}
