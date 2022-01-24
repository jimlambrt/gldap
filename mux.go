package gldap

import (
	"fmt"
	"sync"

	"github.com/go-ldap/ldap/v3"
)

// Mux is an ldap request multiplexer. It matches the inbound request against a
// list of registered route handlers. Routes are matched in the order they're
// added and only one route is called per request.
type Mux struct {
	mu           sync.Mutex
	routes       []route
	defaultRoute route
}

// NewMux creates a new multiplexer.
func NewMux(opt ...Option) (*Mux, error) {
	return &Mux{
		routes: []route{},
	}, nil
}

// Bind will register a handler for bind requests.
// Options supported: WithLabel
func (m *Mux) Bind(bindFn HandlerFunc, opt ...Option) error {
	const op = "gldap.(Mux).Bind"
	if bindFn == nil {
		return fmt.Errorf("%s: missing HandlerFunc: %w", op, ErrInvalidParameter)
	}
	opts := getRouteOpts(opt...)

	r := &simpleBindRoute{
		baseRoute: &baseRoute{
			h:       bindFn,
			routeOp: bindRoute,
			label:   opts.withLabel,
		},
		authChoice: SimpleAuthChoice,
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.routes = append(m.routes, r)
	return nil
}

// Search will register a handler for search requests.
func (m *Mux) Search(searchFn HandlerFunc, opt ...Option) error {
	const op = "gldap.(Mux).Search"
	if searchFn == nil {
		return fmt.Errorf("%s: missing HandlerFunc: %w", op, ErrInvalidParameter)
	}
	opts := getRouteOpts(opt...)
	r := &searchRoute{
		baseRoute: &baseRoute{
			h:       searchFn,
			routeOp: searchRouteOperation,
			label:   opts.withLabel,
		},
		basedn: opts.withBaseDN,
		filter: opts.withFilter,
		scope:  opts.withScope,
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.routes = append(m.routes, r)
	return nil
}

// ExtendedOperation will register a handler for extended operation requests.
func (m *Mux) ExtendedOperation(operationFn HandlerFunc, exName ExtendedOperationName, opt ...Option) error {
	const op = "gldap.(Mux).Search"
	if operationFn == nil {
		return fmt.Errorf("%s: missing HandlerFunc: %w", op, ErrInvalidParameter)
	}
	opts := getRouteOpts(opt...)
	r := &extendedRoute{
		baseRoute: &baseRoute{
			h:       operationFn,
			routeOp: extendedRouteOperation,
			label:   opts.withLabel,
		},
		extendedName: exName,
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.routes = append(m.routes, r)
	return nil
}

// DefaultRoute will register a default handler requests which have no other
// registered handler.
func (m *Mux) DefaultRoute(noRouteFN HandlerFunc, opt ...Option) error {
	const op = "gldap.(Mux).Bind"
	if noRouteFN == nil {
		return fmt.Errorf("%s: missing HandlerFunc: %w", op, ErrInvalidParameter)
	}
	r := &baseRoute{
		h:       noRouteFN,
		routeOp: bindRoute,
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.routes = append(m.routes, r)
	return nil
}

// Routes returns the registered routes along with the registered default route
func (m *Mux) Routes() ([]route, route) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// return a copy of the routes slice
	return append([]route{}, m.routes...), m.defaultRoute
}

// serveRequests will find a matching route to serve the request
func (m *Mux) serve(w *ResponseWriter, req *Request) {
	const op = "gldap.(Mux).serve"
	defer func() {
		w.logger.Debug("finished serving request", "op", op, "connID", w.connID, "requestID", w.requestID)
	}()
	if w == nil {
		// this should be unreachable, and if it is then we'll just panic
		panic(fmt.Errorf("%s: %d/%d missing response writer: %w", op, w.connID, w.requestID, ErrInternal).Error())
	}
	if req == nil {
		w.logger.Error("missing request", "op", op, "connID", w.connID, "requestID", w.requestID)
		return
	}

	// find the first matching route to dispatch the request to and then return
	for _, r := range m.routes {
		if !r.match(req) {
			continue
		}
		h := r.handler()
		if h == nil {
			w.logger.Error("route is missing handler", "op", op, "connID", w.connID, "requestID", w.requestID, "route", r.op)
			return
		}
		// the handler intentionally doesn't return errors, since we want the
		// handler to response to the connection's client with errors.
		h(w, req)
		return
	}
	if m.defaultRoute != nil {
		h := m.defaultRoute.handler()
		h(w, req)
		return
	}
	w.logger.Error("no matching handler found for request and returning internal error", "op", op, "connID", w.connID, "requestID", w.requestID, "routeOp", req.routeOp)
	resp := req.NewResponse(WithResponseCode(ldap.LDAPResultUnwillingToPerform), WithDiagnosticMessage("No matching handler found"))
	_ = w.Write(resp)
}