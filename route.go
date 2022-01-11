package gldap

import (
	"strings"
)

// RouteOperation represents the ldap operation for a route.
type RouteOperation string

const (
	// UndefinedRoute is an undefined operation.
	UndefinedRoute RouteOperation = ""

	// BindRoute is a route supporting the bind operation
	BindRoute RouteOperation = "bind"

	// SearchRoute is a route supporting the search operation
	SearchRoute RouteOperation = "search"

	// ExtendedOperationRoute is a route supporting an extended operation
	ExtendedOperationRoute RouteOperation = "extendedOperation"

	// DefaultRoute is a default route which is used when there are no routes
	// defined for a particular operation
	DefaultRoute RouteOperation = "noRoute"
)

type HandlerFunc func(*ResponseWriter, *Request)

type route interface {
	match(req *Request) bool
	handler() HandlerFunc // implemetn
	op() string
}

type baseRoute struct {
	h     HandlerFunc
	op    RouteOperation
	label string
}

func (r *baseRoute) handler() HandlerFunc {
	return r.h
}

func (r *baseRoute) Op() RouteOperation {
	return r.op
}

type searchRoute struct {
	*baseRoute
	basedn string
	filter string
	scope  int
}

type simpleBindRoute struct {
	*baseRoute
	authChoice AuthChoice
}

type extendedRoute struct {
	*baseRoute
	extendedName string
}

func (r *simpleBindRoute) match(req *Request) bool {
	if req == nil {
		return false
	}
	if r.op != req.RouteOp {
		return false
	}
	if m, ok := req.Message.(*SimpleBindMessage); ok {
		// TODO: define const for these auth choices
		if r.authChoice != "" && r.authChoice == m.AuthChoice {
			return true
		}
	}
	return false
}

func (r *extendedRoute) match(req *Request) bool {
	if r.op != req.RouteOp {
		return false
	}
	if r.extendedName != req.ExtendedName {
		return false
	}
	return true
}

func (r *searchRoute) match(req *Request) bool {
	if r.op != req.RouteOp {
		return false
	}
	searchMsg, ok := req.Message.(SearchMessage)
	if !ok {
		return false
	}
	if r.basedn != "" && strings.ToLower(searchMsg.BaseObject) != strings.ToLower(r.basedn) {
		return false
	}
	if r.filter != "" && strings.ToLower(searchMsg.Filter) != strings.ToLower(r.filter) {
		return false
	}
	if r.scope != 0 && int(searchMsg.Scope) != r.scope {
		return false
	}

	// if it didn't get eliminated by earlier request criteria, then it's a
	// match.
	return true
}
