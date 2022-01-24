package gldap

import (
	"strings"
)

// routeOperation represents the ldap operation for a route.
type routeOperation string

const (
	// undefinedRouteOperation is an undefined operation.
	undefinedRouteOperation routeOperation = ""

	// bindRoute is a route supporting the bind operation
	bindRoute routeOperation = "bind"

	// searchRouteOperation is a route supporting the search operation
	searchRouteOperation routeOperation = "search"

	// extendedRouteOperation is a route supporting an extended operation
	extendedRouteOperation routeOperation = "extendedOperation"

	// defaultRouteOperation is a default route which is used when there are no routes
	// defined for a particular operation
	defaultRouteOperation routeOperation = "noRoute"
)

type HandlerFunc func(*ResponseWriter, *Request)

type route interface {
	match(req *Request) bool
	handler() HandlerFunc
	op() routeOperation
}

type baseRoute struct {
	h       HandlerFunc
	routeOp routeOperation
	label   string
}

func (r *baseRoute) handler() HandlerFunc {
	return r.h
}

func (r *baseRoute) op() routeOperation {
	return r.routeOp
}

func (r *baseRoute) match(req *Request) bool {
	return false
}

type searchRoute struct {
	*baseRoute
	basedn string
	filter string
	scope  Scope
}

type simpleBindRoute struct {
	*baseRoute
	authChoice AuthChoice
}

type extendedRoute struct {
	*baseRoute
	extendedName ExtendedOperationName
}

func (r *simpleBindRoute) match(req *Request) bool {
	if req == nil {
		return false
	}
	if r.routeOp != req.routeOp {
		return false
	}
	if m, ok := req.message.(*SimpleBindMessage); ok {
		if r.authChoice != "" && r.authChoice == m.AuthChoice {
			return true
		}
	}
	return false
}

func (r *extendedRoute) match(req *Request) bool {
	if r.routeOp != req.routeOp {
		return false
	}
	if r.extendedName != req.extendedName {
		return false
	}
	return true
}

func (r *searchRoute) match(req *Request) bool {
	if r.routeOp != req.routeOp {
		return false
	}
	searchMsg, ok := req.message.(*SearchMessage)
	if !ok {
		return false
	}
	if r.basedn != "" && strings.ToLower(searchMsg.BaseDN) != strings.ToLower(r.basedn) {
		return false
	}
	if r.filter != "" && strings.ToLower(searchMsg.Filter) != strings.ToLower(r.filter) {
		return false
	}
	if r.scope != 0 && searchMsg.Scope != r.scope {
		return false
	}

	// if it didn't get eliminated by earlier request criteria, then it's a
	// match.
	return true
}
