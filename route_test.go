package gldap

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSearchRoute_match(t *testing.T) {
	tests := []struct {
		name      string
		route     *searchRoute
		req       *Request
		wantMatch bool
	}{
		{
			name: "req-nil",
			route: &searchRoute{
				baseRoute: &baseRoute{
					routeOp: searchRouteOperation,
				},
			},
		},
		{
			name: "op-mismatched",
			route: &searchRoute{
				baseRoute: &baseRoute{
					routeOp: searchRouteOperation,
				},
			},
			req: &Request{
				routeOp: bindRouteOperation,
			},
		},
		{
			name: "not-a-search-msg",
			route: &searchRoute{
				baseRoute: &baseRoute{
					routeOp: searchRouteOperation,
				},
			},
			req: &Request{
				routeOp: searchRouteOperation,
				message: &SimpleBindMessage{},
			},
		},
		{
			name: "baseDN-match",
			route: &searchRoute{
				baseRoute: &baseRoute{
					routeOp: searchRouteOperation,
				},
				basedn: "ou=people,dc=example,dc=com",
			},
			req: &Request{
				routeOp: searchRouteOperation,
				message: &SearchMessage{
					BaseDN: "ou=people,dc=example,dc=com",
				},
			},
			wantMatch: true,
		},
		{
			name: "baseDN-mismatch",
			route: &searchRoute{
				baseRoute: &baseRoute{
					routeOp: searchRouteOperation,
				},
				basedn: "ou=people,dc=example,dc=com",
			},
			req: &Request{
				routeOp: searchRouteOperation,
				message: &SearchMessage{
					BaseDN: "ou=people,dc=alice,dc=com",
				},
			},
		},
		{
			name: "filter-match",
			route: &searchRoute{
				baseRoute: &baseRoute{
					routeOp: searchRouteOperation,
				},
				filter: "(uid=alice)",
			},
			req: &Request{
				routeOp: searchRouteOperation,
				message: &SearchMessage{
					Filter: "(uid=alice)",
				},
			},
			wantMatch: true,
		},
		{
			name: "filter-mismatch",
			route: &searchRoute{
				baseRoute: &baseRoute{
					routeOp: searchRouteOperation,
				},
				filter: "(uid=alice)",
			},
			req: &Request{
				routeOp: searchRouteOperation,
				message: &SearchMessage{
					Filter: "(uid=bob)",
				},
			},
		},
		{
			name: "scope-match",
			route: &searchRoute{
				baseRoute: &baseRoute{
					routeOp: searchRouteOperation,
				},
				scope: SingleLevel,
			},
			req: &Request{
				routeOp: searchRouteOperation,
				message: &SearchMessage{
					Scope: SingleLevel,
				},
			},
			wantMatch: true,
		},
		{
			name: "scope-mismatch",
			route: &searchRoute{
				baseRoute: &baseRoute{
					routeOp: searchRouteOperation,
				},
				scope: WholeSubtree,
			},
			req: &Request{
				routeOp: searchRouteOperation,
				message: &SearchMessage{
					Scope: SingleLevel,
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			match := tc.route.match(tc.req)
			switch tc.wantMatch {
			case true:
				assert.True(match)
			case false:
				assert.False(match)
			}
		})
	}
}

func TestSimpleBindRoute_match(t *testing.T) {
	tests := []struct {
		name      string
		route     *simpleBindRoute
		req       *Request
		wantMatch bool
	}{
		{
			name: "req-nil",
			route: &simpleBindRoute{
				baseRoute: &baseRoute{
					routeOp: searchRouteOperation,
				},
			},
		},
		{
			name: "op-mismatched",
			route: &simpleBindRoute{
				baseRoute: &baseRoute{
					routeOp: bindRouteOperation,
				},
			},
			req: &Request{
				routeOp: searchRouteOperation,
			},
		},
		{
			name: "not-a-bind-msg",
			route: &simpleBindRoute{
				baseRoute: &baseRoute{
					routeOp: bindRouteOperation,
				},
			},
			req: &Request{
				routeOp: bindRouteOperation,
				message: &SearchMessage{},
			},
		},
		{
			name: "authChoice-mismatched",
			route: &simpleBindRoute{
				baseRoute: &baseRoute{
					routeOp: bindRouteOperation,
				},
				authChoice: SimpleAuthChoice,
			},
			req: &Request{
				routeOp: bindRouteOperation,
				message: &SimpleBindMessage{
					AuthChoice: "mismatched",
				},
			},
		},
		{
			name: "authChoice-matched",
			route: &simpleBindRoute{
				baseRoute: &baseRoute{
					routeOp: bindRouteOperation,
				},
				authChoice: SimpleAuthChoice,
			},
			req: &Request{
				routeOp: bindRouteOperation,
				message: &SimpleBindMessage{
					AuthChoice: SimpleAuthChoice,
				},
			},
			wantMatch: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			match := tc.route.match(tc.req)
			switch tc.wantMatch {
			case true:
				assert.True(match)
			case false:
				assert.False(match)
			}
		})
	}
}

func TestExtendedRoute_match(t *testing.T) {
	tests := []struct {
		name      string
		route     *extendedRoute
		req       *Request
		wantMatch bool
	}{
		{
			name: "req-nil",
			route: &extendedRoute{
				baseRoute: &baseRoute{
					routeOp: extendedRouteOperation,
				},
			},
		},
		{
			name: "op-mismatched",
			route: &extendedRoute{
				baseRoute: &baseRoute{
					routeOp: extendedRouteOperation,
				},
			},
			req: &Request{
				routeOp: searchRouteOperation,
			},
		},
		{
			name: "not-a-extended-op-msg",
			route: &extendedRoute{
				baseRoute: &baseRoute{
					routeOp: extendedRouteOperation,
				},
			},
			req: &Request{
				routeOp: extendedRouteOperation,
				message: &SearchMessage{},
			},
		},
		{
			name: "extended-name-mismatched",
			route: &extendedRoute{
				baseRoute: &baseRoute{
					routeOp: extendedRouteOperation,
				},
				extendedName: ExtendedOperationStartTLS,
			},
			req: &Request{
				routeOp:      extendedRouteOperation,
				message:      &ExtendedOperationMessage{},
				extendedName: ExtendedOperationDisconnection,
			},
		},
		{
			name: "extended-name-matched",
			route: &extendedRoute{
				baseRoute: &baseRoute{
					routeOp: extendedRouteOperation,
				},
				extendedName: ExtendedOperationStartTLS,
			},
			req: &Request{
				routeOp:      extendedRouteOperation,
				message:      &ExtendedOperationMessage{},
				extendedName: ExtendedOperationStartTLS,
			},
			wantMatch: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			match := tc.route.match(tc.req)
			switch tc.wantMatch {
			case true:
				assert.True(match)
			case false:
				assert.False(match)
			}
		})
	}
}
