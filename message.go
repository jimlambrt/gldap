package gldap

import "fmt"

// Scope represents the scope of a search (see: https://ldap.com/the-ldap-search-operation/)
type Scope int64

const (
	// BaseObject (often referred to as “base”): Indicates that only the entry
	// specified as the search base should be considered. None of its
	// subordinates will be considered.
	BaseObject Scope = 0

	// SingleLevel (often referred to as “one”): Indicates that only the
	// immediate children of the entry specified as the search base should be
	// considered. The base entry itself should not be considered, nor any
	// descendants of the immediate children of the base entry.
	SingleLevel Scope = 1

	// WholeSubtree (often referred to as “sub”): Indicates that the entry
	// specified as the search base, and all of its subordinates to any depth,
	// should be considered. Note that in the special case that the search base
	// DN is the null DN, the root DSE should not be considered in a
	// wholeSubtree search.
	WholeSubtree Scope = 2
)

// AuthChoice defines the authentication choice for bind message
type AuthChoice string

// SimpleAuthChoice specifies a simple user/password authentication choice for
// the bind message
const SimpleAuthChoice AuthChoice = "simple"

type requestType string

const (
	unknownRequestType  requestType = ""
	bindRequestType     requestType = "bind"
	searchRequestType   requestType = "search"
	extendedRequestType requestType = "extended"
)

// Message defines a common interface for all messages
type Message interface {
	GetID() int64
}

// baseMessage defines a common base type for all messages (typically embedded)
type baseMessage struct {
	id int64
}

// GetID() returns the message ID
func (m baseMessage) GetID() int64 { return m.id }

// SearchMessage is a search request message
type SearchMessage struct {
	baseMessage
	// BaseObject for the request
	BaseDN string
	// Scope of the request
	Scope Scope
	// DerefAliases for the request
	DerefAliases int
	// TimeLimit is the max time in seconds to spend processing
	TimeLimit int64
	// SizeLimit is the max number of results to return
	SizeLimit int64
	// TypesOnly is true if the client only expects type info
	TypesOnly bool
	// Filter for the request
	Filter string
	// Attributes requested
	Attributes []string
	// Controls requested
	Controls []Control
}

type Control string

// SimpleBindMesssage is a simple bind request message
type SimpleBindMessage struct {
	baseMessage
	// AuthChoice for the request (SimpleAuthChoice)
	AuthChoice AuthChoice
	// UserName for the bind request
	UserName string
	// Password for the bind request
	Password Password
}

// ExtendedOperationMessage is an extended operation request message
type ExtendedOperationMessage struct {
	baseMessage
	// Name of the extended operation
	Name ExtendedOperationName
	// Value of the extended operation
	Value string
}

// NewMessage will create a new message from the packet.
func NewMessage(p *packet) (Message, error) {
	const op = "gldap.NewMessage"

	reqType, err := p.requestType()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	msgID, err := p.requestMessageID()
	if err != nil {
		return nil, fmt.Errorf("%s: unable to get message id: %w", op, err)
	}

	switch reqType {
	case bindRequestType:
		u, pass, err := p.simpleBindParameters()
		if err != nil {
			return nil, fmt.Errorf("%s: invalid bind message: %w", op, err)
		}
		return &SimpleBindMessage{
			baseMessage: baseMessage{
				id: msgID,
			},
			UserName:   u,
			Password:   pass,
			AuthChoice: SimpleAuthChoice,
		}, nil
	case searchRequestType:
		parameters, err := p.searchParmeters()
		if err != nil {
			return nil, fmt.Errorf("%s: invalid search message: %w", op, err)
		}
		return &SearchMessage{
			baseMessage: baseMessage{
				id: msgID,
			},
			BaseDN:       parameters.baseDN,
			Scope:        Scope(parameters.scope),
			DerefAliases: int(parameters.derefAliases),
			SizeLimit:    parameters.sizeLimit,
			TimeLimit:    parameters.timeLimit,
			TypesOnly:    parameters.typesOnly,
			Filter:       parameters.filter,
			Attributes:   parameters.attributes,
			Controls:     parameters.controls,
		}, nil
	case extendedRequestType:
		opName, err := p.extendedOperationName()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		return &ExtendedOperationMessage{
			baseMessage: baseMessage{
				id: msgID,
			},
			Name: opName,
		}, nil
	default:
		return &ExtendedOperationMessage{
			baseMessage: baseMessage{
				id: msgID,
			},
			Name: ExtendedOperationUnknown,
		}, nil
	}
}