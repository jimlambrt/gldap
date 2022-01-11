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

const (
	minChildren     = 2 // messageID packet + Request packet
	requestChildIdx = 1 // starting at 0, this is the second child packet

	requestVersionIdx      = 0 // first child of a request
	requestBindUserNameIdx = 1 // second child of a bind request
	requestBindPasswordIdx = 2 // third child of a bind request
)

type requestType string

const (
	unknownRequestType requestType = ""
	bindRequestType    requestType = "bind"
	searchRequestType  requestType = "search"
)

// Message defines a common interface for all messages
type Message interface {
	GetPacket() *packet
	GetID() string
}

// BaseMessage defines a common base type for all messages (typically embedded)
type BaseMessage struct {
	Packet *packet
	ID     string
}

// GetPacket returns the message packet
func (m BaseMessage) GetPacket() *packet { return m.Packet }

// GetID() returns the message ID
func (m BaseMessage) GetID() string { return m.ID }

// SearchMessage is a search request message
type SearchMessage struct {
	BaseMessage
	BaseObject string
	Filter     string
	Scope      Scope
	Attributes []string
}

// SimpleBindMesssage is a simple bind request message
type SimpleBindMessage struct {
	BaseMessage
	AuthChoice AuthChoice
	UserName   string
	Password   Password
}

// ExtendedOperationMessage is an extended operation request message
type ExtendedOperationMessage struct {
	BaseMessage
	Name  string
	Value string
}

// NewMessage will create a new message from the packet.
func NewMessage(p *packet) (Message, error) {
	const op = "ldap.BuildMessage"

	reqType, err := p.requestType()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	switch reqType {
	case bindRequestType:
		u, p, err := p.simpleBindParameters()
		if err != nil {
			return nil, fmt.Errorf("%s: invalid bind message: %w", op, err)
		}
		return &SimpleBindMessage{
			BaseMessage: BaseMessage{},
			UserName:    u,
			Password:    p,
			AuthChoice:  SimpleAuthChoice,
		}, nil
	case searchRequestType:
		panic("todo")
	default:
		return nil, fmt.Errorf("%s: unhandled request type %s: %w", op, reqType, ErrInternal)
	}
}
