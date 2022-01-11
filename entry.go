package gldap

import (
	"sort"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// Entry represents an ldap entry
type Entry struct {
	// DN is the distinguished name of the entry
	DN string
	// Attributes are the returned attributes for the entry
	Attributes []*EntryAttribute
}

// GetAttributeValues returns the values for the named attribute, or an empty list
func (e *Entry) GetAttributeValues(attribute string) []string {
	for _, attr := range e.Attributes {
		if attr.Name == attribute {
			return attr.Values
		}
	}
	return []string{}
}

// TestEntry returns an Entry object with the specified distinguished name and attribute key-value pairs.
// The map of attributes is accessed in alphabetical order of the keys in order to ensure that, for the
// same input map of attributes, the output entry will contain the same order of attributes
func NewEntry(dn string, attributes map[string][]string) *Entry {
	var attributeNames []string
	for attributeName := range attributes {
		attributeNames = append(attributeNames, attributeName)
	}
	sort.Strings(attributeNames)

	var encodedAttributes []*EntryAttribute
	for _, attributeName := range attributeNames {
		encodedAttributes = append(encodedAttributes, newEntryAttribute(attributeName, attributes[attributeName]))
	}
	return &Entry{
		DN:         dn,
		Attributes: encodedAttributes,
	}
}

// EntryAttribute holds a single attribute
type EntryAttribute struct {
	// Name is the name of the attribute
	Name string
	// Values contain the string values of the attribute
	Values []string
	// ByteValues contain the raw values of the attribute
	ByteValues [][]byte
}

// newEntryAttribute returns a new EntryAttribute with the desired key-value pair
func newEntryAttribute(name string, values []string) *EntryAttribute {
	var bytes [][]byte
	for _, value := range values {
		bytes = append(bytes, []byte(value))
	}
	return &EntryAttribute{
		Name:       name,
		Values:     values,
		ByteValues: bytes,
	}
}

func (a *EntryAttribute) encode() *ber.Packet {
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attribute")
	seq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, a.Name, "Type"))
	set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "AttributeValue")
	for _, value := range a.Values {
		set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, "Vals"))
	}
	seq.AppendChild(set)
	return seq
}
