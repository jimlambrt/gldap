package gldap

import ber "github.com/go-asn1-ber/asn1-ber"

type messageOptions struct {
	withMinChildren     *int
	withLenChildren     *int
	withAssertChild     *int
	withTag             *ber.Tag
	withApplicationCode int
}

func messageDefaults() messageOptions {
	return messageOptions{}
}

func getMessageOpts(opt ...Option) messageOptions {
	opts := messageDefaults()
	applyOpts(&opts, opt...)
	return opts
}

func withMinChildren(min int) Option {
	return func(o interface{}) {
		if o, ok := o.(*messageOptions); ok {
			o.withMinChildren = &min
		}
	}
}

func withLenChildren(len int) Option {
	return func(o interface{}) {
		if o, ok := o.(*messageOptions); ok {
			o.withLenChildren = &len
		}
	}
}

func withAssertChild(idx int) Option {
	return func(o interface{}) {
		if o, ok := o.(*messageOptions); ok {
			o.withAssertChild = &idx
		}
	}
}

func withTag(t ber.Tag) Option {
	return func(o interface{}) {
		if o, ok := o.(*messageOptions); ok {
			o.withTag = &t
		}
	}
}

// for a list of supported application codes see:
// https://github.com/go-ldap/ldap/blob/13008e4c5260d08625b65eb1f172ae909152b751/v3/ldap.go#L11
func WithApplicationCode(ldapApplicationCode int) Option {
	return func(o interface{}) {
		if o, ok := o.(*messageOptions); ok {
			o.withApplicationCode = ldapApplicationCode
		}
	}
}
