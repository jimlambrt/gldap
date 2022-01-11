package gldap

import ber "gopkg.in/asn1-ber.v1"

type messageOptions struct {
	withMinChildren *int
	withLenChildren *int
	withAssertChild *int
	withTag         *ber.Tag
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
