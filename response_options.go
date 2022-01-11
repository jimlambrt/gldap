package gldap

type responseOptions struct {
	withDiagnosticMessage string
	withMatchedDN         string
	withResponseCode      *int
	withAttributes        map[string][]string
}

func responseDefaults() responseOptions {
	return responseOptions{
		withMatchedDN:         "Unused",
		withDiagnosticMessage: "Unused",
	}
}

func getResponseOpts(opt ...Option) responseOptions {
	opts := responseDefaults()
	applyOpts(&opts, opt...)
	return opts
}

func WithDiagnosticMessage(msg string) Option {
	return func(o interface{}) {
		if o, ok := o.(*responseOptions); ok {
			o.withDiagnosticMessage = msg
		}
	}
}

func WithMatchedDN(dn string) Option {
	return func(o interface{}) {
		if o, ok := o.(*responseOptions); ok {
			o.withMatchedDN = dn
		}
	}
}

func WithResponseCode(code int) Option {
	return func(o interface{}) {
		if o, ok := o.(*responseOptions); ok {
			o.withResponseCode = &code
		}
	}
}

func WithAttributes(attributes map[string][]string) Option {
	return func(o interface{}) {
		if o, ok := o.(*responseOptions); ok {
			o.withAttributes = attributes
		}
	}
}
