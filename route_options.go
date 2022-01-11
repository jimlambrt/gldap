package gldap

type routeOptions struct {
	withLabel  string
	withBaseDN string
	withFilter string
	withScope  Scope
}

func routeDefaults() routeOptions {
	return routeOptions{}
}

func getRouteOpts(opt ...Option) routeOptions {
	opts := routeDefaults()
	applyOpts(&opts, opt...)
	return opts
}

func WithLabel(l string) Option {
	return func(o interface{}) {
		if o, ok := o.(*routeOptions); ok {
			o.withLabel = l
		}
	}
}

func WithBaseDN(dn string) Option {
	return func(o interface{}) {
		if o, ok := o.(*routeOptions); ok {
			o.withBaseDN = dn
		}
	}
}

func WithFilter(filter string) Option {
	return func(o interface{}) {
		if o, ok := o.(*routeOptions); ok {
			o.withFilter = filter
		}
	}
}

func WithScope(s Scope) Option {
	return func(o interface{}) {
		if o, ok := o.(*routeOptions); ok {
			o.withScope = s
		}
	}
}
