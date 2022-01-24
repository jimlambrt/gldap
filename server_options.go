package gldap

import (
	"crypto/tls"
	"time"

	"github.com/hashicorp/go-hclog"
)

type configOptions struct {
	withTLSConfig            *tls.Config
	withLogger               hclog.Logger
	withReadTimeout          time.Duration
	withWriteTimeout         time.Duration
	withDisablePanicRecovery bool
}

func configDefaults() configOptions {
	return configOptions{}
}

// getConfigOpts gets the defaults and applies the opt overrides passed
// in.
func getConfigOpts(opt ...Option) configOptions {
	opts := configDefaults()
	applyOpts(&opts, opt...)
	return opts
}

// WithLogger provides the optional logger.
func WithLogger(l hclog.Logger) Option {
	return func(o interface{}) {
		if o, ok := o.(*configOptions); ok {
			o.withLogger = l
		}
	}
}

// WithTLSConfig provides an optional tls.Config
func WithTLSConfig(tc *tls.Config) Option {
	return func(o interface{}) {
		switch v := o.(type) {
		case *configOptions:
			v.withTLSConfig = tc
		}
	}
}

// WithReadTimeout will set a read time out per connection
func WithReadTimeout(d time.Duration) Option {
	return func(o interface{}) {
		if o, ok := o.(*configOptions); ok {
			o.withReadTimeout = d
		}
	}
}

// WithWriteTimeout will set a write timeout per connection
func WithWriteTimeout(d time.Duration) Option {
	return func(o interface{}) {
		if o, ok := o.(*configOptions); ok {
			o.withWriteTimeout = d
		}
	}
}

// WithDisablePanicRecovery will disable recovery from panics which occur when
// handling a request.  This is helpful for debugging since you'll get the
// panic's callstack.
func WithDisablePanicRecovery() Option {
	return func(o interface{}) {
		if o, ok := o.(*configOptions); ok {
			o.withDisablePanicRecovery = true
		}
	}
}
