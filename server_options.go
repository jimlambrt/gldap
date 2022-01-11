package gldap

import (
	"crypto/tls"
	"time"

	"github.com/hashicorp/go-hclog"
)

type configOptions struct {
	withTLSConfig    *tls.Config
	withLogger       hclog.Logger
	withReadTimeout  time.Duration
	withWriteTimeout time.Duration
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

func WithReadTimeout(d time.Duration) Option {
	return func(o interface{}) {
		if o, ok := o.(*configOptions); ok {
			o.withReadTimeout = d
		}
	}
}

func WithWriteTimeout(d time.Duration) Option {
	return func(o interface{}) {
		if o, ok := o.(*configOptions); ok {
			o.withWriteTimeout = d
		}
	}
}
