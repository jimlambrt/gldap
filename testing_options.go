package gldap

// TestOption defines a common functional options type which can be used in a
// variadic parameter pattern.
type TestOption func(interface{})

// getTestOpts gets the test defaults and applies the opt
// overrides passed in
func getTestOpts(t TestingT, opt ...TestOption) testOptions {
	if v, ok := interface{}(t).(HelperT); ok {
		v.Helper()
	}
	opts := testDefaults(t)
	testApplyOpts(&opts, opt...)
	return opts
}

// testApplyOpts takes a pointer to the options struct as a set of default options
// and applies the slice of opts as overrides.
func testApplyOpts(opts interface{}, opt ...TestOption) {
	for _, o := range opt {
		if o == nil { // ignore any nil Options
			continue
		}
		o(opts)
	}
}

// testOptions are the set of available options for test functions
type testOptions struct {
	withMTLS bool
}

func testDefaults(t TestingT) testOptions {
	if v, ok := interface{}(t).(HelperT); ok {
		v.Helper()
	}
	return testOptions{}
}

// WithTestMTLS provides the option to use mTLS for the test directory.
//
// Valid for: StartDirectory(...)
func WithTestMTLS() TestOption {
	return func(o interface{}) {
		if o, ok := o.(*testOptions); ok {
			o.withMTLS = true
		}
	}
}
