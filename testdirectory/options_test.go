package testdirectory

import (
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/jimlambrt/gldap"
	"github.com/stretchr/testify/assert"
)

func TestAllOptions(t *testing.T) {
	testLogger := hclog.New(&hclog.LoggerOptions{
		Name:  "my-app",
		Level: hclog.LevelFromString("DEBUG"),
	})
	t.Run("WithDefaults", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(t,
			WithLogger(t, testLogger),
			WithDefaults(t, &Defaults{
				UserAttr:  "user-attr",
				GroupAttr: "grp-attr",
				Users:     NewUsers(t, []string{"alice"}),
				Groups:    []*gldap.Entry{NewGroup(t, "admin", []string{"alice"})},
				UserDN:    "user-dn",
				GroupDN:   "grp-dn",
				TokenGroups: map[string][]*gldap.Entry{
					"S-1-1": {
						NewGroup(t, "admin", []string{"alice"}),
					},
				},
				AllowAnonymousBind: true,
				UPNDomain:          "domain",
			}))
		testOpts := defaults(t)
		testOpts.withLogger = testLogger
		testOpts.withDefaults.UserAttr = "user-attr"
		testOpts.withDefaults.GroupAttr = "grp-attr"
		testOpts.withDefaults.UserDN = "user-dn"
		testOpts.withDefaults.GroupDN = "grp-dn"
		testOpts.withDefaults.Users = NewUsers(t, []string{"alice"})
		testOpts.withDefaults.Groups = []*gldap.Entry{NewGroup(t, "admin", []string{"alice"})}
		testOpts.withDefaults.TokenGroups = map[string][]*gldap.Entry{
			"S-1-1": {
				NewGroup(t, "admin", []string{"alice"}),
			},
		}
		testOpts.withDefaults.AllowAnonymousBind = true
		testOpts.withDefaults.UPNDomain = "domain"
		assert.Equal(opts, testOpts)
	})
	t.Run("withFirst", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(t, WithLogger(t, testLogger), withFirst(t))
		testOpts := defaults(t)
		testOpts.withLogger = testLogger
		testOpts.withFirst = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithDisablePanicRecovery", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(t, WithLogger(t, testLogger), WithDisablePanicRecovery(t, true))
		testOpts := defaults(t)
		testOpts.withLogger = testLogger
		testOpts.withDisablePanicRecovery = true
		assert.Equal(opts, testOpts)
	})
}

func Test_applyOpts(t *testing.T) {
	assert := assert.New(t)
	opts := options{}
	applyOpts(&opts, nil)
	assert.Equal(options{}, opts)

	applyOpts(&opts, withFirst(t))
	assert.Equal(options{withFirst: true}, opts)
}
