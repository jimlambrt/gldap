package testdirectory_test

import (
	"testing"

	"github.com/jimlambrt/gldap/testdirectory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMemberOf(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		DNs := testdirectory.NewMemberOf(t,
			[]string{"grp1", "grp2"},
			testdirectory.WithDefaults(t, &testdirectory.Defaults{
				GroupDN:   "grp-dn",
				GroupAttr: "grp-attr",
			}))
		require.Len(DNs, 2)
		assert.Equal("grp-attr=grp1,grp-dn", DNs[0])
		assert.Equal("grp-attr=grp2,grp-dn", DNs[1])
	})
}
