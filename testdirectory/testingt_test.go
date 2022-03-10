package testdirectory_test

import (
	"strings"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/jimlambrt/gldap/testdirectory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Logger(t *testing.T) {
	buf := &strings.Builder{}
	bufLogger := hclog.New(&hclog.LoggerOptions{
		Name:   "my-app",
		Level:  hclog.LevelFromString("DEBUG"),
		Output: buf,
	})
	t.Run("NewLogger", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		l, err := testdirectory.NewLogger(nil)
		assert.Error(err)
		assert.Nil(l)

		l, err = testdirectory.NewLogger(bufLogger)
		require.NoError(err)
		require.NotNil(l)
		assert.Equal(bufLogger, l.Logger)
	})
	t.Run("Errorf", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		l, err := testdirectory.NewLogger(bufLogger)
		require.NoError(err)
		require.NotNil(l)
		buf.Reset()

		l.Errorf("test error")
		assert.Contains(buf.String(), "[ERROR] my-app: test error")
		buf.Reset()
	})
	t.Run("Infof", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		l, err := testdirectory.NewLogger(bufLogger)
		require.NoError(err)
		require.NotNil(l)
		buf.Reset()

		l.Infof("test info")
		assert.Contains(buf.String(), "[INFO]  my-app: test info")
		buf.Reset()
	})
	t.Run("Log", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		l, err := testdirectory.NewLogger(bufLogger)
		require.NoError(err)
		require.NotNil(l)
		buf.Reset()

		l.Log("test log")
		assert.Contains(buf.String(), "[INFO]  my-app: test log")
		buf.Reset()
	})
	t.Run("FailNow", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		l, err := testdirectory.NewLogger(bufLogger)
		require.NoError(err)
		require.NotNil(l)
		buf.Reset()

		assert.PanicsWithValue("testing.T failed, see logs for output (if any)", func() {
			l.FailNow()
		})

	})
}
