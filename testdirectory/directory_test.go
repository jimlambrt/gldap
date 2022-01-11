package testdirectory_test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/go-hclog"
	"github.com/jimlambrt/gldap"
	"github.com/jimlambrt/gldap/testdirectory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Start(t *testing.T) {
	t.Parallel()
	userDN := "uid=alice," + testdirectory.DefaultUserDN
	testPwd := "password"
	testEntries := testdirectory.NewUsers(t, []string{"alice"}, testdirectory.WithDefaults(t, &testdirectory.Defaults{UserAttr: "uid"}))
	testLogger := hclog.New(&hclog.LoggerOptions{
		Name:  "test-logger",
		Level: hclog.Error,
	})

	t.Run("non-tls", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		port := testdirectory.FreePort(t)
		td := testdirectory.Start(
			t,
			testdirectory.WithPort(t, port),
			testdirectory.WithDefaults(t, &testdirectory.Defaults{Users: testEntries}),
			testdirectory.WithLogger(t, testLogger),
			testdirectory.WithNoTLS(t),
		)
		assert.Equal(port, td.Port())

		c := td.Conn()
		defer c.Close()

		err := c.Bind(userDN, testPwd)
		require.NoError(err)
	})
	t.Run("tls", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		port := testdirectory.FreePort(t)
		td := testdirectory.Start(
			t,
			testdirectory.WithPort(t, port),
			testdirectory.WithDefaults(t, &testdirectory.Defaults{Users: testEntries}),
			testdirectory.WithLogger(t, testLogger),
		)
		assert.Equal(port, td.Port())

		c := td.Conn()
		defer c.Close()

		err := c.Bind(userDN, testPwd)
		require.NoError(err)
	})
	t.Run("mtls", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		port := testdirectory.FreePort(t)
		td := testdirectory.Start(
			t,
			testdirectory.WithPort(t, port),
			testdirectory.WithDefaults(t, &testdirectory.Defaults{Users: testEntries}),
			testdirectory.WithLogger(t, testLogger),
			testdirectory.WithMTLS(t),
		)
		assert.Equal(port, td.Port())

		c := td.Conn()
		defer c.Close()

		err := c.Bind(userDN, testPwd)
		require.NoError(err)
	})
	t.Run("start-tls", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		port := testdirectory.FreePort(t)
		td := testdirectory.Start(
			t,
			testdirectory.WithPort(t, port),
			testdirectory.WithDefaults(t, &testdirectory.Defaults{Users: testEntries}),
			testdirectory.WithLogger(t, testLogger),
			testdirectory.WithNoTLS(t),
		)
		assert.Equal(port, td.Port())

		c := td.Conn()
		defer c.Close()

		caPool := x509.NewCertPool()
		require.True(caPool.AppendCertsFromPEM([]byte(td.Cert())))
		tlsConfig := &tls.Config{
			RootCAs:    caPool,
			ServerName: "127.0.0.1",
		}
		err := c.StartTLS(tlsConfig)
		require.NoError(err)

		err = c.Bind(userDN, testPwd)
		require.NoError(err)
	})
}

func TestDirectory_SimpleBindResponse(t *testing.T) {
	testLogger := hclog.New(&hclog.LoggerOptions{
		Name:  "test-logger",
		Level: hclog.Error,
	})
	td := testdirectory.Start(t,
		testdirectory.WithLogger(t, testLogger),
		testdirectory.WithDefaults(t, &testdirectory.Defaults{AllowAnonymousBind: true}),
	)
	users := testdirectory.NewUsers(t, []string{"alice", "bob"})
	td.SetUsers(users...)

	tests := []struct {
		name     string
		userName string
		userPass string
		wantErr  bool
	}{
		{
			name:     "simple-success",
			userName: fmt.Sprintf("%s=alice,%s", testdirectory.DefaultUserAttr, testdirectory.DefaultUserDN),
			userPass: "password",
		},
		{
			name:     "simple-invalid",
			userName: fmt.Sprintf("%s=alice,%s", testdirectory.DefaultUserAttr, testdirectory.DefaultUserDN),
			userPass: "invalid-password",
			wantErr:  true,
		},
		{
			name:     "anon",
			userName: fmt.Sprintf("%s=alice,%s", testdirectory.DefaultUserAttr, testdirectory.DefaultUserDN),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			client := td.Conn()
			defer func() { client.Close() }()
			var err error
			switch tc.userPass {
			case "":
				err = client.UnauthenticatedBind(tc.userName)
			default:
				err = client.Bind(tc.userName, tc.userPass)
			}

			if tc.wantErr {
				assert.Error(err)
				return
			}
			assert.NoError(err)
		})
	}
}

func TestDirectory_SearchUsersResponse(t *testing.T) {
	testLogger := hclog.New(&hclog.LoggerOptions{
		Name:  "test-logger",
		Level: hclog.Error,
	})

	td := testdirectory.Start(t,
		testdirectory.WithLogger(t, testLogger),
		testdirectory.WithDefaults(t, &testdirectory.Defaults{AllowAnonymousBind: true}),
	)
	groups := []*gldap.Entry{
		testdirectory.NewGroup(t, "admin", []string{"alice"}),
		testdirectory.NewGroup(t, "admin-upn", []string{"eve"}, testdirectory.WithDefaults(t, &testdirectory.Defaults{UPNDomain: "example.com"})),
	}
	tokenGroups := map[string][]*gldap.Entry{
		"S-1-1": {
			testdirectory.NewGroup(t, "admin", []string{"alice"}),
		},
	}
	sidBytes, err := gldap.SIDBytes(1, 1)
	require.NoError(t, err)

	users := testdirectory.NewUsers(t, []string{"alice", "bob"}, testdirectory.WithMembersOf(t, "admin"), testdirectory.WithTokenGroups(t, sidBytes))
	users = append(
		users,
		testdirectory.NewUsers(
			t,
			[]string{"eve"},
			testdirectory.WithDefaults(t, &testdirectory.Defaults{UPNDomain: "example.com"}),
			testdirectory.WithMembersOf(t, "admin"))...,
	)
	td.SetUsers(users...)
	td.SetGroups(groups...)
	td.SetTokenGroups(tokenGroups)

	tests := []struct {
		name            string
		filter          string
		baseDN          string
		wantEntry       *gldap.Entry
		wantErr         bool
		wantErrContains string
	}{
		{
			name:            "not-found",
			filter:          fmt.Sprintf("(%s=not-found,%s)", testdirectory.DefaultUserAttr, testdirectory.DefaultUserDN),
			baseDN:          testdirectory.DefaultUserDN,
			wantErr:         true,
			wantErrContains: `LDAP Result Code 32 "No Such Object"`,
		},
		{
			name:      "alice-found",
			filter:    fmt.Sprintf("(%s=alice,%s)", testdirectory.DefaultUserAttr, testdirectory.DefaultUserDN),
			baseDN:    testdirectory.DefaultUserDN,
			wantEntry: users[0],
		},
		{
			name:      "admin-group-found",
			filter:    fmt.Sprintf("(%s=admin,%s)", testdirectory.DefaultGroupAttr, testdirectory.DefaultGroupDN),
			baseDN:    testdirectory.DefaultGroupDN,
			wantEntry: groups[0],
		},
		{
			name:            "group-not-found",
			filter:          fmt.Sprintf("(%s=not-found,%s)", testdirectory.DefaultGroupAttr, testdirectory.DefaultGroupDN),
			baseDN:          testdirectory.DefaultGroupDN,
			wantErr:         true,
			wantErrContains: `LDAP Result Code 32 "No Such Object"`,
		},
		{
			name:      "admin-member-found",
			filter:    fmt.Sprintf("(%s=alice,%s)", testdirectory.DefaultUserAttr, testdirectory.DefaultUserDN),
			baseDN:    testdirectory.DefaultGroupDN,
			wantEntry: groups[0],
		},
		{
			name:            "admin-member-not-found",
			filter:          fmt.Sprintf("(%s=not-found-member,%s)", testdirectory.DefaultUserAttr, testdirectory.DefaultUserDN),
			baseDN:          testdirectory.DefaultGroupDN,
			wantErr:         true,
			wantErrContains: `LDAP Result Code 32 "No Such Object"`,
		},
		{
			name:      "admin-member-found-upn",
			filter:    fmt.Sprintf("(userPrincipalName=eve@%s,%s)", "example.com", testdirectory.DefaultUserDN),
			baseDN:    testdirectory.DefaultGroupDN,
			wantEntry: groups[1],
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			client := td.Conn()
			defer func() { client.Close() }()
			_, err := client.Search(&ldap.SearchRequest{
				BaseDN: tc.baseDN,
				Filter: tc.filter,
			})
			if tc.wantErr {
				require.Error(err)
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			assert.NoError(err)
		})
	}
}
