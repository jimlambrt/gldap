// Copyright (c) Jim Lambert
// SPDX-License-Identifier: MIT

package gldap_test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/go-hclog"
	"github.com/jimlambrt/gldap"
	"github.com/jimlambrt/gldap/testdirectory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

/*
	A set of overall tests which use the testdirectory. The purposes of these
	tests is to primarily create a baseline set of end to end tests.
*/

func Test_Start(t *testing.T) {
	t.Parallel()
	userDN := "uid=alice," + testdirectory.DefaultUserDN
	testPwd := "password"
	testEntries := testdirectory.NewUsers(t, []string{"alice"}, testdirectory.WithDefaults(t, &testdirectory.Defaults{UserAttr: "uid"}))
	testLogger := hclog.New(&hclog.LoggerOptions{
		Name:  "Test_Start-logger",
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
			ServerName: "localhost",
		}
		err := c.StartTLS(tlsConfig)
		require.NoError(err)

		err = c.Bind(userDN, testPwd)
		require.NoError(err)
	})
}

func TestDirectory_SimpleBindResponse(t *testing.T) {
	testLogger := hclog.New(&hclog.LoggerOptions{
		Name:  "TestDirectory_SimpleBindResponse-logger",
		Level: hclog.Error,
	})
	td := testdirectory.Start(t,
		testdirectory.WithDisablePanicRecovery(t, true),
		testdirectory.WithLogger(t, testLogger),
		testdirectory.WithDefaults(t, &testdirectory.Defaults{AllowAnonymousBind: true}),
	)
	users := testdirectory.NewUsers(t, []string{"alice", "bob"})
	td.SetUsers(users...)
	p, err := gldap.NewControlBeheraPasswordPolicy(gldap.WithGraceAuthNsRemaining(60))
	require.NoError(t, err)
	td.SetControls(p)

	tests := []struct {
		name         string
		userName     string
		userPass     string
		wantControls []gldap.Control
		wantErr      bool
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
			// var result *ldap.SimpleBindResult
			switch tc.userPass {
			case "":
				err = client.UnauthenticatedBind(tc.userName)
			default:
				controls := []ldap.Control{}
				controls = append(controls, ldap.NewControlBeheraPasswordPolicy())
				bindRequest := ldap.NewSimpleBindRequest(tc.userName, tc.userPass, controls)
				_, err = client.SimpleBind(bindRequest)
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
	t.Parallel()
	testLogger := hclog.New(&hclog.LoggerOptions{
		Name:  "TestDirectory_SearchUsersResponse-logger",
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
	paging, err := gldap.NewControlPaging(60)
	require.NoError(t, err)

	td.SetControls(paging)
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
			results, err := client.Search(&ldap.SearchRequest{
				BaseDN:   tc.baseDN,
				Filter:   tc.filter,
				Controls: []ldap.Control{ldap.NewControlPaging(60)},
			})
			if tc.wantErr {
				require.Error(err)
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			assert.NoError(err)
			if gldap.TestWithDebug(t) {
				fmt.Printf("test name: %s\n", tc.name)
				fmt.Printf("  entries:\n")
				for _, r := range results.Entries {
					fmt.Printf("      dn: %s\n", r.DN)
					for _, a := range r.Attributes {
						fmt.Printf("      %s: %s\n", a.Name, a.Values)
					}
				}
				for _, c := range results.Controls {
					fmt.Println("  controls:")
					fmt.Printf("    %s\n", c)
				}
			}
		})
	}
}

func TestDirectory_ModifyResponse(t *testing.T) {
	t.Parallel()
	testLogger := hclog.New(&hclog.LoggerOptions{
		Name:  "TestDirectory_ModifyResponse-logger",
		Level: hclog.Error,
	})
	td := testdirectory.Start(t,
		testdirectory.WithLogger(t, testLogger),
		testdirectory.WithDefaults(t, &testdirectory.Defaults{AllowAnonymousBind: true}),
	)
	users := testdirectory.NewUsers(t, []string{"alice", "bob", "eve"})
	td.SetUsers(users...)

	const (
		alice = 0
		bob   = 1
		eve   = 2
	)

	tests := []struct {
		name            string
		dn              string
		changes         []ldap.Change
		wantEntry       *gldap.Entry
		wantErr         bool
		wantErrContains string
	}{
		{
			name: "alice-add-description",
			dn:   users[alice].DN,
			changes: []ldap.Change{
				{
					Operation: ldap.AddAttribute,
					Modification: ldap.PartialAttribute{
						Type: "description",
						Vals: []string{"test-add-attribute"},
					},
				},
			},
			wantEntry: &gldap.Entry{
				DN: users[alice].DN,
				Attributes: func() []*gldap.EntryAttribute {
					attrs := append([]*gldap.EntryAttribute{}, users[alice].Attributes...)
					attrs = append(attrs, gldap.NewEntryAttribute("description", []string{gldap.TestEncodeString(t, ber.TagOctetString, "test-add-attribute")}))
					return attrs
				}(),
			},
		},
		{
			name: "bob-replace-email",
			dn:   users[bob].DN,
			changes: []ldap.Change{
				{
					Operation: ldap.ReplaceAttribute,
					Modification: ldap.PartialAttribute{
						Type: "email",
						Vals: []string{"bobs-new-email@example.com"},
					},
				},
			},
			wantEntry: &gldap.Entry{
				DN: users[bob].DN,
				Attributes: func() []*gldap.EntryAttribute {
					attrs := make([]*gldap.EntryAttribute, 0, len(users[bob].Attributes)-1)
					for _, a := range users[bob].Attributes {
						if a.Name == "email" {
							a.Values = []string{"bobs-new-email@example.com"}
						}
						attrs = append(attrs, a)
					}
					return attrs
				}(),
			},
		},
		{
			name: "eve-remove-email",
			dn:   users[eve].DN,
			changes: []ldap.Change{
				{
					Operation: ldap.DeleteAttribute,
					Modification: ldap.PartialAttribute{
						Type: "email",
					},
				},
			},
			wantEntry: &gldap.Entry{
				DN: users[eve].DN,
				Attributes: func() []*gldap.EntryAttribute {
					attrs := make([]*gldap.EntryAttribute, 0, len(users[eve].Attributes)-1)
					for _, a := range users[eve].Attributes {
						if a.Name == "email" {
							continue
						}
						attrs = append(attrs, a)
					}
					return attrs
				}(),
			},
		},
		{
			name: "not-found",
			dn:   "uid=not-found,ou=people,dc=example,dc=com",
			changes: []ldap.Change{
				{
					Operation: ldap.DeleteAttribute,
					Modification: ldap.PartialAttribute{
						Type: "email",
					},
				},
			},
			wantErr:         true,
			wantErrContains: "No Such Object",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			client := td.Conn()
			defer func() { client.Close() }()
			err := client.Modify(&ldap.ModifyRequest{
				DN:      tc.dn,
				Changes: tc.changes,
			})
			if tc.wantErr {
				require.Error(err)
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			result, err := client.Search(&ldap.SearchRequest{
				BaseDN: tc.dn,
				Filter: fmt.Sprintf("(%s)", tc.dn),
			})
			require.NoError(err)
			assert.Equal(len(tc.wantEntry.Attributes), len(result.Entries[0].Attributes))
			assert.Equal(tc.wantEntry.DN, result.Entries[0].DN)
			for _, a := range tc.wantEntry.Attributes {
				assert.Equal(tc.wantEntry.GetAttributeValues(a.Name), result.Entries[0].GetAttributeValues(a.Name))
			}
		})
	}
}

func TestDirectory_AddResponse(t *testing.T) {
	t.Parallel()
	testLogger := hclog.New(&hclog.LoggerOptions{
		Name:  "TestDirectory_AddResponse-logger",
		Level: hclog.Error,
	})
	td := testdirectory.Start(t,
		testdirectory.WithLogger(t, testLogger),
		testdirectory.WithDefaults(t, &testdirectory.Defaults{AllowAnonymousBind: true}),
	)
	users := testdirectory.NewUsers(t, []string{"alice", "bob", "eve"})
	td.SetUsers(users...)

	const (
		alice = 0
		bob   = 1
		eve   = 2
	)

	tests := []struct {
		name            string
		dn              string
		attributes      []ldap.Attribute
		wantEntry       *gldap.Entry
		wantErr         bool
		wantErrContains string
	}{
		{
			name: "alice",
			dn:   fmt.Sprintf("%s=%s,%s", testdirectory.DefaultUserAttr, "joe", testdirectory.DefaultUserDN),
			attributes: []ldap.Attribute{
				{
					Type: "email",
					Vals: []string{"joe@example.com"},
				},
				{
					Type: "givenname",
					Vals: []string{"joe"},
				},
			},
			wantEntry: &gldap.Entry{
				DN: fmt.Sprintf("%s=%s,%s", testdirectory.DefaultUserAttr, "joe", testdirectory.DefaultUserDN),
				Attributes: func() []*gldap.EntryAttribute {
					attrs := append([]*gldap.EntryAttribute{}, gldap.NewEntryAttribute("email", []string{"joe@example.com"}))
					attrs = append(attrs, gldap.NewEntryAttribute("givenname", []string{"joe"}))
					return attrs
				}(),
			},
		},

		{
			name: "existing-entry",
			dn:   users[alice].DN,
			attributes: []ldap.Attribute{
				{
					Type: "email",
					Vals: []string{"alice@example.com"},
				},
			},
			wantErr:         true,
			wantErrContains: "Entry Already Exists",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			client := td.Conn()
			defer func() { client.Close() }()

			err := client.Add(&ldap.AddRequest{
				DN:         tc.dn,
				Attributes: tc.attributes,
			})
			if tc.wantErr {
				require.Error(err)
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			result, err := client.Search(&ldap.SearchRequest{
				BaseDN: tc.dn,
				Filter: fmt.Sprintf("(%s)", tc.dn),
			})
			require.NoError(err)
			assert.Equal(len(tc.wantEntry.Attributes), len(result.Entries[0].Attributes))
			assert.Equal(tc.wantEntry.DN, result.Entries[0].DN)
			for _, a := range tc.wantEntry.Attributes {
				assert.Equal(tc.wantEntry.GetAttributeValues(a.Name), result.Entries[0].GetAttributeValues(a.Name))
			}
		})
	}
}

func TestDirectory_DeleteResponse(t *testing.T) {
	t.Parallel()
	testLogger := hclog.New(&hclog.LoggerOptions{
		Name:  "TestDirectory_DeleteResponse-logger",
		Level: hclog.Error,
	})
	td := testdirectory.Start(t,
		testdirectory.WithLogger(t, testLogger),
		testdirectory.WithDefaults(t, &testdirectory.Defaults{AllowAnonymousBind: true}),
	)
	users := testdirectory.NewUsers(t, []string{"alice", "bob", "eve"})
	groups := testdirectory.NewGroup(t, "admin", []string{"bob"})
	td.SetUsers(users...)
	td.SetGroups(groups)

	tests := []struct {
		name            string
		dn              string
		attributes      []ldap.Attribute
		wantErr         bool
		wantErrContains string
	}{
		{
			name:            "not-found",
			dn:              fmt.Sprintf("%s=%s,%s", testdirectory.DefaultUserAttr, "joe", testdirectory.DefaultUserDN),
			wantErr:         true,
			wantErrContains: "No Such Object",
		},
		{
			name: "success-user",
			dn:   fmt.Sprintf("%s=%s,%s", testdirectory.DefaultUserAttr, "alice", testdirectory.DefaultUserDN),
		},
		{
			name: "success-group",
			dn:   fmt.Sprintf("%s=%s,%s", testdirectory.DefaultGroupAttr, "admin", testdirectory.DefaultGroupDN),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			client := td.Conn()
			defer func() { client.Close() }()

			err := client.Del(&ldap.DelRequest{
				DN: tc.dn,
			})
			if tc.wantErr {
				require.Error(err)
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			_, err = client.Search(&ldap.SearchRequest{
				BaseDN: tc.dn,
				Filter: fmt.Sprintf("(%s)", tc.dn),
			})
			require.Error(err)
			assert.Contains(err.Error(), `LDAP Result Code 32 "No Such Object"`)
		})
	}
}

func Test_Start_Unbind(t *testing.T) {
	t.Parallel()
	t.Run("unbind", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		port := testdirectory.FreePort(t)

		l := hclog.New(&hclog.LoggerOptions{
			Name:  "simple-bind-logger",
			Level: hclog.Error,
		})

		// create a new server
		s, err := gldap.NewServer(gldap.WithLogger(l), gldap.WithDisablePanicRecovery())
		require.NoError(err)

		// create a router and add a bind handler
		r, err := gldap.NewMux()
		require.NoError(err)

		var got string
		var wg sync.WaitGroup
		wg.Add(1)
		err = r.Unbind(func(w *gldap.ResponseWriter, req *gldap.Request) {
			m, err := req.GetUnbindMessage()
			if err != nil {
				t.Fatalf("unable to get unbind msg: %s", err.Error())
			}
			if m == nil {
				t.Fatal("unbind msg is nil")
			}
			got = "unbind-success"
			wg.Done()
		})
		require.NoError(err)

		err = r.Bind(func(w *gldap.ResponseWriter, r *gldap.Request) {
			resp := r.NewBindResponse(gldap.WithResponseCode(gldap.ResultSuccess))
			defer func() {
				_ = w.Write(resp)
			}()
		})
		require.NoError(err)

		err = s.Router(r)
		require.NoError(err)
		go func() { require.NoError(s.Run(fmt.Sprintf(":%d", port))) }()
		defer func() { require.NoError(s.Stop()) }()

		time.Sleep(1 * time.Second)
		conn, err := ldap.DialURL(fmt.Sprintf("ldap://localhost:%d", port))
		require.NoError(err)
		defer conn.Close()

		err = conn.Bind("does not", "matter")
		require.NoError(err)

		err = conn.Unbind()
		require.NoError(err)

		wg.Wait()
		assert.Equal("unbind-success", got)
	})
}
