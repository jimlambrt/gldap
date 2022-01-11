## [gldap.testdirectory](testdirectory/)
[![Go
Reference](https://pkg.go.dev/badge/github.com/jimlambrt/gldap/testdirectory.svg)](https://pkg.go.dev/github.com/jimlambrt/gldap/testdirectory)

The `testdirectory` package provides an in-memory test LDAP service with support
for capabilities which make writing tests that depend on an LDAP service much
easier. 

Example:

```go

// this example demonstrates how you might write unit tests to verify that 
// go-ldap's client works as expected.  
//
// Once you substitute your ldap client for go-ldap's you'll have a working
// unit test for your custom client.
func TestDirectory_SimpleBindResponse(t *testing.T) {

    // start a test directory running ldaps on an available free port (defaults)
    // that allows anon binds (a default override)
	td := testdirectory.Start(t,
		testdirectory.WithDefaults(&testdirectory.Defaults{AllowAnonymousBind: true}),
	)
    // create some test new user entries (using defaults for ou, password, etc)
	users := testdirectory.NewUsers(t, []string{"alice", "bob"})
    // set the test directories user entries
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
            // retrieve a client for the test directory.
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
```