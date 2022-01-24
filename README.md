# gldap
[![Go Reference](https://pkg.go.dev/badge/github.com/jimlambrt/gldap/gldap.svg)](https://pkg.go.dev/github.com/jimlambrt/gldap)
 

**This is a work in progress! I would only suggest using it for development and test.**

<hr>

`gldap` is a framework for building LDAP services.  Among other things, it defines abstractions for:

* `Server`: supports both LDAP and LDAPS (TLS) protocols as well as the StartTLS
  requests. 
* `Request`: represents an LDAP request (bind, search, extended, etc) along with
  the inbound request message. 
* `ResponseWriter`: allows you to compose request responses.
* `Mux`: an ldap request multiplexer. It matches the inbound request against a
  list of registered route handlers. 
* `HandlerFunc`: handlers provided to the Mux which serve individual ldap requests.

<hr>

Example:

```go
package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-ldap/ldap/v3"
	"github.com/jimlambrt/gldap"
)

func main() {
	// create a new server
	s, err := gldap.NewServer()
	if err != nil {
		log.Fatalf("unable to create server: %s", err.Error())
	}

	// create a router and add a bind handler
	r, err := gldap.NewMux()
	if err != nil {
		log.Fatalf("unable to create router: %s", err.Error())
	}
	r.Bind(bindHandler)
	s.Router(r)

	go s.Run(":10389") // listen on port 10389

	// stop server gracefully when ctrl-c, sigint or sigterm occurs
	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	close(ch)

	s.Stop()
}

func bindHandler(w *gldap.ResponseWriter, r *gldap.Request) {
	resp := r.NewBindResponse(
		gldap.WithResponseCode(ldap.LDAPResultInvalidCredentials),
	)
	defer func() {
		w.Write(resp)
	}()

	m, err := r.GetSimpleBindMessage()
	if err != nil {
		log.Printf("not a simple bind message: %s", err)
		return
	}

	if m.UserName == "alice" {
		resp.SetResultCode(ldap.LDAPResultSuccess)
		log.Println("bind success")
		return
	}
}
```
<hr>

## Road map

### Currently supported features:

* `ldap`, `ldaps` and `mTLS` connections
* StartTLS Requests
* Bind Requests
  * Simple Auth (user/pass) 
* Search Requests

### Near-term features 

* Add Requests
* Delete Requests
* Modify Requests
### Long-term features

* ???

<hr>

## [gldap.testdirectory](testdirectory/README.md)
[![Go
Reference](https://pkg.go.dev/badge/github.com/jimlambrt/gldap/testdirectory.svg)](https://pkg.go.dev/github.com/jimlambrt/gldap/testdirectory) 

The `testdirectory` package built using `gldap` which provides an in-memory test
LDAP service with capabilities which make writing tests that depend on an LDAP
service much easier.  
