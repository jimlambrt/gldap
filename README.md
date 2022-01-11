# gldap
[![Go Reference](https://pkg.go.dev/badge/github.com/jimlambrt/gldap/gldap.svg)](https://pkg.go.dev/github.com/jimlambrt/gldap)
 

**This is a work in progress!  It is not ready for any sort of use yet, even development!**

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

func main() {
    s, err := gldap.NewServer()
    r := gldap.NewMux()

    bindHandler := func(w *ResponseWriter, r *Request) {
        // handle bind request
    }
    r.Bind(bindFn bindHandler, opt ...Option) error {
    s.Router(r)
    go s.Run()

    // When CTRL+C, SIGINT and SIGTERM signal occurs
    // Then stop server gracefully
    ch := make(chan os.Signal)
    signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
    <-ch
    close(ch)
    server.Stop()
}
```